package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const legacyProjection = `SELECT agent_id,kind AS source_kind,record_id,received_at_ns,payload,0 AS item,'event' AS display_kind FROM records WHERE kind='event'
UNION ALL SELECT agent_id,kind,record_id,received_at_ns,json_extract(payload,'$.event'),0,'event' FROM records WHERE kind='event_bundle'`
const legacyDetectionProjection = `SELECT agent_id,kind AS source_kind,record_id,received_at_ns,payload,0 AS item,'finding' AS display_kind FROM records WHERE kind='finding'
UNION ALL SELECT r.agent_id,r.kind,r.record_id,r.received_at_ns,j.value,CAST(j.key AS INTEGER),'finding' FROM records r INDEXED BY records_history_detection_bundle_idx,json_each(r.payload,'$.findings') j WHERE r.kind='event_bundle' AND json_array_length(r.payload,'$.findings')>0 AND json_type(r.payload,'$.findings')='array' AND j.type='object'`
const legacyPageQuery = `WITH history AS (%s) SELECT agent_id,display_kind,record_id,received_at_ns,payload,source_kind,item FROM history WHERE (?='' OR agent_id=?) AND (?=0 OR received_at_ns>=?) AND (?=0 OR received_at_ns<?) AND (?='' OR json_extract(payload,?)=?) AND (?='' OR instr(lower(CAST(payload AS TEXT)),lower(?))>0) AND (?=0 OR (received_at_ns,agent_id,source_kind,record_id,item)<(?,?,?,?,?)) ORDER BY received_at_ns DESC,agent_id DESC,source_kind DESC,record_id DESC,item DESC LIMIT ?`

type historyTestRow struct {
	Agent, Display, ID string
	At                 int64
	Payload            []byte
	Kind               string
	Item               int64
}

func queryHistoryTestRows(t *testing.T, db *sql.DB, q string, args ...any) []historyTestRow {
	t.Helper()
	rows, err := db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []historyTestRow{}
	for rows.Next() {
		var r historyTestRow
		if err := rows.Scan(&r.Agent, &r.Display, &r.ID, &r.At, &r.Payload, &r.Kind, &r.Item); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
func seedMixedHistory(t *testing.T, f *fixture) {
	t.Helper()
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	for _, agent := range []string{"agent-a", "agent-b"} {
		for _, kind := range []string{"event", "event_bundle", "finding", "audit"} {
			for i := 0; i < 4; i++ {
				payload := map[string]any{"event_type": []string{"process.exec", "process.credential_change"}[i%2], "event_time": base, "rule_id": []string{"rule.one", "rule.two"}[i%2], "action": "audit.one", "note": "visible needle"}
				var body any = payload
				if kind == "event_bundle" {
					body = map[string]any{"event": payload, "bundle_only": "not-searchable-event", "findings": []any{map[string]any{"rule_id": "rule.one", "note": "first needle"}, nil, map[string]any{"rule_id": "rule.two", "note": "last needle"}}}
				}
				addHistoryRecord(t, f, agent, kind, fmt.Sprintf("%s-%s-%d", agent, kind, i), base.Add(time.Duration(i/2)*time.Second), body)
			}
		}
	}
}
func TestPushedHistoryQueryMatchesLegacyAcrossFiltersAndCursors(t *testing.T) {
	f := setup(t)
	seedMixedHistory(t, f)
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC).UnixNano()
	for _, view := range []string{"events", "detections", "agent_audit"} {
		types := []string{"", "missing.type"}
		path := "$.action"
		projection := `SELECT agent_id,kind AS source_kind,record_id,received_at_ns,payload,0 AS item,'audit' AS display_kind FROM records WHERE kind='audit'`
		if view == "events" {
			types = append(types, "process.credential_change")
			path = "$.event_type"
			projection = legacyProjection
		}
		if view == "detections" {
			types = append(types, "rule.one", "rule.two")
			path = "$.rule_id"
			projection = legacyDetectionProjection
		}
		if view == "agent_audit" {
			types = append(types, "audit.one")
		}
		all := queryHistoryTestRows(t, f.store.db, fmt.Sprintf(legacyPageQuery, projection), "", "", 0, 0, 0, 0, "", path, "", "", "", 0, 0, "", "", "", 0, 501)
		cursors := []historyPageCursor{{}}
		for _, r := range all {
			cursors = append(cursors, historyPageCursor{At: r.At, Agent: r.Agent, Kind: r.Kind, ID: r.ID, Item: r.Item})
		}
		for _, agent := range []string{"", "agent-a", "absent"} {
			for _, typ := range types {
				for _, search := range []string{"", "needle", "bundle_only", "' OR 1=1 --"} {
					for _, bounds := range [][2]int64{{0, 0}, {base, base + int64(time.Second)}, {base + int64(time.Second), 0}} {
						for _, cursor := range cursors {
							if cursor.At != 0 && (agent == "absent" || typ != "" || search != "needle" || bounds != ([2]int64{0, 0})) {
								continue
							}
							filter := historyFilter{View: view, Agent: agent, Type: typ, Search: search}
							for _, limit := range []int{1, 3, 500} {
								old := queryHistoryTestRows(t, f.store.db, fmt.Sprintf(legacyPageQuery, projection), agent, agent, bounds[0], bounds[0], bounds[1], bounds[1], typ, path, typ, search, search, cursor.At, cursor.At, cursor.Agent, cursor.Kind, cursor.ID, cursor.Item, limit+1)
								query, args := buildHistoryQuery(filter, bounds[0], bounds[1], cursor, limit)
								page, _, err := f.store.readHistoryPage(context.Background(), query, args, 501, historyResponseBytes, true)
								if err != nil {
									t.Fatal(err)
								}
								got := []historyTestRow{}
								for _, r := range page {
									got = append(got, historyTestRow{Agent: r.record.AgentID, Display: r.record.Kind, ID: r.record.ID, At: r.at, Payload: r.record.Payload, Kind: r.source, Item: r.item})
								}
								if !reflect.DeepEqual(got, old) {
									t.Fatalf("mismatch view=%s agent=%s type=%s search=%s bounds=%v cursor=%+v limit=%d got=%+v old=%+v", view, agent, typ, search, bounds, cursor, limit, got, old)
								}
							}
						}
					}
				}
			}
		}
	}
}

func historyQueryPlan(t *testing.T, db *sql.DB, query string, args []any) string {
	t.Helper()
	rows, err := db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	details := []string{}
	for rows.Next() {
		var a, b, c int
		var detail string
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(details, "\n")
}
func TestHistoryEventFiltersUseExpressionAndRangeIndexes(t *testing.T) {
	f := setup(t)
	for _, test := range []struct {
		filter historyFilter
		want   []string
	}{
		{historyFilter{View: "events", Type: "process.credential_change"}, []string{"records_history_event_type_idx", "records_history_bundle_event_type_idx"}},
		{historyFilter{View: "events", Agent: "agent-a", Type: "process.exec"}, []string{"records_history_event_agent_type_idx", "records_history_bundle_event_agent_type_idx"}},
		{historyFilter{View: "events"}, []string{"records_history_kind_idx"}},
	} {
		query, args := buildHistoryQuery(test.filter, 1, 100, historyPageCursor{}, 20)
		plan := historyQueryPlan(t, f.store.historyDB, query, args)
		for _, want := range test.want {
			if !strings.Contains(plan, want) {
				t.Fatalf("missing %s:\n%s", want, plan)
			}
		}
		if !strings.Contains(plan, "received_at_ns>?") || !strings.Contains(plan, "received_at_ns<?") {
			t.Fatalf("date range is not indexed:\n%s", plan)
		}
		if strings.Contains(plan, "SCAN r") {
			t.Fatalf("full records scan:\n%s", plan)
		}
		if strings.Count(query, "LIMIT ?") != 3 {
			t.Fatalf("branches were not bounded before merge: %s", query)
		}
	}
}
func TestHistoryReaderIsReadOnlyAndDoesNotHoldWriterConnection(t *testing.T) {
	f := setup(t)
	if _, err := f.store.historyDB.Exec("INSERT INTO audit(agent_id,kind,created_at_ns,details_json) VALUES('qa','qa',1,'{}')"); err == nil {
		t.Fatal("history connection accepted a write")
	}
	var mode string
	if err := f.store.historyDB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("reader is not using WAL: %s %v", mode, err)
	}
	if f.store.historyDB.Stats().MaxOpenConnections != 1 {
		t.Fatal("history pool is not bounded")
	}
	reader, err := f.store.historyDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ExecContext(context.Background(), "BEGIN"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := reader.QueryRowContext(context.Background(), "SELECT count(*) FROM records").Scan(&count); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit(agent_id,kind,created_at_ns,details_json) VALUES('qa','qa',1,'{}')"); err != nil {
		t.Fatal("reader blocked writer", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM audit WHERE kind='qa'").Scan(&count); err != nil || count != 1 {
		t.Fatal("transaction-local read failed", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
}
func TestHistoryPoolWaitHasControlledTimeout(t *testing.T) {
	f := setup(t)
	reader, err := f.store.historyDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/api/history?view=events", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	f.server.consoleHistoryView(recorder, req)
	if recorder.Code != 503 || recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("unexpected timeout response %d", recorder.Code)
	}
	var body map[string]string
	if json.Unmarshal(recorder.Body.Bytes(), &body) != nil || !strings.Contains(body["error"], "조회 시간이 초과") {
		t.Fatal("missing controlled JSON timeout")
	}
}

func TestLegacyHistoryQueryMatchesRawPagingAndGlobalIndex(t *testing.T) {
	f := setup(t)
	seedMixedHistory(t, f)
	legacy := `SELECT agent_id,kind AS display_kind,record_id,received_at_ns,payload,kind AS source_kind,0 AS item FROM records WHERE (?='' OR agent_id=?) AND (?='' OR kind=? OR (?='detections' AND (kind='finding' OR (kind='event_bundle' AND json_array_length(payload,'$.findings')>0)))) AND (?='' OR (received_at_ns,agent_id,kind,record_id)<(?,?,?,?)) ORDER BY received_at_ns DESC,agent_id DESC,kind DESC,record_id DESC LIMIT ?`
	for _, agent := range []string{"", "agent-a"} {
		for _, kind := range []string{"", "event", "event_bundle", "finding", "audit", "detections"} {
			args := []any{agent, agent, kind, kind, kind, "", 0, "", "", "", 501}
			all := queryHistoryTestRows(t, f.store.db, legacy, args...)
			cursors := []consoleHistoryCursor{{}}
			for _, r := range all {
				cursors = append(cursors, consoleHistoryCursor{At: r.At, AgentID: r.Agent, Kind: r.Kind, ID: r.ID})
			}
			for _, cursor := range cursors {
				for _, limit := range []int{1, 3, 500} {
					before := ""
					if cursor.At != 0 {
						before = "present"
					}
					want := queryHistoryTestRows(t, f.store.db, legacy, agent, agent, kind, kind, kind, before, cursor.At, cursor.AgentID, cursor.Kind, cursor.ID, limit+1)
					query, args := buildLegacyHistoryQuery(agent, kind, cursor, limit)
					page, _, err := f.store.readHistoryPage(context.Background(), query, args, 501, historyResponseBytes, false)
					if err != nil {
						t.Fatal(err)
					}
					got := []historyTestRow{}
					for _, r := range page {
						got = append(got, historyTestRow{Agent: r.record.AgentID, Display: r.record.Kind, ID: r.record.ID, At: r.at, Payload: r.record.Payload, Kind: r.source, Item: r.item})
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("legacy mismatch kind=%s agent=%s cursor=%+v", kind, agent, cursor)
					}
				}
			}
		}
	}
	query, args := buildLegacyHistoryQuery("", "", consoleHistoryCursor{}, 20)
	plan := historyQueryPlan(t, f.store.historyDB, query, args)
	if !strings.Contains(plan, "records_console_page_idx") {
		t.Fatalf("global legacy index missing:\n%s", plan)
	}
	query, args = buildLegacyHistoryQuery("", "detections", consoleHistoryCursor{}, 20)
	plan = historyQueryPlan(t, f.store.historyDB, query, args)
	if !strings.Contains(plan, "records_history_detection_bundle_idx") {
		t.Fatalf("recent detections scan nonfinding bundles:\n%s", plan)
	}
}
