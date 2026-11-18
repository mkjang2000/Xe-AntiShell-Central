package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHistoryByteBudgetKeepsCrossKindCursorWithoutLoss(t *testing.T) {
	f := setup(t)
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	padding := strings.Repeat("x", 600000)
	for _, agent := range []string{"agent-a", "agent-b"} {
		for _, kind := range []string{"event", "event_bundle"} {
			for i := 0; i < 4; i++ {
				event := map[string]any{"event_id": fmt.Sprintf("%s-%s-%d", agent, kind, i), "event_type": "process.exec", "event_time": base, "padding": padding}
				var payload any = event
				if kind == "event_bundle" {
					payload = map[string]any{"event": event, "findings": []any{}}
				}
				addHistoryRecord(t, f, agent, kind, fmt.Sprintf("same-%d", i), base, payload)
			}
		}
	}
	for _, view := range []string{"events", "legacy"} {
		path := "/api/history?view=events&limit=500"
		if view == "legacy" {
			path = "/api/history?limit=500"
		}
		seen := map[string]bool{}
		pages := 0
		for {
			response := f.console(t, "GET", path, nil)
			var items []HistoryRecord
			consoleWant(t, response, 200, &items)
			if response.Body.Len() > historyResponseBytes {
				t.Fatal("wire response exceeded conservative budget")
			}
			if len(items) == 0 {
				t.Fatal("budget pagination did not progress")
			}
			for _, item := range items {
				key := item.AgentID + "/" + item.Kind + "/" + item.ID
				if view == "events" {
					var event struct {
						ID string `json:"event_id"`
					}
					if err := json.Unmarshal(item.Payload, &event); err != nil {
						t.Fatal(err)
					}
					key = event.ID
				}
				if seen[key] {
					t.Fatal("repeated record across budget boundary", key)
				}
				seen[key] = true
			}
			pages++
			next := response.Header().Get("X-Next-Cursor")
			if next == "" {
				break
			}
			if pages > 5 {
				t.Fatal("unbounded pagination")
			}
			path = strings.Split(path, "&before=")[0] + "&before=" + url.QueryEscape(next)
		}
		if len(seen) != 16 || pages < 2 {
			t.Fatalf("lost records at byte boundary: %s rows=%d pages=%d", view, len(seen), pages)
		}
	}
	// The first legal record progresses even under a deliberately tiny test budget.
	q, args := buildHistoryQuery(historyFilter{View: "events"}, 0, 0, historyPageCursor{}, 500)
	first, more, err := f.store.readHistoryPage(context.Background(), q, args, 500, 1, true)
	if err != nil || len(first) != 1 || !more {
		t.Fatalf("first-row progress: rows=%d more=%v err=%v", len(first), more, err)
	}
}
func TestFindingBudgetResumesWithinBundleAndAcrossKinds(t *testing.T) {
	f := setup(t)
	seedMixedHistory(t, f)
	filter := historyFilter{View: "detections"}
	q, args := buildHistoryQuery(filter, 0, 0, historyPageCursor{}, 500)
	want, _, err := f.store.readHistoryPage(context.Background(), q, args, 500, historyResponseBytes, true)
	if err != nil {
		t.Fatal(err)
	}
	cursor := historyPageCursor{}
	got := []historyPageItem{}
	inside := false
	for range want {
		q, args = buildHistoryQuery(filter, 0, 0, cursor, 500)
		page, more, err := f.store.readHistoryPage(context.Background(), q, args, 500, 1, true)
		if err != nil || len(page) != 1 {
			t.Fatalf("finding budget progress: %v", err)
		}
		got = append(got, page...)
		last := page[0]
		cursor = historyPageCursor{At: last.at, Agent: last.record.AgentID, Kind: last.source, ID: last.record.ID, Item: last.item, Filter: filter}
		if last.source == "event_bundle" && last.item > 0 {
			inside = true
		}
		if !more {
			break
		}
	}
	if !inside || !reflect.DeepEqual(got, want) {
		t.Fatal("bundle item/cross-kind cursor lost or repeated a finding")
	}
}
func TestAuditBudgetAndLegacyStoreOrdering(t *testing.T) {
	f := setup(t)
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	details, _ := json.Marshal(map[string]any{"padding": strings.Repeat("x", 600000)})
	for i := 0; i < 16; i++ {
		if _, err := f.store.db.Exec("INSERT INTO audit(agent_id,kind,created_at_ns,details_json) VALUES('qa','qa',?,?)", base.UnixNano(), details); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/api/audit?limit=500", "/api/audit?view=audit&limit=500"} {
		seen := map[int64]bool{}
		pages := 0
		for {
			response := f.console(t, "GET", path, nil)
			var items []AuditEntry
			consoleWant(t, response, 200, &items)
			if response.Body.Len() > historyResponseBytes {
				t.Fatal("audit wire budget exceeded")
			}
			for _, item := range items {
				if seen[item.ID] {
					t.Fatal("duplicate audit")
				}
				seen[item.ID] = true
			}
			pages++
			next := response.Header().Get("X-Next-Cursor")
			if next == "" {
				break
			}
			if pages > 5 {
				t.Fatal("audit failed to progress")
			}
			path = strings.Split(path, "&before=")[0] + "&before=" + url.QueryEscape(next)
		}
		if len(seen) != 16 || pages < 2 {
			t.Fatal("audit pagination lost records")
		}
	}
	items, err := f.store.Audit(context.Background(), 500)
	if err != nil || len(items) >= 16 || len(items) == 0 {
		t.Fatalf("admin audit budget: %d %v", len(items), err)
	}
	seedMixedHistory(t, f)
	for _, agent := range []string{"", "agent-a"} {
		for _, kind := range []string{"", "event", "finding", "unknown' OR 1=1 --"} {
			old, err := f.store.db.Query("SELECT agent_id,kind,record_id,received_at_ns,payload FROM records WHERE (?='' OR agent_id=?) AND (?='' OR kind=?) ORDER BY received_at_ns DESC,record_id LIMIT ?", agent, agent, kind, kind, 500)
			if err != nil {
				t.Fatal(err)
			}
			want := []HistoryRecord{}
			for old.Next() {
				var item HistoryRecord
				var at int64
				var payload []byte
				if err := old.Scan(&item.AgentID, &item.Kind, &item.ID, &at, &payload); err != nil {
					t.Fatal(err)
				}
				item.ReceivedAt = time.Unix(0, at).UTC()
				item.Payload = payload
				want = append(want, item)
			}
			old.Close()
			got, err := f.store.History(context.Background(), agent, kind, 500)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("admin ordering/filters changed: agent=%s kind=%s error=%v", agent, kind, err)
			}
		}
	}
}
func TestHistoryMigrationPreservesEvidenceAndClosesReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"records_history_event_type_idx", "records_history_event_agent_type_idx", "records_history_bundle_event_type_idx", "records_history_bundle_event_agent_type_idx"} {
		if _, err := db.Exec("DROP INDEX " + name); err != nil {
			t.Fatal(err)
		}
	}
	original := []byte(`{"event_type":"process.credential_change","exact":9007199254740993}`)
	if _, err := db.Exec("INSERT INTO records(agent_id,kind,record_id,payload,received_at_ns) VALUES('qa','event','qa',?,1)", original); err != nil {
		t.Fatal(err)
	}
	db.Close()
	store, err = Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := store.historyDB.QueryRow("SELECT payload FROM records WHERE record_id='qa'").Scan(&payload); err != nil || string(payload) != string(original) {
		t.Fatal("index migration rewrote evidence", err)
	}
	var version int
	store.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 4 {
		t.Fatal("unexpected schema version change")
	}
	reader := store.historyDB
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Ping(); err == nil {
		t.Fatal("reader remained open after Store.Close")
	}
}
func TestActiveSparseMetadataQueryCancellationAndPoolRecovery(t *testing.T) {
	f := setup(t)
	// One candidate is immediate, but satisfying LIMIT 2 requires an intentionally
	// huge sparse search. The bounded aggregate keeps all work in the initial step.
	q := `WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT 'qa' AS agent_id,'event' AS display_kind,'missing' AS record_id,1 AS received_at_ns,NULL AS payload,'event' AS source_kind,0 AS item FROM n WHERE x=0 OR x=100000000 LIMIT 2`
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := f.store.readHistoryPage(ctx, q, nil, 20, historyResponseBytes, true)
	if err == nil || ctx.Err() == nil || time.Since(start) > time.Second {
		t.Fatalf("active search was not cancelled: %v elapsed=%s", err, time.Since(start))
	}
	if err := f.store.historyDB.PingContext(context.Background()); err != nil {
		t.Fatal("reader did not recover", err)
	}
	reader, err := f.store.historyDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, call := range []func(context.Context) error{func(ctx context.Context) error { _, err := f.store.History(ctx, "", "", 20); return err }, func(ctx context.Context) error { _, err := f.store.Audit(ctx, 20); return err }} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
		err := call(ctx)
		cancel()
		if err != errHistoryTimeout {
			t.Fatal("admin pool wait did not retain shorter deadline", err)
		}
	}
	req := httptest.NewRequest("GET", "/api/state", nil)
	response := httptest.NewRecorder()
	f.server.ConsoleHandler().ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatal("held history reader blocked state transaction")
	}
}

func TestHistoryWireEscapingAndMissingEvidenceFailClosed(t *testing.T) {
	raw := []byte("{\"value\":\"<>&\u2028\u2029\"}")
	encoded, err := json.Marshal(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if historyJSONBytes(raw) < len(encoded) {
		t.Fatal("HTML/line-separator escaping bypasses the byte budget")
	}
	f := setup(t)
	query := `SELECT 'missing-agent' AS agent_id,'event' AS display_kind,'missing-record' AS record_id,1 AS received_at_ns,NULL AS payload,'event' AS source_kind,0 AS item`
	if _, _, err := f.store.readHistoryPage(context.Background(), query, nil, 20, historyResponseBytes, true); err == nil {
		t.Fatal("missing immutable evidence was silently skipped")
	}
	if err := f.store.historyDB.Ping(); err != nil {
		t.Fatal("reader failed to recover after missing evidence", err)
	}
}
