package central

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func addHistoryRecord(t *testing.T, f *fixture, agent, kind, id string, at time.Time, payload any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.db.Exec("INSERT INTO records(agent_id,kind,record_id,received_at_ns,payload) VALUES(?,?,?,?,?)", agent, kind, id, at.UnixNano(), body); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleHistoryViewsFilterAndPageBundleItems(t *testing.T) {
	f := setup(t)
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	event := map[string]any{"event_id": "exec-1", "event_type": "process.exec", "event_time": base, "process": map[string]any{"exe": "/usr/bin/bash"}}
	addHistoryRecord(t, f, "agent-a", "event", "exec-1", base, event)
	addHistoryRecord(t, f, "agent-a", "event_bundle", "exec-2", base.Add(time.Second), map[string]any{"event": event, "findings": []any{
		map[string]any{"finding_id": "finding-1", "rule_id": "rule.one", "summary": "first"}, map[string]any{"finding_id": "finding-2", "rule_id": "rule.two", "summary": "second"},
	}})
	addHistoryRecord(t, f, "agent-b", "finding", "finding-3", base.Add(2*time.Second), map[string]any{"finding_id": "finding-3", "rule_id": "rule.one"})
	addHistoryRecord(t, f, "agent-a", "audit", "audit-1", base, managed.AuditRecord{ID: "audit-1", Action: "removal.requested", Result: "pending"})
	var audits []HistoryRecord
	consoleWant(t, f.console(t, "GET", "/api/history?view=agent_audit&type=removal.requested", nil), 200, &audits)
	if len(audits) != 1 || audits[0].Kind != "audit" || audits[0].ID != "audit-1" {
		t.Fatalf("agent audit action filter: %+v", audits)
	}
	consoleWant(t, f.console(t, "GET", "/api/history?view=agent_audit&type=other.action", nil), 200, &audits)
	if len(audits) != 0 {
		t.Fatalf("unmatched agent audit action returned records: %+v", audits)
	}
	path := "/api/history?view=detections&agent_id=agent-a&limit=1"
	seen := map[string]bool{}
	for pages := 0; pages < 2; pages++ {
		response := f.console(t, "GET", path, nil)
		var items []HistoryRecord
		consoleWant(t, response, 200, &items)
		if len(items) != 1 || items[0].Kind != "finding" {
			t.Fatalf("finding projection: %+v", items)
		}
		var finding struct {
			ID string `json:"finding_id"`
		}
		if err := json.Unmarshal(items[0].Payload, &finding); err != nil {
			t.Fatal(err)
		}
		if seen[finding.ID] {
			t.Fatal("bundle item repeated on another page")
		}
		seen[finding.ID] = true
		cursor := response.Header().Get("X-Next-Cursor")
		if pages == 0 {
			if cursor == "" {
				t.Fatal("missing cursor inside a multi-finding bundle")
			}
			consoleWant(t, f.console(t, "GET", path+"&q=changed&before="+url.QueryEscape(cursor), nil), 400, nil)
			path += "&before=" + url.QueryEscape(cursor)
		} else if cursor != "" {
			t.Fatal("extra page after last finding")
		}
	}
	if !seen["finding-1"] || !seen["finding-2"] {
		t.Fatalf("findings lost: %+v", seen)
	}
	for _, query := range []string{"view=events&agent_id=agent-a&type=process.exec", "view=detections&type=rule.one", "view=detections&agent_id=agent-a&q=second"} {
		var items []HistoryRecord
		consoleWant(t, f.console(t, "GET", "/api/history?"+query, nil), 200, &items)
		want := 2
		if strings.Contains(query, "q=second") {
			want = 1
		}
		if len(items) != want {
			t.Fatalf("query %s: got %d want %d", query, len(items), want)
		}
	}
	from := url.QueryEscape(base.Add(time.Second).Format(time.RFC3339))
	until := url.QueryEscape(base.Add(2 * time.Second).Format(time.RFC3339))
	var bounded []HistoryRecord
	consoleWant(t, f.console(t, "GET", "/api/history?view=events&from="+from+"&until="+until, nil), 200, &bounded)
	if len(bounded) != 1 || bounded[0].ID != "exec-2" {
		t.Fatalf("date bounds were not inclusive/exclusive: %+v", bounded)
	}
	for _, query := range []string{"view=unknown", "view=events&from=not-a-date", "view=events&limit=0", "view=events&from=" + until + "&until=" + from} {
		consoleWant(t, f.console(t, "GET", "/api/history?"+query, nil), 400, nil)
	}
}

func TestConsoleDetectionHistorySkipsNullFindings(t *testing.T) {
	for _, test := range []struct {
		name     string
		findings any
		omitted  bool
		want     int
	}{
		{name: "nil findings", findings: []model.Finding(nil)},
		{name: "empty findings", findings: []model.Finding{}},
		{name: "omitted findings", omitted: true},
		{name: "null array element", findings: []any{nil}},
		{name: "mixed null and finding", findings: []any{nil, map[string]any{"finding_id": "real-finding", "rule_id": "rule.real"}, nil}, want: 1},
		{name: "non-array object", findings: map[string]any{"finding_id": "not-an-array", "rule_id": "rule.real"}},
		{name: "non-object elements", findings: []any{"text", 12, true, []any{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := setup(t)
			base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
			bundle := map[string]any{"event": map[string]any{"event_id": "exec-1", "event_type": "process.exec", "event_time": base}}
			if !test.omitted {
				bundle["findings"] = test.findings
			}
			addHistoryRecord(t, f, "agent-a", "event_bundle", "exec-1", base, bundle)
			var items []HistoryRecord
			consoleWant(t, f.console(t, "GET", "/api/history?view=detections", nil), 200, &items)
			if len(items) != test.want {
				t.Fatalf("projected %d findings, want %d: %+v", len(items), test.want, items)
			}
			for _, item := range items {
				var finding model.Finding
				if err := json.Unmarshal(item.Payload, &finding); err != nil || finding.ID != "real-finding" {
					t.Fatalf("non-finding projection: %s, %v", item.Payload, err)
				}
			}
			var events []HistoryRecord
			consoleWant(t, f.console(t, "GET", "/api/history?view=events", nil), 200, &events)
			if len(events) != 1 {
				t.Fatalf("non-detection bundle lost its event: %+v", events)
			}
		})
	}
}

func TestConsoleDetectionHistoryUsesFindingBundleIndex(t *testing.T) {
	f := setup(t)
	query, args := buildHistoryQuery(historyFilter{View: "detections"}, 0, 0, historyPageCursor{}, 20)
	query = "EXPLAIN QUERY PLAN " + query
	rows, err := f.store.db.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(details, "\n"), "records_history_detection_bundle_idx") {
		t.Fatalf("detection paging scans non-detection bundles: %v", details)
	}
}

func TestConsoleAuditFiltersAreServerSideAndCursorBound(t *testing.T) {
	f := setup(t)
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	for _, agent := range []string{"agent-a", "agent-b"} {
		for index := 0; index < 3; index++ {
			if _, err := f.store.db.Exec("INSERT INTO audit(agent_id,kind,created_at_ns,details_json) VALUES(?,?,?,?)", agent, "test.action", base.Add(time.Duration(index)*time.Second).UnixNano(), []byte(`{"note":"searchable"}`)); err != nil {
				t.Fatal(err)
			}
		}
	}
	path := "/api/audit?view=audit&agent_id=agent-a&type=test.action&q=searchable&limit=1&from=" + url.QueryEscape(base.Add(time.Second).Format(time.RFC3339))
	response := f.console(t, "GET", path, nil)
	var first []AuditEntry
	consoleWant(t, response, 200, &first)
	if len(first) != 1 || first[0].AgentID != "agent-a" {
		t.Fatalf("audit filters: %+v", first)
	}
	cursor := response.Header().Get("X-Next-Cursor")
	if cursor == "" {
		t.Fatal("missing audit cursor")
	}
	var second []AuditEntry
	consoleWant(t, f.console(t, "GET", path+"&before="+url.QueryEscape(cursor), nil), 200, &second)
	if len(second) != 1 || second[0].ID == first[0].ID {
		t.Fatalf("audit paging: %+v", second)
	}
	consoleWant(t, f.console(t, "GET", "/api/audit?view=audit&agent_id=agent-b&before="+url.QueryEscape(cursor), nil), 400, nil)
}

func TestAgentErrorHistoryRecordsTransitionsWithoutRawDiagnostics(t *testing.T) {
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	base := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	heartbeat := managed.Heartbeat{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Status: model.AgentStatus{Mode: "error", Health: "error", LastError: "storage: process last-seen time precedes first-seen time SECRET_TOKEN"}}
	for index := 0; index < 3; index++ {
		if err := f.store.Heartbeat(context.Background(), "agent-a", heartbeat, base.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	heartbeat.Status.LastError = "malformed collector payload SECRET_TOKEN"
	if err := f.store.Heartbeat(context.Background(), "agent-a", heartbeat, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	heartbeat.Status = model.AgentStatus{Mode: "active", Health: "healthy"}
	if err := f.store.Heartbeat(context.Background(), "agent-a", heartbeat, base.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	response := f.console(t, "GET", "/api/errors?type=agent&agent_id=agent-a", nil)
	var items []AgentErrorRecord
	consoleWant(t, response, 200, &items)
	if len(items) != 3 || items[0].Transition != "recovered" || items[1].Transition != "changed" || items[2].Transition != "occurred" || items[2].Category != "storage_order" {
		t.Fatalf("error transitions: %+v", items)
	}
	if strings.Contains(response.Body.String(), "SECRET") || strings.Contains(response.Body.String(), "last-seen") {
		t.Fatal("raw diagnostics leaked into historical error API")
	}
	heartbeat.EnrollmentID = "wrong-enrollment"
	if err := f.store.Heartbeat(context.Background(), "agent-a", heartbeat, base); err != ErrUnauthorized {
		t.Fatalf("wrong enrollment error=%v", err)
	}
	consoleWant(t, f.console(t, "GET", "/api/errors?type=unknown", nil), 400, nil)
}

func TestErrorBaselineCapturedOnceWithoutRewritingHeartbeat(t *testing.T) {
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	heartbeat := managed.Heartbeat{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Status: model.AgentStatus{Health: "error", LastError: "storage: existing private diagnostic"}}
	body, _ := json.Marshal(heartbeat)
	if _, err := f.store.db.Exec("UPDATE agents SET heartbeat_json=? WHERE agent_id='agent-a'", body); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		tx, err := f.store.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = initializeErrorHistory(context.Background(), tx); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	var items []AgentErrorRecord
	consoleWant(t, f.console(t, "GET", "/api/errors", nil), 200, &items)
	if len(items) != 1 || items[0].Transition != "baseline" {
		t.Fatalf("baseline duplicated or missing: %+v", items)
	}
	var stored []byte
	if err := f.store.db.QueryRow("SELECT heartbeat_json FROM agents WHERE agent_id='agent-a'").Scan(&stored); err != nil || string(stored) != string(body) {
		t.Fatalf("migration changed latest heartbeat: %v", err)
	}
}
