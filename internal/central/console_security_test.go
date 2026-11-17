package central

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type consoleDatabaseCheckingWriter struct {
	*httptest.ResponseRecorder
	once  sync.Once
	check func()
}

func (w *consoleDatabaseCheckingWriter) WriteHeader(status int) {
	w.once.Do(w.check)
	w.ResponseRecorder.WriteHeader(status)
}

func TestConsoleReleasesDatabaseBeforeNetworkWrite(t *testing.T) {
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	f.consoleDrafts(t, []string{"agent-a"})
	stalePreview := f.preview(t)
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "업데이트", Version: 1, Settings: defaultConsoleSettings(time.Now())}), 200, nil)
	for i := 0; i < 3; i++ {
		if _, err := f.store.db.Exec("INSERT INTO records(agent_id,kind,record_id,payload,received_at_ns) VALUES('agent-a','event',?,?,?)", fmt.Sprint(i), []byte(`{"event":"test"}`), time.Now().UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	for _, route := range []struct {
		method string
		path   string
		value  any
		status int
	}{
		{"GET", "/api/state", nil, 200},
		{"GET", "/api/agents/agent-a/policy", nil, 200},
		{"GET", "/api/agents/missing/policy", nil, 404},
		{"GET", "/api/history?limit=1", nil, 200},
		{"GET", "/api/audit?limit=1", nil, 200},
		{"POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "default", AgentIDs: []string{"agent-a"}}, 200},
		{"POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "missing", AgentIDs: []string{"agent-a"}}, 404},
		{"POST", "/api/removal", removalRequest{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Challenge: "invalid"}, 400},
		{"POST", "/api/deploy", map[string]any{"preview_token": stalePreview, "confirm": true}, 409},
	} {
		t.Run(route.method+route.path, func(t *testing.T) {
			body, err := json.Marshal(route.value)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(route.method, route.path, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := &consoleDatabaseCheckingWriter{ResponseRecorder: httptest.NewRecorder()}
			response.check = func() {
				ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
				defer cancel()
				var count int
				if err := f.store.db.QueryRowContext(ctx, "SELECT count(*) FROM agents").Scan(&count); err != nil {
					t.Errorf("database still occupied during HTTP write: %v", err)
				}
			}
			f.server.ConsoleHandler().ServeHTTP(response, request)
			consoleWant(t, response.ResponseRecorder, route.status, nil)
		})
	}
}

func TestConsoleFleetTruncationIsExplicit(t *testing.T) {
	f := setup(t)
	tx, err := f.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	statement, err := tx.Prepare("INSERT INTO agents(agent_id,enrollment_id,cert_serial,enrolled_at_ns) VALUES(?,?,?,1)")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1001; i++ {
		id := fmt.Sprintf("agent-%04d", i)
		if _, err = statement.Exec(id, "enrollment", id); err != nil {
			t.Fatal(err)
		}
	}
	_ = statement.Close()
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var state struct {
		Agents    []Agent `json:"agents"`
		Total     int     `json:"total_agents"`
		Truncated bool    `json:"agents_truncated"`
	}
	consoleWant(t, f.console(t, "GET", "/api/state", nil), 200, &state)
	if len(state.Agents) != 1000 || state.Total != 1001 || !state.Truncated {
		t.Fatalf("hidden fleet count: agents=%d total=%d truncated=%v", len(state.Agents), state.Total, state.Truncated)
	}
}

func TestConsoleStrictRequestsTamperingAndSafeErrors(t *testing.T) {
	f := setup(t)
	f.enroll(t, "agent-a")
	f.consoleDrafts(t, []string{"agent-a"})
	for _, route := range []struct {
		path string
		body string
	}{
		{"/api/enrollment", `{"agent_id":"agent-a","ttl_seconds":9223372036854775807}`},
		{"/api/enrollment", `{"agent_id":"agent-a","operator_token":"hidden"}`},
		{"/api/revoke", `{"agent_id":"agent-a","confirm":true} {}`},
		{"/api/deploy/preview", `{"template_id":"default","agent_ids":["agent-a","agent-a"]}`},
		{"/api/groups", `{"id":"new","name":"new","agent_ids":["agent-a","agent-a"]}`},
	} {
		request := httptest.NewRequest("POST", route.path, strings.NewReader(route.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		f.server.ConsoleHandler().ServeHTTP(response, request)
		consoleWant(t, response, 400, nil)
	}
	request := httptest.NewRequest("POST", "/api/enrollment", strings.NewReader(`{"agent_id":"new"}`))
	response := httptest.NewRecorder()
	f.server.ConsoleHandler().ServeHTTP(response, request)
	consoleWant(t, response, 415, nil)
	token := f.preview(t)
	separator := strings.IndexByte(token, '.')
	changed := []byte(token)
	if changed[separator+1] == 'A' {
		changed[separator+1] = 'B'
	} else {
		changed[separator+1] = 'A'
	}
	consoleWant(t, f.deploy(t, string(changed)), 409, nil)
	consoleWant(t, f.deploy(t, strings.Repeat("a", 800000)), 409, nil)
	var logs bytes.Buffer
	f.server.logger = slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := f.store.db.Exec(`CREATE TRIGGER fail_credential BEFORE INSERT ON enrollment_tokens BEGIN SELECT RAISE(ABORT,'private-secret-marker'); END`); err != nil {
		t.Fatal(err)
	}
	response = f.console(t, "POST", "/api/enrollment", map[string]any{"agent_id": "new"})
	consoleWant(t, response, 500, nil)
	if strings.Contains(logs.String(), "private-secret-marker") || strings.Contains(response.Body.String(), "private-secret-marker") {
		t.Fatal("internal database error exposed")
	}
}
