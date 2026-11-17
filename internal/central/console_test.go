package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func (f *fixture) console(t *testing.T, method, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if value != nil {
		var err error
		body, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.server.ConsoleHandler().ServeHTTP(response, request)
	return response
}

func consoleWant(t *testing.T, response *httptest.ResponseRecorder, status int, output any) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if output != nil {
		if err := json.Unmarshal(response.Body.Bytes(), output); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) consoleDrafts(t *testing.T, agents []string) {
	t.Helper()
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "운영 정책", Settings: defaultConsoleSettings(time.Now())}), 200, nil)
	consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "웹 서버", AgentIDs: agents}), 200, nil)
}

func (f *fixture) preview(t *testing.T) string {
	t.Helper()
	var response struct {
		Token string `json:"preview_token"`
	}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "default", GroupIDs: []string{"web"}}), 200, &response)
	if response.Token == "" {
		t.Fatal("missing preview token")
	}
	return response.Token
}

func (f *fixture) deploy(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return f.console(t, "POST", "/api/deploy", map[string]any{"preview_token": token, "confirm": true})
}

func TestConsoleSchemaUpgradePreservesVersionOneState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "central.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"PRAGMA user_version=1",
		"INSERT INTO agents(agent_id,enrollment_id,cert_serial,enrolled_at_ns,desired_policy_revision) VALUES('legacy','enrollment','serial',123,7)",
		"INSERT INTO policies(agent_id,enrollment_id,revision,signed_json) VALUES('legacy','enrollment',7,'exact-signed-bytes')",
		"INSERT INTO enrollment_tokens(token_hash,agent_id,expires_at_ns,csr_hash,enrollment_id,certificate_pem) VALUES('hash','legacy',456,'csr','enrollment','certificate')",
		"INSERT INTO delivery_cursors(agent_id,enrollment_id,spool_id,acknowledged) VALUES('legacy','enrollment','spool',9)",
	} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var version, revision, cursor int
	var signed, certificate string
	if err = store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatalf("schema version=%d error=%v", version, err)
	}
	if err = store.db.QueryRow("SELECT desired_policy_revision FROM agents WHERE agent_id='legacy'").Scan(&revision); err != nil || revision != 7 {
		t.Fatalf("legacy policy changed: %d %v", revision, err)
	}
	if err = store.db.QueryRow("SELECT signed_json FROM policies").Scan(&signed); err != nil || signed != "exact-signed-bytes" {
		t.Fatalf("signed bytes changed: %q %v", signed, err)
	}
	if err = store.db.QueryRow("SELECT certificate_pem FROM enrollment_tokens").Scan(&certificate); err != nil || certificate != "certificate" {
		t.Fatalf("enrollment acknowledgement changed: %q %v", certificate, err)
	}
	if err = store.db.QueryRow("SELECT acknowledged FROM delivery_cursors").Scan(&cursor); err != nil || cursor != 9 {
		t.Fatalf("delivery state changed: %d %v", cursor, err)
	}
	if _, err = store.saveConsoleGroup(context.Background(), ConsoleGroup{ID: "new", Name: "새 그룹"}, time.Now()); err != nil {
		t.Fatalf("new schema unavailable: %v", err)
	}
}

func TestConsoleOptimisticDraftsNeverDeploy(t *testing.T) {
	f := setup(t)
	f.enroll(t, "agent-a")
	f.consoleDrafts(t, []string{"agent-a"})
	consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "충돌", AgentIDs: []string{"agent-a"}}), 409, nil)
	var group ConsoleGroup
	consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "업데이트", Version: 1}), 200, &group)
	if group.Version != 2 || len(group.AgentIDs) != 0 {
		t.Fatalf("group update=%+v", group)
	}
	consoleWant(t, f.console(t, "DELETE", "/api/groups/web?version=1", nil), 409, nil)
	consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "bad", Name: "잘못된 그룹", AgentIDs: []string{"missing"}}), 400, nil)
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "충돌", Settings: defaultConsoleSettings(time.Now())}), 409, nil)
	consoleWant(t, f.console(t, "DELETE", "/api/templates/default?version=2", nil), 409, nil)
	consoleWant(t, f.console(t, "DELETE", "/api/groups/web?version=2", nil), 200, nil)
	consoleWant(t, f.console(t, "DELETE", "/api/groups/web?version=2", nil), 404, nil)
	consoleWant(t, f.console(t, "DELETE", "/api/templates/default?version=1", nil), 200, nil)
	agents, err := f.store.Agents(context.Background())
	if err != nil || len(agents) != 1 || agents[0].DesiredPolicyRevision != 0 {
		t.Fatalf("editing drafts deployed policy: %+v %v", agents, err)
	}
	consoleWant(t, f.console(t, "GET", "/api/agents/agent-a/policy", nil), 200, nil)
}

func TestConsoleTransactionalDeploymentAndPendingIntegrity(t *testing.T) {
	f := setup(t)
	first, _, _ := f.enroll(t, "agent-a")
	second, _, _ := f.enroll(t, "agent-b")
	f.consoleDrafts(t, []string{"agent-b", "agent-a"})
	settings := defaultConsoleSettings(time.Now())
	settings.Integrity = ConsoleIntegrity{Enabled: true, Mode: "enforce", RequireTPM: true, Paths: []string{"/usr/sbin", "/opt/application"}}
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "무결성 정책", Version: 1, Settings: settings}), 200, nil)
	token := f.preview(t)
	agents, _ := f.store.Agents(context.Background())
	if agents[0].DesiredPolicyRevision != 0 || agents[1].DesiredPolicyRevision != 0 {
		t.Fatal("preview changed desired policy")
	}
	consoleWant(t, f.console(t, "POST", "/api/deploy", map[string]any{"preview_token": token, "confirm": false}), 400, nil)
	var result struct {
		Targets []consoleDeployTarget `json:"targets"`
		Pending []string              `json:"pending_features"`
	}
	consoleWant(t, f.deploy(t, token), 200, &result)
	if len(result.Targets) != 2 || len(result.Pending) != 1 || result.Pending[0] != "integrity" {
		t.Fatalf("deployment=%+v", result)
	}
	for _, target := range []managed.EnrollResponse{first, second} {
		signed, err := f.store.LatestPolicy(context.Background(), target.AgentID, target.EnrollmentID)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(signed)
		if bytes.Contains(body, []byte("integrity")) {
			t.Fatal("unsupported integrity leaked into managed-v1 wire")
		}
		if _, err = managed.DecodeSignedPolicy(body); err != nil {
			t.Fatalf("old strict decoder rejected policy: %v", err)
		}
		policy, err := managed.VerifyPolicy(signed, map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}, target.AgentID, target.EnrollmentID, 1, time.Now())
		if err != nil || policy.Revision != 1 || policy.Response.Mode != "observe" || policy.Response.Action != "none" {
			t.Fatalf("wire policy=%+v error=%v", policy, err)
		}
	}
	consoleWant(t, f.deploy(t, token), 409, nil)
	// A saved template is mutable; a deployed revision's desired settings are not.
	consoleWant(t, f.console(t, "DELETE", "/api/templates/default?version=2", nil), 200, nil)
	var existing struct {
		Policy  managed.Policy  `json:"policy"`
		Pending []string        `json:"pending_features"`
		Desired ConsoleSettings `json:"desired_settings"`
	}
	consoleWant(t, f.console(t, "GET", "/api/agents/agent-a/policy", nil), 200, &existing)
	if existing.Policy.Revision != 1 || len(existing.Pending) != 1 || !existing.Desired.Integrity.RequireTPM || len(existing.Desired.Integrity.Paths) != 2 {
		t.Fatalf("desired settings lost after template deletion: %+v", existing)
	}
	var state struct {
		Agents []struct {
			Pending []string `json:"pending_features"`
		} `json:"agents"`
		Defaults ConsoleSettings `json:"defaults"`
	}
	consoleWant(t, f.console(t, "GET", "/api/state", nil), 200, &state)
	if len(state.Agents) != 2 || len(state.Agents[0].Pending) != 1 || state.Defaults.Response.Mode != "observe" {
		t.Fatalf("state=%+v", state)
	}
}

func TestConsoleDeploymentRollbackAndConcurrentReplay(t *testing.T) {
	f := setup(t)
	f.enroll(t, "agent-a")
	f.enroll(t, "agent-b")
	f.consoleDrafts(t, []string{"agent-a", "agent-b"})
	token := f.preview(t)
	if _, err := f.store.db.Exec(`CREATE TRIGGER fail_second_policy BEFORE INSERT ON policies WHEN NEW.agent_id='agent-b' BEGIN SELECT RAISE(ABORT,'simulated failure'); END`); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.deploy(t, token), 500, nil)
	for _, table := range []string{"policies", "console_policy_settings"} {
		var count int
		if err := f.store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial deployment in %s count=%d error=%v", table, count, err)
		}
	}
	agents, _ := f.store.Agents(context.Background())
	if agents[0].DesiredPolicyRevision != 0 || agents[1].DesiredPolicyRevision != 0 {
		t.Fatal("failed deployment advanced revisions")
	}
	var count int
	if err := f.store.db.QueryRow("SELECT count(*) FROM audit WHERE kind='policy.assigned'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed deployment left audit count=%d error=%v", count, err)
	}
	if _, err := f.store.db.Exec("DROP TRIGGER fail_second_policy"); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- f.deploy(t, token).Code
		}()
	}
	wait.Wait()
	close(statuses)
	results := map[int]int{}
	for status := range statuses {
		results[status]++
	}
	if results[200] != 1 || results[409] != 1 {
		t.Fatalf("concurrent deployment results=%v", results)
	}
}

func TestConsolePreviewReturnsActualTemplateSnapshot(t *testing.T) {
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	f.consoleDrafts(t, []string{"agent-a"})
	var staleUI struct {
		Templates []ConsoleTemplate `json:"templates"`
	}
	consoleWant(t, f.console(t, "GET", "/api/state", nil), 200, &staleUI)
	if len(staleUI.Templates) != 1 || staleUI.Templates[0].Version != 1 || staleUI.Templates[0].Settings.Response.Mode != "observe" {
		t.Fatalf("unexpected original UI snapshot: %+v", staleUI)
	}
	changed := staleUI.Templates[0]
	changed.Settings.Response.Mode, changed.Settings.Response.Action = "enforce", "terminate"
	changed.Settings.Response.RequiredCapabilities = []string{"response.terminate"}
	consoleWant(t, f.console(t, "POST", "/api/templates", changed), 200, nil)
	var preview struct {
		Token    string          `json:"preview_token"`
		Template ConsoleTemplate `json:"template"`
	}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: staleUI.Templates[0].ID, AgentIDs: []string{"agent-a"}}), 200, &preview)
	if preview.Template.ID != changed.ID || preview.Template.Version != 2 || preview.Template.Settings.Response.Mode != "enforce" || preview.Template.Settings.Response.Action != "terminate" {
		t.Fatalf("preview concealed the changed server template: %+v", preview.Template)
	}
	snapshot, err := f.server.decodeConsolePreview(preview.Token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := consoleHash(preview.Template.Settings)
	if err != nil || snapshot.TemplateHash != hash || snapshot.TemplateVersion != preview.Template.Version {
		t.Fatalf("displayed template differs from signed snapshot: %v", err)
	}
	consoleWant(t, f.deploy(t, preview.Token), 200, nil)
	signed, err := f.store.LatestPolicy(context.Background(), enrolled.AgentID, enrolled.EnrollmentID)
	if err != nil || signed.Policy.Response.Mode != preview.Template.Settings.Response.Mode {
		t.Fatalf("deployed policy differs from displayed preview: %+v %v", signed.Policy, err)
	}
}

func TestConsoleStaleDeploymentDependencies(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *fixture)
	}{
		{"template", func(t *testing.T, f *fixture) {
			consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "변경", Version: 1, Settings: defaultConsoleSettings(time.Now())}), 200, nil)
		}},
		{"group", func(t *testing.T, f *fixture) {
			consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "변경", Version: 1, AgentIDs: []string{"agent-b"}}), 200, nil)
		}},
		{"group recreated", func(t *testing.T, f *fixture) {
			consoleWant(t, f.console(t, "DELETE", "/api/groups/web?version=1", nil), 200, nil)
			consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "웹 서버", AgentIDs: []string{"agent-a", "agent-b"}}), 200, nil)
		}},
		{"template recreated", func(t *testing.T, f *fixture) {
			consoleWant(t, f.console(t, "DELETE", "/api/templates/default?version=1", nil), 200, nil)
			consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "운영 정책", Settings: defaultConsoleSettings(time.Now())}), 200, nil)
		}},
		{"reenrollment", func(t *testing.T, f *fixture) { f.enroll(t, "agent-a") }},
		{"revoked", func(t *testing.T, f *fixture) {
			consoleWant(t, f.console(t, "POST", "/api/revoke", map[string]any{"agent_id": "agent-a", "confirm": true}), 200, nil)
		}},
		{"revision", func(t *testing.T, f *fixture) {
			enrollment, err := f.store.CurrentEnrollment(context.Background(), "agent-a")
			if err != nil {
				t.Fatal(err)
			}
			consoleWant(t, f.request(t, "POST", "/admin/policy", managed.DefaultPolicy("agent-a", enrollment, 1, time.Now()), nil, f.operator(t)), 201, nil)
		}},
		{"expired", func(t *testing.T, f *fixture) {
			future := time.Now().Add(previewLifetime + time.Second)
			f.server.now = func() time.Time { return future }
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			f := setup(t)
			f.enroll(t, "agent-a")
			f.enroll(t, "agent-b")
			f.consoleDrafts(t, []string{"agent-a", "agent-b"})
			token := f.preview(t)
			item.change(t, f)
			consoleWant(t, f.deploy(t, token), 409, nil)
		})
	}
}

func TestConsoleIssuedSecretsAndConfirmedRevocation(t *testing.T) {
	f := setup(t)
	var issued struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"token"`
	}
	consoleWant(t, f.console(t, "POST", "/api/enrollment", map[string]any{"agent_id": "issued-agent", "ttl_seconds": 60}), 201, &issued)
	requestCSR, _ := csr(t, "issued-agent")
	_, _, err := f.store.Enroll(context.Background(), issued.Token, issued.AgentID, requestCSR, f.material, time.Now())
	if err != nil {
		t.Fatalf("issued token unusable: %v", err)
	}
	differentCSR, _ := csr(t, "issued-agent")
	if _, _, err = f.store.Enroll(context.Background(), issued.Token, issued.AgentID, differentCSR, f.material, time.Now()); err == nil {
		t.Fatal("issued credential reused for another enrollment")
	}
	enrolled, certificate, _ := f.enroll(t, "agent-a")
	challenge, err := managed.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	var grant managed.SignedRemovalGrant
	consoleWant(t, f.console(t, "POST", "/api/removal", removalRequest{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Challenge: challenge}), 201, &grant)
	if _, err = managed.VerifyRemovalGrant(grant, map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}, "agent-a", enrolled.EnrollmentID, challenge, time.Now()); err != nil {
		t.Fatalf("invalid signed removal approval: %v", err)
	}
	consoleWant(t, f.console(t, "POST", "/api/removal", removalRequest{AgentID: "agent-a", EnrollmentID: "another-enrollment", Challenge: challenge}), 401, nil)
	for _, path := range []string{"/api/state", "/api/audit?limit=500", "/api/history?limit=500"} {
		response := f.console(t, "GET", path, nil)
		consoleWant(t, response, 200, nil)
		if strings.Contains(response.Body.String(), issued.Token) || strings.Contains(response.Body.String(), grant.Signature) || strings.Contains(response.Body.String(), f.operator(t)) {
			t.Fatalf("secret disclosed by %s", path)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("secret/state response can be cached")
		}
	}
	consoleWant(t, f.console(t, "POST", "/api/revoke", map[string]any{"agent_id": "agent-a", "confirm": false}), 400, nil)
	consoleWant(t, f.request(t, "GET", "/v1/policy", nil, certificate, ""), 204, nil)
	consoleWant(t, f.console(t, "POST", "/api/revoke", map[string]any{"agent_id": "agent-a", "confirm": true}), 200, nil)
	consoleWant(t, f.request(t, "GET", "/v1/policy", nil, certificate, ""), 401, nil)
}

func TestConsolePolicyValidationAndWarnings(t *testing.T) {
	for _, change := range []func(*ConsoleSettings){
		func(s *ConsoleSettings) { s.ValidityHours = 0 },
		func(s *ConsoleSettings) { s.ValidityHours = 8761 },
		func(s *ConsoleSettings) { s.Response.Mode = "invalid" },
		func(s *ConsoleSettings) { s.Monitoring.SampleIntervalSeconds = 1 },
		func(s *ConsoleSettings) { s.Integrity.Mode = "invalid" },
		func(s *ConsoleSettings) { s.Integrity.Paths = []string{"relative"} },
		func(s *ConsoleSettings) { s.Integrity.Paths = []string{"/a/../b"} },
		func(s *ConsoleSettings) { s.Integrity.Paths = []string{"/a", "/a"} },
	} {
		settings := defaultConsoleSettings(time.Now())
		change(&settings)
		if settings.validate() == nil {
			t.Fatalf("invalid settings accepted: %+v", settings)
		}
	}
	now := time.Now().UTC()
	settings := defaultConsoleSettings(now)
	settings.Response.Mode, settings.Response.Action = "enforce", "terminate"
	settings.Response.RequiredCapabilities = []string{"response.terminate"}
	body, _ := json.Marshal(managed.Heartbeat{Status: model.AgentStatus{CapabilityReport: &model.CapabilityReport{ProbedAt: now, Capabilities: map[string]model.Capability{"response.terminate": {State: model.CapabilitySupported, RuntimeState: "available"}}}}})
	warnings := strings.Join(consolePolicyWarnings(settings, body, now), " ")
	if !strings.Contains(warnings, "비활성화") || !strings.Contains(warnings, "opt-in") {
		t.Fatalf("local opt-out misreported: %s", warnings)
	}
	stale := strings.Join(consolePolicyWarnings(settings, body, now.Add(time.Hour)), " ")
	if !strings.Contains(stale, "오래되었") {
		t.Fatalf("stale report trusted: %s", stale)
	}
}

func TestConsoleHistoryAndAuditStablePagination(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// Equal timestamps and IDs across agents/kinds must not skip or repeat rows.
	for _, agent := range []string{"a", "b"} {
		for _, kind := range []string{"event", "finding", "event_bundle"} {
			for i := 0; i < 3; i++ {
				payload := `{"findings":[{"id":"finding"}]}`
				if i == 0 && kind == "event_bundle" {
					payload = `{"findings":[]}`
				}
				if _, err := f.store.db.Exec("INSERT INTO records(agent_id,kind,record_id,payload,received_at_ns) VALUES(?,?,?,?,?)", agent, kind, fmt.Sprint(i), payload, now.UnixNano()); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, filter := range []struct {
		kind string
		want int
	}{{"", 18}, {"detections", 10}, {"finding", 6}} {
		seen := map[string]bool{}
		cursor := ""
		for page := 0; page < 20; page++ {
			response := f.console(t, "GET", "/api/history?limit=2&kind="+filter.kind+"&before="+url.QueryEscape(cursor), nil)
			var items []HistoryRecord
			consoleWant(t, response, 200, &items)
			for _, item := range items {
				key := item.AgentID + "/" + item.Kind + "/" + item.ID
				if seen[key] {
					t.Fatalf("repeated page record: %s", key)
				}
				seen[key] = true
			}
			cursor = response.Header().Get("X-Next-Cursor")
			if cursor == "" {
				break
			}
		}
		if len(seen) != filter.want {
			t.Fatalf("filter=%s records=%d want=%d", filter.kind, len(seen), filter.want)
		}
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err = appendAudit(ctx, tx, "a", "test.audit", nil, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		response := f.console(t, "GET", "/api/audit?limit=2&before="+url.QueryEscape(cursor), nil)
		var items []AuditEntry
		consoleWant(t, response, 200, &items)
		for _, item := range items {
			if seen[item.ID] {
				t.Fatal("repeated audit row")
			}
			seen[item.ID] = true
		}
		cursor = response.Header().Get("X-Next-Cursor")
		if cursor == "" {
			break
		}
	}
	if len(seen) != 7 {
		t.Fatalf("audit records=%d", len(seen))
	}
	for _, path := range []string{"/api/history?limit=0", "/api/history?before=bad", "/api/audit?before=-1"} {
		consoleWant(t, f.console(t, "GET", path, nil), 400, nil)
	}
}
