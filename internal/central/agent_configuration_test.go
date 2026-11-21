package central

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

type testAgentConfigurationConsole func(string, string, []byte, string) *httptest.ResponseRecorder

func (client testAgentConfigurationConsole) call(t *testing.T, method, path string, body, into any, status int) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	consoleWant(t, client(method, path, raw, "application/json"), status, into)
}

func configHeartbeat(t *testing.T, f *fixture, agent managed.EnrollResponse, cert *x509.Certificate, report managed.AgentConfigurationReport, now time.Time) {
	t.Helper()
	snapshot, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := map[string]model.Capability{
		managed.AgentConfigurationCapability: {Details: map[string]string{"contract": managed.AgentConfigurationContract, "snapshot": string(snapshot)}},
		"storage.capacity": {Details: map[string]string{
			"utc_day": now.Format(time.DateOnly), "stored_events_today": "15", "stored_events_yesterday": "14",
			"measurement_started_at": now.Add(-48 * time.Hour).Format(time.RFC3339),
			"oldest_event_at":        now.Add(-2 * time.Hour).Format(time.RFC3339), "retention_backlog_events": "2",
		}},
	}
	h := managed.Heartbeat{AgentID: agent.AgentID, EnrollmentID: agent.EnrollmentID, SentAt: now,
		Status: model.AgentStatus{CapabilityReport: &model.CapabilityReport{Capabilities: capabilities}}}
	consoleWant(t, f.request(t, "POST", "/v1/heartbeat", h, cert, ""), 200, nil)
}

func baseConfigurationReport(minutes int) managed.AgentConfigurationReport {
	return managed.AgentConfigurationReport{Result: "local", Effective: managed.AgentConfigurationEffective{
		SampleIntervalSeconds: 10, HeartbeatIntervalSeconds: 10, ObservationHistoryMinutes: minutes, RetentionDays: 7,
		LocalObservationHistoryMinutes: minutes, LocalRetentionDays: 7, MaxObservationHistoryMinutes: 240, PanelAccess: "allow",
	}}
}

type configPreviewReply struct {
	Token     string                     `json:"preview_token"`
	Targets   []agentConfigurationTarget `json:"targets"`
	Reduction bool                       `json:"retention_reduction_required"`
}

func (client testAgentConfigurationConsole) preview(t *testing.T, req agentConfigurationRequest, expected int) configPreviewReply {
	t.Helper()
	var reply configPreviewReply
	var out any
	if expected == 200 {
		out = &reply
	}
	client.call(t, "POST", "/api/agent-configuration/preview", req, out, expected)
	return reply
}

func (client testAgentConfigurationConsole) apply(t *testing.T, token string, approve bool, expected int) {
	t.Helper()
	client.call(t, "POST", "/api/agent-configuration/apply", map[string]any{
		"preview_token": token, "confirm": true, "approve_retention_reduction": approve,
	}, nil, expected)
}

func readAssignedConfiguration(t *testing.T, f *fixture, agent managed.EnrollResponse, cert *x509.Certificate, now time.Time) managed.AgentConfiguration {
	t.Helper()
	var signed managed.SignedAgentConfiguration
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, cert, ""), 200, &signed)
	trusted := map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}
	cfg, err := managed.VerifyAgentConfiguration(signed, trusted, agent.AgentID, agent.EnrollmentID, now)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAgentConfigurationBulkPreviewRequiresRetentionConsent(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	a, certA, _ := f.enroll(t, "a")
	b, certB, _ := f.enroll(t, "b")
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, certA, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, nil, ""), http.StatusUnauthorized, nil)
	configHeartbeat(t, f, a, certA, baseConfigurationReport(120), now)
	configHeartbeat(t, f, b, certB, baseConfigurationReport(60), now)
	client := testAgentConfigurationConsole(updateConsoleClient(t, f))
	req := agentConfigurationRequest{AgentIDs: []string{"b", "a"}, Set: managed.AgentConfigurationSet{
		Monitoring: &managed.AgentConfigurationMonitoring{SampleIntervalSeconds: 35},
		Retention:  &managed.AgentConfigurationRetention{ObservationHistoryMinutes: 60},
		LocalPanel: &managed.AgentConfigurationLocalPanel{Access: "block"},
	}}
	reply := client.preview(t, req, 200)
	if !reply.Reduction || len(reply.Targets) != 2 || reply.Targets[0].AgentID != "a" || !reply.Targets[0].RetentionReduction || reply.Targets[1].RetentionReduction {
		t.Fatalf("incorrect reduction preview: %#v", reply)
	}
	impact := reply.Targets[0].RetentionImpact
	if impact == nil || impact.CurrentMinutes != 120 || impact.ProposedMinutes != 60 || impact.EstimatedNewlyExpiredMax == nil || *impact.EstimatedNewlyExpiredMax < 15 {
		t.Fatalf("incorrect estimate: %#v", impact)
	}
	client.apply(t, reply.Token, false, 400)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, certA, ""), http.StatusNoContent, nil)
	client.apply(t, reply.Token, true, 200)
	client.apply(t, reply.Token, true, 409)
	client.preview(t, req, 400)
	aCfg := readAssignedConfiguration(t, f, a, certA, now)
	bCfg := readAssignedConfiguration(t, f, b, certB, now)
	for _, cfg := range []managed.AgentConfiguration{aCfg, bCfg} {
		if cfg.BaseRevision != 0 || cfg.Revision != 1 || cfg.Set.LocalPanel.Access != "block" || cfg.Set.Monitoring.SampleIntervalSeconds != 35 {
			t.Fatalf("unexpected signed overlay: %#v", cfg)
		}
	}
	if !aCfg.RetentionReductionApproved || bCfg.RetentionReductionApproved {
		t.Fatal("approval not scoped to the affected target")
	}
	var state agentConfigurationState
	client.call(t, "GET", "/api/agent-configuration/a", nil, &state, 200)
	if state.AssignmentState != "pending" || state.DesiredRevision != 1 || state.Report.AppliedRevision != 0 {
		t.Fatalf("unexpected pending state: %#v", state)
	}
}

func TestAgentConfigurationPreservesLastAppliedOverlayAfterRejection(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	a, cert, _ := f.enroll(t, "a")
	report := baseConfigurationReport(60)
	configHeartbeat(t, f, a, cert, report, now)
	client := testAgentConfigurationConsole(updateConsoleClient(t, f))
	issue := func(set managed.AgentConfigurationSet, inherit ...string) managed.AgentConfiguration {
		reply := client.preview(t, agentConfigurationRequest{AgentIDs: []string{"a"}, Set: set, Inherit: inherit}, 200)
		client.apply(t, reply.Token, true, 200)
		return readAssignedConfiguration(t, f, a, cert, now)
	}
	issue(managed.AgentConfigurationSet{Monitoring: &managed.AgentConfigurationMonitoring{SampleIntervalSeconds: 40}})
	now = now.Add(time.Second)
	report.Result, report.RequestedRevision, report.AppliedRevision = "applied", 1, 1
	appliedAt := now
	report.AppliedAt = &appliedAt
	report.Effective.SampleIntervalSeconds = 40
	configHeartbeat(t, f, a, cert, report, now)
	second := issue(managed.AgentConfigurationSet{LocalPanel: &managed.AgentConfigurationLocalPanel{Access: "block"}})
	if second.Set.Monitoring == nil || second.Set.Monitoring.SampleIntervalSeconds != 40 || second.BaseRevision != 1 {
		t.Fatalf("second revision lost prior overlay: %#v", second)
	}
	now = now.Add(time.Second)
	report.Result, report.RequestedRevision, report.Error = "rejected", 2, "local_persistence_failed"
	configHeartbeat(t, f, a, cert, report, now)
	var state agentConfigurationState
	client.call(t, "GET", "/api/agent-configuration/a", nil, &state, 200)
	if state.AssignmentState != "rejected" || state.Report.AppliedRevision != 1 {
		t.Fatalf("failed issue hid the previous state: %#v", state)
	}
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, cert, ""), http.StatusNoContent, nil)
	now = now.Add(time.Second)
	report.Result, report.RequestedRevision, report.Error = "applied", 1, ""
	configHeartbeat(t, f, a, cert, report, now)
	client.call(t, "GET", "/api/agent-configuration/a", nil, &state, 200)
	if state.AssignmentState != "rejected" || state.Report.RequestedRevision != 1 {
		t.Fatalf("restarted agent erased the terminal rejection: %#v", state)
	}
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, cert, ""), http.StatusNoContent, nil)
	third := issue(managed.AgentConfigurationSet{Retention: &managed.AgentConfigurationRetention{ObservationHistoryMinutes: 120}}, managed.AgentConfigSamplingKey)
	if third.Revision != 3 || third.BaseRevision != 1 || third.Set.LocalPanel != nil || third.Set.Monitoring != nil ||
		!slices.Equal(third.Inherit, []string{managed.AgentConfigSamplingKey}) {
		t.Fatalf("third revision inherited a rejected field: %#v", third)
	}
}

func TestAgentConfigurationPreviewRejectsEnrollmentAndRetentionDrift(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	a, certA, _ := f.enroll(t, "a")
	b, certB, _ := f.enroll(t, "b")
	report := baseConfigurationReport(60)
	configHeartbeat(t, f, a, certA, report, now)
	configHeartbeat(t, f, b, certB, report, now)
	client := testAgentConfigurationConsole(updateConsoleClient(t, f))
	req := agentConfigurationRequest{AgentIDs: []string{"a", "b"}, Set: managed.AgentConfigurationSet{
		Retention: &managed.AgentConfigurationRetention{ObservationHistoryMinutes: 120},
	}}
	reply := client.preview(t, req, 200)
	report.Effective.ObservationHistoryMinutes = 180
	configHeartbeat(t, f, b, certB, report, now)
	client.apply(t, reply.Token, true, 409)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, certA, ""), http.StatusNoContent, nil)

	reply = client.preview(t, req, 200)
	if err := f.store.Revoke(context.Background(), b.AgentID, now); err != nil {
		t.Fatal(err)
	}
	b, replaced, _ := f.enroll(t, b.AgentID)
	configHeartbeat(t, f, b, replaced, report, now)
	client.apply(t, reply.Token, true, 409)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, replaced, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, certA, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, certB, ""), http.StatusUnauthorized, nil)

	reply = client.preview(t, req, 200)
	now = now.Add(previewLifetime)
	client.apply(t, reply.Token, true, 409)
}

func TestAgentConfigurationExpiredPendingAllowsNewRevision(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	a, cert, _ := f.enroll(t, "a")
	report := baseConfigurationReport(60)
	configHeartbeat(t, f, a, cert, report, now)
	client := testAgentConfigurationConsole(updateConsoleClient(t, f))
	first := agentConfigurationRequest{AgentIDs: []string{"a"}, Set: managed.AgentConfigurationSet{
		LocalPanel: &managed.AgentConfigurationLocalPanel{Access: "block"},
	}}
	reply := client.preview(t, first, 200)
	client.apply(t, reply.Token, false, 200)
	now = now.Add(agentConfigurationLifetime)
	configHeartbeat(t, f, a, cert, report, now)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, cert, ""), http.StatusNoContent, nil)
	second := agentConfigurationRequest{AgentIDs: []string{"a"}, Set: managed.AgentConfigurationSet{
		Monitoring: &managed.AgentConfigurationMonitoring{SampleIntervalSeconds: 20},
	}}
	reply = client.preview(t, second, 200)
	client.apply(t, reply.Token, false, 200)
	cfg := readAssignedConfiguration(t, f, a, cert, now)
	if cfg.BaseRevision != 0 || cfg.Revision != 2 || cfg.Set.LocalPanel != nil {
		t.Fatalf("expired overlay leaked into new assignment: %#v", cfg)
	}
}

func TestAgentConfigurationIgnoresMalformedAndStaleRejectionReports(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	a, cert, _ := f.enroll(t, "a")
	report := baseConfigurationReport(60)
	configHeartbeat(t, f, a, cert, report, now)
	client := testAgentConfigurationConsole(updateConsoleClient(t, f))
	reply := client.preview(t, agentConfigurationRequest{AgentIDs: []string{"a"}, Set: managed.AgentConfigurationSet{
		LocalPanel: &managed.AgentConfigurationLocalPanel{Access: "block"},
	}}, 200)
	client.apply(t, reply.Token, true, 200)

	hb := managed.Heartbeat{AgentID: a.AgentID, EnrollmentID: a.EnrollmentID, SentAt: now,
		Status: model.AgentStatus{CapabilityReport: &model.CapabilityReport{Capabilities: map[string]model.Capability{
			managed.AgentConfigurationCapability: {Details: map[string]string{"contract": managed.AgentConfigurationContract, "snapshot": "{"}},
		}}}}
	consoleWant(t, f.request(t, "POST", "/v1/heartbeat", hb, cert, ""), 200, nil)
	readAssignedConfiguration(t, f, a, cert, now)

	report.Result, report.Error, report.RequestedRevision = "rejected", "local_persistence_failed", 2
	configHeartbeat(t, f, a, cert, report, now)
	readAssignedConfiguration(t, f, a, cert, now)

	report.RequestedRevision = 1
	configHeartbeat(t, f, a, cert, report, now.Add(-3*time.Minute))
	readAssignedConfiguration(t, f, a, cert, now)
	configHeartbeat(t, f, a, cert, report, now)
	consoleWant(t, f.request(t, "GET", "/v1/agent-configuration", nil, cert, ""), http.StatusNoContent, nil)
}

func TestAgentConfigurationRejectsAmbiguousOperatorJSON(t *testing.T) {
	f := setup(t)
	client := testAgentConfigurationConsole(updateConsoleClient(t, f))
	for _, raw := range []string{
		`{"agent_ids":["a"],"set":{"local_panel":{"access":"block"}},"inherit":null}`,
		`{"agent_ids":["a"],"agent_ids":["b"],"set":{"local_panel":{"access":"block"}}}`,
		`{"Agent_IDs":["a"],"set":{"local_panel":{"access":"block"}}}`,
	} {
		consoleWant(t, client("POST", "/api/agent-configuration/preview", []byte(raw), "application/json"), 400, nil)
	}
	for _, raw := range []string{
		`{"preview_token":"token","confirm":false,"confirm":true}`,
		`{"preview_token":"token","confirm":true,"approve_retention_reduction":null}`,
		`{"preview_token":"token","confirm":true,"Approve_Retention_Reduction":true}`,
	} {
		consoleWant(t, client("POST", "/api/agent-configuration/apply", []byte(raw), "application/json"), 400, nil)
	}
}
