package central

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

type assignmentState struct {
	Agents []struct {
		ID       string `json:"agent_id"`
		PolicyID string `json:"desired_policy_id"`
		State    string `json:"policy_template_state"`
	} `json:"agents"`
}

func (f *fixture) assignments(t *testing.T) map[string][2]string {
	t.Helper()
	var state assignmentState
	consoleWant(t, f.console(t, "GET", "/api/state", nil), 200, &state)
	out := make(map[string][2]string)
	for _, agent := range state.Agents {
		out[agent.ID] = [2]string{agent.PolicyID, agent.State}
	}
	return out
}

type previewCurrent struct {
	Current []consoleCurrentPolicy `json:"current_policies"`
}

func (f *fixture) previewCurrent(t *testing.T) []consoleCurrentPolicy {
	t.Helper()
	var response previewCurrent
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "default", GroupIDs: []string{"web"}}), 200, &response)
	return response.Current
}

func TestConsoleStateNamesTemplateBehindDesiredRevision(t *testing.T) {
	f := setup(t)
	f.enroll(t, "agent-a")
	f.enroll(t, "agent-b")
	f.consoleDrafts(t, []string{"agent-a"})
	if got := f.assignments(t); got["agent-a"] != [2]string{} || got["agent-b"] != [2]string{} {
		t.Fatalf("assignment before deployment=%v", got)
	}
	consoleWant(t, f.deploy(t, f.preview(t)), 200, nil)
	if got := f.assignments(t); got["agent-a"] != [2]string{"default", "current"} || got["agent-b"] != [2]string{} {
		t.Fatalf("assignment after deployment=%v", got)
	}
	// Saving a template does not redeploy it, so the deployed host becomes outdated.
	settings := defaultConsoleSettings(time.Now())
	settings.Monitoring.SampleIntervalSeconds = 30
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "운영 정책", Version: 1, Settings: settings}), 200, nil)
	if got := f.assignments(t)["agent-a"]; got != [2]string{"default", "changed"} {
		t.Fatalf("assignment after template edit=%v", got)
	}
	consoleWant(t, f.console(t, "DELETE", "/api/templates/default?version=2", nil), 200, nil)
	if got := f.assignments(t)["agent-a"]; got != [2]string{"default", "missing"} {
		t.Fatalf("assignment after template deletion=%v", got)
	}
}

func TestConsolePreviewGroupsTargetsByCurrentPolicy(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	f.enroll(t, "agent-a")
	f.enroll(t, "agent-b")
	direct, _, _ := f.enroll(t, "agent-c")
	f.consoleDrafts(t, []string{"agent-a", "agent-b"})
	current := f.previewCurrent(t)
	if len(current) != 1 || current[0].Kind != "none" || len(current[0].AgentIDs) != 2 || current[0].Settings != nil {
		t.Fatalf("current before deployment=%+v", current)
	}
	consoleWant(t, f.deploy(t, f.preview(t)), 200, nil)
	policy := managed.DefaultPolicy("agent-c", direct.EnrollmentID, 1, now)
	policy.ID = "operator-direct"
	signed, err := managed.SignPolicy(policy, f.material.PolicyKeyID, f.material.PolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.AssignPolicy(ctx, signed, now); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "웹 서버", Version: 1, AgentIDs: []string{"agent-a", "agent-b", "agent-c"}}), 200, nil)
	current = f.previewCurrent(t)
	if len(current) != 2 {
		t.Fatalf("current groups=%+v", current)
	}
	deployed, other := current[0], current[1]
	if deployed.Kind != "console" || deployed.PolicyID != "default" || deployed.Settings == nil || len(deployed.AgentIDs) != 2 ||
		deployed.Settings.Monitoring.SampleIntervalSeconds != defaultConsoleSettings(now).Monitoring.SampleIntervalSeconds {
		t.Fatalf("console group=%+v", deployed)
	}
	if other.Kind != "direct" || other.PolicyID != "operator-direct" || other.Settings != nil || len(other.AgentIDs) != 1 || other.AgentIDs[0] != "agent-c" {
		t.Fatalf("direct group=%+v", other)
	}
}

func TestConsoleRejectedSettingsNameTheProtocolReason(t *testing.T) {
	f := setup(t)
	settings := defaultConsoleSettings(time.Now())
	settings.Response.Mode = "enforce"
	response := f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "bad", Name: "잘못된 대응", Settings: settings})
	consoleWant(t, response, 400, nil)
	if body := response.Body.String(); !strings.Contains(body, "모니터링 설정을 확인하세요 (") {
		t.Fatalf("validation reason missing: %s", body)
	}
}

func TestConsoleStateReportsDesiredResponseModes(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.enroll(t, "agent-a")
	f.enroll(t, "agent-b")
	direct, _, _ := f.enroll(t, "agent-c")
	f.consoleDrafts(t, []string{"agent-a"})
	consoleWant(t, f.deploy(t, f.preview(t)), 200, nil)
	policy := managed.DefaultPolicy("agent-c", direct.EnrollmentID, 1, now)
	policy.ID = "operator-direct"
	edge := managed.ApplicationPolicy{Service: "edge.service", PolicyID: "edge", PolicyVersion: 1, Detection: policy.Detection, Response: policy.Response}
	edge.Detection.WebServices, edge.Detection.WebExecutables = []string{"edge.service"}, nil
	edge.Detection.PrivilegeRules, edge.Detection.RootExecAlerts = false, ""
	edge.Response.Mode = "would_block"
	edge.Response.Action = "terminate"
	edge.Response.RequiredCapabilities = []string{"observation.process_exec"}
	policy.Applications = []managed.ApplicationPolicy{edge}
	// Service policies need the host's application policy support report.
	h := privilegeHeartbeat("agent-c", direct.EnrollmentID, now)
	h.Status.CapabilityReport.Capabilities[managed.ApplicationPoliciesCapability] = model.Capability{Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}
	if err := f.store.Heartbeat(context.Background(), "agent-c", h, now); err != nil {
		t.Fatal(err)
	}
	signed, err := managed.SignPolicy(policy, f.material.PolicyKeyID, f.material.PolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.AssignPolicy(context.Background(), signed, now); err != nil {
		t.Fatal(err)
	}
	var state struct {
		Agents []struct {
			ID       string   `json:"agent_id"`
			Template string   `json:"desired_policy_id"`
			Mode     *string  `json:"desired_response_mode"`
			Services []string `json:"desired_service_response_modes"`
		} `json:"agents"`
	}
	consoleWant(t, f.console(t, "GET", "/api/state", nil), 200, &state)
	got := make(map[string]string)
	for _, agent := range state.Agents {
		mode := "<none>"
		if agent.Mode != nil {
			mode = *agent.Mode
		}
		got[agent.ID] = agent.Template + "|" + mode + "|" + strings.Join(agent.Services, ",")
	}
	// The direct policy keeps no console template but still reports its modes.
	want := map[string]string{"agent-a": "default|observe|", "agent-b": "|<none>|", "agent-c": "|observe|would_block"}
	for id, value := range want {
		if got[id] != value {
			t.Fatalf("state modes=%v want=%v", got, want)
		}
	}
}

func TestDesiredResponseListsDistinctServiceModesWeakestFirst(t *testing.T) {
	if response := desiredResponse("observe", nil); response.Mode != "observe" || response.ServiceModes != nil {
		t.Fatalf("modes without bindings=%+v", response)
	}
	if response := desiredResponse("observe", []string{"enforce", "observe", "", "would_block", "enforce"}); strings.Join(response.ServiceModes, ",") != "would_block,enforce" {
		t.Fatalf("modes with bindings=%+v", response)
	}
	if response := desiredResponse("enforce", []string{"enforce", "would_block", "observe"}); strings.Join(response.ServiceModes, ",") != "observe,would_block" {
		t.Fatalf("services weaker than default=%+v", response)
	}
}
