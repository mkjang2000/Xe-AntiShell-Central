package central

import (
	"context"
	"errors"
	"testing"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func TestServiceScopeDeploymentRequiresSupportIncludingEmptyOverrides(t *testing.T) {
	f := setup(t)
	first, _, _ := f.enroll(t, "agent-a")
	second, _, _ := f.enroll(t, "agent-b")
	f.consoleDrafts(t, []string{first.AgentID, second.AgentID})
	now := time.Now().UTC()
	settings := defaultConsoleSettings(now)
	scopes := []managed.ServiceObservationPolicy{}
	settings.Detection.ServiceObservations = &scopes
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "서비스 규칙", Version: 1, Settings: settings}), 200, nil)
	h := privilegeHeartbeat(first.AgentID, first.EnrollmentID, now)
	h.Status.Collector = "audit-dispatcher"
	h.Status.CapabilityReport.Capabilities["detection.service_observations"] = model.Capability{Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}
	if err := f.store.Heartbeat(context.Background(), first.AgentID, h, now); err != nil {
		t.Fatal(err)
	}
	group := consolePreviewRequest{TemplateID: "default", AgentIDs: []string{first.AgentID, second.AgentID}}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", group), 400, nil)
	policy := managed.DefaultPolicy(second.AgentID, second.EnrollmentID, 1, now)
	policy.Detection.ServiceObservations = &scopes
	consoleWant(t, f.request(t, "POST", "/admin/policy", policy, nil, f.operator(t)), 400, nil)
	policy.Detection.ServiceObservations = nil
	consoleWant(t, f.request(t, "POST", "/admin/policy", policy, nil, f.operator(t)), 201, nil)
	single := consolePreviewRequest{TemplateID: "default", AgentIDs: []string{first.AgentID}}
	preview := func() string {
		var response struct {
			PreviewToken string `json:"preview_token"`
		}
		consoleWant(t, f.console(t, "POST", "/api/deploy/preview", single), 200, &response)
		return response.PreviewToken
	}
	token := preview()
	current := h.Status.CapabilityReport
	h.Status.CapabilityReport = nil
	h.SentAt = time.Now().UTC()
	if err := f.store.Heartbeat(context.Background(), first.AgentID, h, h.SentAt); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.deploy(t, token), 409, nil)
	if _, err := f.store.LatestPolicy(context.Background(), first.AgentID, first.EnrollmentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed deployment changed active policy: %v", err)
	}
	h.Status.CapabilityReport = current
	h.SentAt = time.Now().UTC()
	if err := f.store.Heartbeat(context.Background(), first.AgentID, h, h.SentAt); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.deploy(t, preview()), 200, nil)
	signed, err := f.store.LatestPolicy(context.Background(), first.AgentID, first.EnrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	got := signed.Policy.Detection.ServiceObservations
	if got == nil || len(*got) != 0 {
		t.Fatal("empty override lost in policy storage")
	}
}

func TestServiceRuleControlsUseIndependentContractAtPreviewAndDeploy(t *testing.T) {
	f := setup(t)
	a, cert, _ := f.enroll(t, "agent-a")
	f.consoleDrafts(t, []string{a.AgentID})
	now := time.Now().UTC()
	end := now.Add(time.Hour)
	settings := defaultConsoleSettings(now)
	settings.Integrity.PackageFiles = true
	settings.Detection.ServiceRuleControls = []managed.ServiceRuleControl{{Service: "web.service", RuleID: managed.RuleWebDescendantShell, Mode: "suppress_until", Reason: "maintenance", ExpiresAt: &end}}
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "Controls", Version: 1, Settings: settings}), 200, nil)
	h := privilegeHeartbeat(a.AgentID, a.EnrollmentID, now)
	caps := h.Status.CapabilityReport.Capabilities
	caps["detection.service_observations"] = model.Capability{Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}
	put := func() {
		t.Helper()
		h.SentAt = time.Now().UTC()
		if err := f.store.Heartbeat(context.Background(), a.AgentID, h, h.SentAt); err != nil {
			t.Fatal(err)
		}
	}
	put()
	target := consolePreviewRequest{TemplateID: "default", GroupIDs: []string{"web"}}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", target), 400, nil)
	direct := settings.wirePolicy("rule-controls", a.AgentID, a.EnrollmentID, 1, now)
	consoleWant(t, f.request(t, "POST", "/admin/policy", direct, nil, f.operator(t)), 400, nil)
	caps["detection.service_rule_controls"] = model.Capability{Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}
	put()
	preview := f.preview(t)
	delete(caps, "detection.service_rule_controls")
	put()
	consoleWant(t, f.deploy(t, preview), 409, nil)
	caps["detection.service_rule_controls"] = model.Capability{Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}
	put()
	consoleWant(t, f.deploy(t, f.preview(t)), 200, nil)
	saved, err := f.store.LatestPolicy(context.Background(), a.AgentID, a.EnrollmentID)
	if err != nil || len(saved.Policy.Detection.ServiceRuleControls) != 1 {
		t.Fatalf("missing saved controls: %v", err)
	}
	if got := saved.Policy.Detection.ServiceRuleControls[0]; got.RuleID != managed.RuleWebDescendantShell || got.Reason != "maintenance" || !got.ExpiresAt.Equal(end) {
		t.Fatalf("signed control mismatch %+v", got)
	}
	var assignment contract.Assignment
	consoleWant(t, f.request(t, "GET", "/v1/integrity/files", nil, cert, ""), 200, &assignment)
	digest, err := contract.PolicyDigest(saved)
	if err != nil || assignment.Revision != saved.Policy.Revision || assignment.PolicySHA256 != digest {
		t.Fatalf("file measurement failed to bind deployed rule controls: %+v %v", assignment, err)
	}
}
