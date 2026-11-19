package central

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func TestApplicationBindingPinsSourceAndScopesItsSettings(t *testing.T) {
	f := setup(t)
	settings := defaultConsoleSettings(time.Now())
	source := ConsoleTemplate{ID: "edge", Name: "Edge", Settings: settings}
	unit := "nginx.service"
	source.Settings.Detection.PrivilegeRules = true
	source.Settings.Detection.RootExecAlerts = "all"
	source.Settings.Detection.AllowedPairs = []string{"NGINX.SERVICE:sh", "other.service:sh"}
	source.Settings.Detection.ServiceRuleControls = []managed.ServiceRuleControl{
		{Service: unit, RuleID: managed.RuleWebDescendantShell, Mode: "disabled"},
		{Service: "other.service", RuleID: managed.RuleWebDescendantShell, Mode: "disabled"},
	}
	scopes := []managed.ServiceObservationPolicy{{Service: unit, ProtectedDirs: []string{"/srv/web"}}, {Service: "other.service", ProtectedDirs: []string{"/srv/other"}}}
	source.Settings.Detection.ServiceObservations = &scopes
	consoleWant(t, f.console(t, "POST", "/api/templates", source), 200, &source)
	host := ConsoleTemplate{ID: "site", Name: "Site", Settings: settings}
	ref := ApplicationBinding{unit, source.ID, uint64(source.Version)}
	host.Settings.ApplicationBindings = []ApplicationBinding{ref}
	consoleWant(t, f.console(t, "POST", "/api/templates", host), 200, &host)
	pin := host.Settings.Applications[0]
	d := pin.Detection
	if !reflect.DeepEqual(d.WebServices, []string{unit}) || len(d.WebExecutables) != 0 || d.PrivilegeRules || d.RootExecAlerts != "" || !reflect.DeepEqual(d.AllowedPairs, []string{"NGINX.SERVICE:sh"}) || len(d.ServiceRuleControls) != 1 || d.ServiceRuleControls[0].Service != unit || d.ServiceObservations == nil || len(*d.ServiceObservations) != 1 || (*d.ServiceObservations)[0].Service != unit {
		t.Fatalf("incorrect service snapshot %+v", pin)
	}
	consoleWant(t, f.console(t, "DELETE", "/api/templates/edge?version=1", nil), 200, nil)
	source.Version = 0
	source.Settings.Detection.Shells = []string{"ksh"}
	consoleWant(t, f.console(t, "POST", "/api/templates", source), 200, &source)
	if source.Version <= int64(ref.PolicyVersion) {
		t.Fatal("recreated template reused deleted generation's version")
	}
	host.Settings.Applications[0].PolicyID = "injected"
	consoleWant(t, f.console(t, "POST", "/api/templates", host), 200, &host)
	if !reflect.DeepEqual(host.Settings.Applications[0], pin) {
		t.Fatal("editing unchanged binding rewrote or trusted supplied snapshot")
	}
	host.Settings.ApplicationBindings = nil
	host.Settings.Applications = nil
	host.Description = "Legacy editor update"
	consoleWant(t, f.console(t, "POST", "/api/templates", host), 200, &host)
	if len(host.Settings.Applications) != 1 || !reflect.DeepEqual(host.Settings.Applications[0], pin) {
		t.Fatal("legacy editor discarded application snapshot")
	}
	fresh := ConsoleTemplate{ID: "fresh", Name: "Fresh", Settings: settings}
	fresh.Settings.ApplicationBindings = []ApplicationBinding{ref}
	consoleWant(t, f.console(t, "POST", "/api/templates", fresh), 409, nil)
	fresh.Settings.ApplicationBindings[0].PolicyVersion = uint64(source.Version)
	consoleWant(t, f.console(t, "POST", "/api/templates", fresh), 200, &fresh)
	if got := fresh.Settings.Applications[0].Detection.Shells; !reflect.DeepEqual(got, []string{"ksh"}) {
		t.Fatalf("changed source not materialized: %v", got)
	}
	fresh.Settings.ApplicationBindings = []ApplicationBinding{{unit, host.ID, uint64(host.Version)}}
	consoleWant(t, f.console(t, "POST", "/api/templates", fresh), 400, nil)
	fresh.Settings.ApplicationBindings = []ApplicationBinding{ref, ref}
	fresh.Settings.ApplicationBindings[0].PolicyVersion = uint64(source.Version)
	consoleWant(t, f.console(t, "POST", "/api/templates", fresh), 400, nil)
}

func TestApplicationBindingRejectsLossOfExecutableException(t *testing.T) {
	f := setup(t)
	settings := defaultConsoleSettings(time.Now())
	source := ConsoleTemplate{ID: "runtime", Name: "Runtime", Settings: settings}
	source.Settings.Detection.AllowedPairs = []string{"NGINX:Bash"}
	consoleWant(t, f.console(t, "POST", "/api/templates", source), 200, &source)
	base := ConsoleTemplate{ID: "site", Name: "Site", Settings: settings}
	base.Settings.ApplicationBindings = []ApplicationBinding{{"nginx.service", source.ID, uint64(source.Version)}}
	rejected := f.console(t, "POST", "/api/templates", base)
	if rejected.Code != 400 || !strings.Contains(rejected.Body.String(), "nginx.service:Bash") {
		t.Fatalf("silently discarded exemption: %d %s", rejected.Code, rejected.Body.String())
	}
	source.Settings.Detection.AllowedPairs = append(source.Settings.Detection.AllowedPairs, "nginx.service:bash")
	consoleWant(t, f.console(t, "POST", "/api/templates", source), 200, &source)
	base.Settings.ApplicationBindings[0].PolicyVersion = uint64(source.Version)
	consoleWant(t, f.console(t, "POST", "/api/templates", base), 200, &base)
	if got := base.Settings.Applications[0].Detection.AllowedPairs; !reflect.DeepEqual(got, []string{"nginx.service:bash"}) {
		t.Fatalf("expected service-specific exemption: %v", got)
	}
}

func TestApplicationDeploymentAndConfirmedPolicyReadback(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a, _, _ := f.enroll(t, "agent-a")
	now := f.server.now().UTC()
	f.consoleDrafts(t, []string{a.AgentID})
	settings := defaultConsoleSettings(now)
	source := ConsoleTemplate{ID: "runtime", Name: "Runtime", Settings: settings}
	consoleWant(t, f.console(t, "POST", "/api/templates", source), 200, &source)
	base := ConsoleTemplate{ID: "default", Name: "Host", Version: 1, Settings: settings}
	base.Settings.ApplicationBindings = []ApplicationBinding{{"nginx.service", source.ID, uint64(source.Version)}}
	consoleWant(t, f.console(t, "POST", "/api/templates", base), 200, &base)
	preview := consolePreviewRequest{TemplateID: base.ID, AgentIDs: []string{a.AgentID}}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", preview), 400, nil)
	p := base.Settings.wirePolicy(base.ID, a.AgentID, a.EnrollmentID, 1, now)
	consoleWant(t, f.request(t, "POST", "/admin/policy", p, nil, f.operator(t)), 400, nil)
	h := privilegeHeartbeat(a.AgentID, a.EnrollmentID, now)
	caps := h.Status.CapabilityReport.Capabilities
	put := func() {
		t.Helper()
		if err := f.store.Heartbeat(ctx, a.AgentID, h, now); err != nil {
			t.Fatal(err)
		}
	}
	cap := model.Capability{Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}
	caps[managed.ApplicationPoliciesCapability] = cap
	put()
	token := f.preview(t)
	trialBody, err := json.Marshal(map[string]any{"preview_token": token, "canary": a.AgentID})
	if err != nil {
		t.Fatal(err)
	}
	client := updateConsoleClient(t, f)
	trial := client("POST", "/api/policy-trials", trialBody, "application/json")
	if trial.Code != 400 || !strings.Contains(trial.Body.String(), "표본 비교기") {
		t.Fatalf("unsupported application comparison was offered: %d %s", trial.Code, trial.Body.String())
	}
	delete(caps, managed.ApplicationPoliciesCapability)
	put()
	consoleWant(t, f.deploy(t, token), 409, nil)
	caps[managed.ApplicationPoliciesCapability] = cap
	put()
	consoleWant(t, f.deploy(t, f.preview(t)), 200, nil)
	signed, err := f.store.LatestPolicy(ctx, a.AgentID, a.EnrollmentID)
	if err != nil || len(signed.Policy.Applications) != 1 {
		t.Fatalf("signed application missing: %v", err)
	}
	digest, err := integrity.PolicyDigest(signed)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want string, applied uint64) {
		t.Helper()
		var body struct {
			Applied *managed.Policy   `json:"applied_policy"`
			Status  applicationStatus `json:"application_status"`
		}
		consoleWant(t, f.console(t, "GET", "/api/agents/agent-a/policy", nil), 200, &body)
		if want != body.Status.State || (applied == 0) != (body.Applied == nil) || body.Applied != nil && body.Applied.Revision != applied {
			t.Fatalf("status=%+v applied=%+v, want %s/%d", body.Status, body.Applied, want, applied)
		}
	}
	h.PolicyStatus = managed.PolicyStatus{ActiveRevision: 1, DesiredRevision: 1, Result: "applied", AppliedAt: &now}
	put()
	check("unverified", 0)
	h.PolicyStatus.PolicySHA256 = strings.Repeat("e", 64)
	put()
	check("mismatch", 0)
	h.PolicyStatus.PolicySHA256 = digest
	put()
	check("applied", 1)
	f.enroll(t, "aaa")
	var page templateUsagePage
	consoleWant(t, f.console(t, "GET", "/api/templates/runtime/usage?limit=1", nil), 200, &page)
	if len(page.Items) != 0 || page.NextAfter != "aaa" {
		t.Fatalf("incorrect sparse usage page: %+v", page)
	}
	page = templateUsagePage{}
	consoleWant(t, f.console(t, "GET", "/api/templates/runtime/usage?limit=1&after=aaa", nil), 200, &page)
	if page.NextAfter != "" {
		t.Fatalf("unexpected next page: %q", page.NextAfter)
	}
	if len(page.Items) != 1 || page.Items[0].HostPolicy || page.Items[0].Status.State != "applied" || len(page.Items[0].Bindings) != 1 || page.Items[0].Bindings[0].Service != "nginx.service" {
		t.Fatalf("application usage %+v", page)
	}
	consoleWant(t, f.console(t, "GET", "/api/templates/default/usage", nil), 200, &page)
	if len(page.Items) != 1 || !page.Items[0].HostPolicy {
		t.Fatalf("host usage %+v", page)
	}
	consoleWant(t, f.console(t, "GET", "/api/templates/default/usage?limit=101", nil), 400, nil)
	// An app policy cannot be the baseline of a sample-only policy trial either.
	base.Settings.ApplicationBindings = nil
	base.Settings.Applications = nil
	asJSON, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var edit map[string]any
	if err = json.Unmarshal(asJSON, &edit); err != nil {
		t.Fatal(err)
	}
	edit["settings"].(map[string]any)["application_bindings"] = []ApplicationBinding{}
	consoleWant(t, f.console(t, "POST", "/api/templates", edit), 200, &base)
	h.Status.Health = model.HealthHealthy
	put()
	trialBody, err = json.Marshal(map[string]any{"preview_token": f.preview(t), "canary": a.AgentID})
	if err != nil {
		t.Fatal(err)
	}
	trial = client("POST", "/api/policy-trials", trialBody, "application/json")
	if trial.Code != 400 || !strings.Contains(trial.Body.String(), "표본 비교기") {
		t.Fatalf("unsupported baseline reached trial: %d %s", trial.Code, trial.Body.String())
	}
	h.SentAt = now.Add(-3 * time.Minute)
	put()
	check("stale", 0)
	h.SentAt = now
	plain := managed.DefaultPolicy(a.AgentID, a.EnrollmentID, 2, now)
	consoleWant(t, f.request(t, "POST", "/admin/policy", plain, nil, f.operator(t)), 201, nil)
	h.PolicyStatus.DesiredRevision = 2
	h.PolicyStatus.Result = "rejected"
	put()
	check("previous", 1)
	h.PolicyStatus = managed.PolicyStatus{ActiveRevision: 2, DesiredRevision: 2, Result: "applied", AppliedAt: &now}
	put()
	check("legacy_applied", 2)
	consoleWant(t, f.console(t, "GET", "/api/templates/default/usage", nil), 200, &page)
	if len(page.Items) != 0 {
		t.Fatalf("attributed direct admin policy to an identically named template: %+v", page)
	}
}
