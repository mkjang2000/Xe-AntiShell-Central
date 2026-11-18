package central

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func TestPolicyTrialComparesAndRepublishesExactBaseline(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	agents := []string{"agent-a", "agent-b"}
	enroll := map[string]string{}
	old := map[string]managed.Policy{}
	heartbeat := func(id string, active, desired uint64, state string) {
		t.Helper()
		h := managed.Heartbeat{AgentID: id, EnrollmentID: enroll[id], SentAt: now, Status: model.AgentStatus{Health: "healthy"}, PolicyStatus: managed.PolicyStatus{ActiveRevision: active, DesiredRevision: desired, Result: state, AppliedAt: &now}}
		if err := f.store.Heartbeat(ctx, id, h, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range agents {
		e, _, _ := f.enroll(t, id)
		enroll[id] = e.EnrollmentID
		p := managed.DefaultPolicy(id, e.EnrollmentID, 1, now)
		p.ID = "baseline"
		p.Detection.WebServices = []string{id + ".service"}
		old[id] = p
		signed, err := managed.SignPolicy(p, f.material.PolicyKeyID, f.material.PolicyKey)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.store.AssignPolicy(ctx, signed, now); err != nil {
			t.Fatal(err)
		}
		heartbeat(id, 1, 1, "applied")
	}
	f.consoleDrafts(t, agents)
	client := updateConsoleClient(t, f)
	call := func(method, path string, req any, code int, out any) {
		t.Helper()
		var body []byte
		if req != nil {
			body, _ = json.Marshal(req)
		}
		w := client(method, path, body, "application/json")
		consoleWant(t, w, code, out)
	}
	var trial policyTrial
	call("POST", "/api/policy-trials", map[string]any{"preview_token": f.preview(t), "canary": agents[0]}, 200, &trial)
	base := "/api/policy-trials/" + trial.ID
	report := func(agent, hash string, expected int) {
		t.Helper()
		var in managed.PolicyImpactInput
		call("GET", base+"?view=input&agent_id="+url.QueryEscape(agent), nil, 200, &in)
		digest, err := in.Digest()
		if err != nil {
			t.Fatal(err)
		}
		r := managed.PolicyImpactReport{InputDigest: digest, SampleDigest: strings.Repeat(hash, 64), HostDigest: strings.Repeat("c", 64), EvaluatedAt: in.EvaluatedAt, Events: 2}
		for _, id := range managed.BuiltinRuleIDs() {
			r.Rules = append(r.Rules, managed.PolicyRuleImpact{ID: id})
		}
		if binary := os.Getenv("XEAS_POLICY_COMPARE_TEST_BINARY"); binary != "" {
			sample := os.Getenv("XEAS_POLICY_COMPARE_TEST_SAMPLE")
			if sample == "" {
				t.Fatal("provide a normalized local sample")
			}
			dir := t.TempDir()
			inputFile := filepath.Join(dir, "input.json")
			hostFile := filepath.Join(dir, "host.yaml")
			b, _ := json.Marshal(in)
			if err := os.WriteFile(inputFile, b, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hostFile, []byte("version: 1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "rules", "compare", "--managed-input", inputFile, "--host-config", hostFile, "--events", sample)
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("local compare: %v %s", err, raw)
			}
			if err = json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			if hash == "b" {
				r.SampleDigest = strings.Repeat(hash, 64)
			}
		}
		call("POST", base+"/report", map[string]any{"agent_id": agent, "report": r}, expected, nil)
	}
	step := func(action, phase string, expected int) trialAction {
		t.Helper()
		req := trialAction{Action: action, Phase: phase}
		var plan trialActionPlan
		call("POST", base+"/preview", req, expected, &plan)
		req.Token = plan.Token
		req.Note = "확인한 부하와 경보 표본"
		return req
	}
	report(agents[0], "a", 200)
	report(agents[1], "b", 409)
	r := step("canary", "prepared", 200)
	call("POST", base+"/apply", r, 200, nil)
	call("POST", base+"/apply", r, 200, nil)
	step("promote", "canary", 409)
	heartbeat(agents[0], 1, 2, "rejected")
	step("promote", "canary", 409)
	heartbeat(agents[0], 2, 2, "applied")
	step("promote", "canary", 400)
	report(agents[1], "a", 200)
	oldTicket := step("promote", "canary", 200)
	now = now.Add(previewLifetime)
	call("POST", base+"/apply", oldTicket, 409, nil)
	for i, id := range agents {
		rev := uint64(1)
		if i == 0 {
			rev = 2
		}
		heartbeat(id, rev, rev, "applied")
	}
	promote := step("promote", "canary", 200)
	call("POST", base+"/apply", promote, 200, nil)
	var state struct {
		Targets []trialStatus `json:"targets"`
	}
	call("GET", base, nil, 200, &state)
	if state.Targets[0].State != "applied" || state.Targets[1].State != "pending" {
		t.Fatalf("status %+v", state.Targets)
	}
	heartbeat(agents[1], 2, 2, "applied")
	restore := step("restore", "expanded", 200)
	call("POST", base+"/apply", restore, 200, nil)
	for _, id := range agents {
		p, err := f.store.LatestPolicy(ctx, id, enroll[id])
		if err != nil {
			t.Fatal(err)
		}
		baseline := old[id]
		if p.Policy.Revision != 3 || p.Policy.ID != baseline.ID || !reflect.DeepEqual(p.Policy.Detection, baseline.Detection) || p.Policy.ExpiresAt.Sub(p.Policy.IssuedAt) != baseline.ExpiresAt.Sub(baseline.IssuedAt) {
			t.Fatalf("rollback %+v", p.Policy)
		}
		heartbeat(id, 3, 3, "applied")
	}
	call("GET", base, nil, 200, &state)
	for _, v := range state.Targets {
		if v.State != "applied" || v.Active != 3 {
			t.Fatalf("resolved state %+v", v)
		}
	}
}
