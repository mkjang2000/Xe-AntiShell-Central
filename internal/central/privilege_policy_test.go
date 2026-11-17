package central

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func privilegeHeartbeat(agent, enrollment string, now time.Time) managed.Heartbeat {
	return managed.Heartbeat{AgentID: agent, EnrollmentID: enrollment, SentAt: now, Status: model.AgentStatus{Collector: "tetragon-json", CapabilityReport: &model.CapabilityReport{Capabilities: map[string]model.Capability{"detection.privilege_rules": {Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}}}}}
}

func TestPrivilegePolicyRequiresCurrentCompatibleEngineNotSensorReceipt(t *testing.T) {
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	detection := managed.DetectionPolicy{PrivilegeRules: true}
	cases := []struct {
		name    string
		mutate  func(*managed.Heartbeat)
		allowed bool
	}{
		{"available-engine-without-credential-receipt", func(*managed.Heartbeat) {}, true},
		{"active-engine", func(h *managed.Heartbeat) {
			v := h.Status.CapabilityReport.Capabilities["detection.privilege_rules"]
			v.RuntimeState = "active"
			h.Status.CapabilityReport.Capabilities["detection.privilege_rules"] = v
		}, true},
		{"old-agent", func(h *managed.Heartbeat) {
			delete(h.Status.CapabilityReport.Capabilities, "detection.privilege_rules")
		}, false},
		{"missing-report", func(h *managed.Heartbeat) { h.Status.CapabilityReport = nil }, false},
		{"other-enrollment", func(h *managed.Heartbeat) { h.EnrollmentID = "old-enrollment" }, false},
		{"other-agent", func(h *managed.Heartbeat) { h.AgentID = "other-agent" }, false},
		{"stale", func(h *managed.Heartbeat) { h.SentAt = now.Add(-2*time.Minute - time.Nanosecond) }, false},
		{"future", func(h *managed.Heartbeat) { h.SentAt = now.Add(time.Minute + time.Nanosecond) }, false},
		{"missing-time", func(h *managed.Heartbeat) { h.SentAt = time.Time{} }, false},
		{"audit-selected", func(h *managed.Heartbeat) { h.Status.Collector = "audit-dispatcher" }, false},
	}
	for _, change := range []struct{ name, implementation, runtime, contract string }{
		{"planned", "planned", "available", "1"}, {"inactive", "implemented", "inactive", "1"}, {"failed", "implemented", "error", "1"}, {"missing-contract", "implemented", "available", ""}, {"different-contract", "implemented", "available", "2"},
	} {
		x := change
		cases = append(cases, struct {
			name    string
			mutate  func(*managed.Heartbeat)
			allowed bool
		}{x.name, func(h *managed.Heartbeat) {
			h.Status.CapabilityReport.Capabilities["detection.privilege_rules"] = model.Capability{Implementation: x.implementation, RuntimeState: x.runtime, Details: map[string]string{"contract": x.contract}}
		}, false})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h := privilegeHeartbeat("agent-a", "current-enrollment", now)
			test.mutate(&h)
			body, _ := json.Marshal(h)
			err := requirePrivilegePolicySupport(detection, body, "agent-a", "current-enrollment", now)
			if (err == nil) != test.allowed {
				t.Fatalf("allowed=%v err=%v", test.allowed, err)
			}
			if !test.allowed && !errors.Is(err, ErrInvalid) {
				t.Fatal("missing invalid-policy classification")
			}
		})
	}
	if err := requirePrivilegePolicySupport(managed.DetectionPolicy{}, nil, "old", "old", now); err != nil {
		t.Fatal("legacy policy now requires support report", err)
	}
}

func TestPrivilegeConsolePreviewAndConfirmRecheckSupport(t *testing.T) {
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	f.consoleDrafts(t, []string{"agent-a"})
	settings := defaultConsoleSettings(time.Now())
	settings.Detection.PrivilegeRules = true
	settings.Detection.RootExecAlerts = "suspicious"
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "권한 탐지", Version: 1, Settings: settings}), 200, nil)
	request := consolePreviewRequest{TemplateID: "default", AgentIDs: []string{"agent-a"}}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", request), 400, nil)
	h := privilegeHeartbeat(enrolled.AgentID, enrolled.EnrollmentID, time.Now().UTC())
	if err := f.store.Heartbeat(context.Background(), enrolled.AgentID, h, time.Now()); err != nil {
		t.Fatal(err)
	}
	token := f.preview(t)
	h.Status.CapabilityReport = nil
	h.SentAt = time.Now().UTC()
	if err := f.store.Heartbeat(context.Background(), enrolled.AgentID, h, time.Now()); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.deploy(t, token), 409, nil)
	if _, err := f.store.LatestPolicy(context.Background(), enrolled.AgentID, enrolled.EnrollmentID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rejected deployment changed policy", err)
	}
	h = privilegeHeartbeat(enrolled.AgentID, enrolled.EnrollmentID, time.Now().UTC())
	if err := f.store.Heartbeat(context.Background(), enrolled.AgentID, h, time.Now()); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.deploy(t, f.preview(t)), 200, nil)
	signed, err := f.store.LatestPolicy(context.Background(), enrolled.AgentID, enrolled.EnrollmentID)
	if err != nil || !signed.Policy.Detection.PrivilegeRules || signed.Policy.Detection.RootExecAlerts != "suspicious" {
		t.Fatal("new settings not preserved", err)
	}
}

func TestAdminPolicyCannotBypassPrivilegeSupportAndLegacyBytesStayOmitted(t *testing.T) {
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	now := time.Now().UTC()
	policy := managed.DefaultPolicy(enrolled.AgentID, enrolled.EnrollmentID, 1, now)
	legacy, _ := json.Marshal(policy)
	if bytes.Contains(legacy, []byte("privilege_rules")) || bytes.Contains(legacy, []byte("root_exec_alerts")) {
		t.Fatal("new false fields changed legacy wire")
	}
	policy.Detection.PrivilegeRules = true
	policy.Detection.RootExecAlerts = "all"
	consoleWant(t, f.request(t, "POST", "/admin/policy", policy, nil, f.operator(t)), 400, nil)
	h := privilegeHeartbeat(enrolled.AgentID, enrolled.EnrollmentID, now)
	if err := f.store.Heartbeat(context.Background(), enrolled.AgentID, h, now); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.request(t, "POST", "/admin/policy", policy, nil, f.operator(t)), 201, nil)
	// Existing exact policy retry does not require another write or new support.
	signed, err := f.store.LatestPolicy(context.Background(), enrolled.AgentID, enrolled.EnrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.AssignPolicy(context.Background(), signed, now.Add(time.Hour)); err != nil {
		t.Fatal("idempotent exact retry changed", err)
	}
}
