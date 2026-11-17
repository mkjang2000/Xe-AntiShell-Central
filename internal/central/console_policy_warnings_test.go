package central

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func TestConsolePolicyWarningsMatchAgentRuntimeCapabilityGate(t *testing.T) {
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	settings := defaultConsoleSettings(now)
	settings.Response.Mode, settings.Response.Action = "would_block", "terminate"
	settings.Response.RequiredCapabilities = []string{"collector.tetragon"}
	verified, zero := now.Add(-24*time.Hour), time.Time{}
	for _, test := range []struct {
		name       string
		capability model.Capability
		missing    bool
		wantWarn   bool
	}{
		{"supported-active", model.Capability{State: model.CapabilitySupported, Implementation: "implemented", RuntimeState: "active", VerifiedAt: &verified}, false, false},
		{"limited-active", model.Capability{State: model.CapabilityLimited, Implementation: "implemented", RuntimeState: "active", VerifiedAt: &verified}, false, false},
		{"unsupported-active", model.Capability{State: model.CapabilityUnsupported, Implementation: "implemented", RuntimeState: "active", VerifiedAt: &verified}, false, false},
		{"passive-error-active", model.Capability{State: model.CapabilityError, Implementation: "implemented", RuntimeState: "active", VerifiedAt: &verified}, false, false},
		{"missing", model.Capability{}, true, true},
		{"implementation-missing", model.Capability{State: model.CapabilitySupported, RuntimeState: "active", VerifiedAt: &verified}, false, true},
		{"planned", model.Capability{Implementation: "planned", RuntimeState: "active", VerifiedAt: &verified}, false, true},
		{"runtime-inactive", model.Capability{State: model.CapabilitySupported, Implementation: "implemented", RuntimeState: "inactive", VerifiedAt: &verified}, false, true},
		{"runtime-error", model.Capability{State: model.CapabilitySupported, Implementation: "implemented", RuntimeState: "error", VerifiedAt: &verified}, false, true},
		{"verification-missing", model.Capability{State: model.CapabilitySupported, Implementation: "implemented", RuntimeState: "active"}, false, true},
		// The current agent checks a non-nil pointer, not IsZero or an age
		// threshold. Central warnings must not invent a different action gate.
		{"non-nil-zero-verification", model.Capability{Implementation: "implemented", RuntimeState: "active", VerifiedAt: &zero}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			capabilities := map[string]model.Capability{}
			if !test.missing {
				capabilities["collector.tetragon"] = test.capability
			}
			body := warningHeartbeat(t, now, now.Add(-48*time.Hour), "tetragon-json", capabilities)
			warnings := consolePolicyWarnings(settings, body, now)
			if got := len(warnings) != 0; got != test.wantWarn {
				t.Fatalf("warnings=%v, want capability warning=%v", warnings, test.wantWarn)
			}
			if test.wantWarn && !strings.Contains(strings.Join(warnings, " "), "collector.tetragon") {
				t.Fatalf("missing capability identity in warning: %v", warnings)
			}
		})
	}
}

func TestConsolePolicyWarningsUseHeartbeatFreshnessIndependently(t *testing.T) {
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	settings := defaultConsoleSettings(now)
	settings.Response.Mode, settings.Response.Action = "would_block", "terminate"
	settings.Response.RequiredCapabilities = []string{"response.terminate"}
	oldVerification := now.Add(-7 * 24 * time.Hour)
	active := map[string]model.Capability{"response.terminate": {Implementation: "implemented", RuntimeState: "active", VerifiedAt: &oldVerification}}
	for _, test := range []struct {
		name       string
		sentAt     time.Time
		probedAt   time.Time
		wantStale  bool
		missingCap bool
	}{
		{"old-passive-probe", now, now.Add(-24 * time.Hour), false, false},
		{"no-passive-probe", now, time.Time{}, false, false},
		{"stale-heartbeat", now.Add(-6 * time.Minute), now, true, false},
		{"stale-and-missing-capability", now.Add(-6 * time.Minute), now, true, true},
		{"missing-heartbeat-time", time.Time{}, now, true, false},
		{"future-heartbeat", now.Add(2 * time.Minute), now, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			capabilities := active
			if test.missingCap {
				capabilities = nil
			}
			warnings := strings.Join(consolePolicyWarnings(settings, warningHeartbeat(t, test.sentAt, test.probedAt, "tetragon-json", capabilities), now), " ")
			if got := strings.Contains(warnings, "하트비트"); got != test.wantStale {
				t.Fatalf("heartbeat warning=%q, want stale=%v", warnings, test.wantStale)
			}
			if got := strings.Contains(warnings, "response.terminate"); got != test.missingCap {
				t.Fatalf("freshness changed the runtime gate warning: %q", warnings)
			}
		})
	}
}

func TestConsolePolicyWarningsIncludeImplicitEnforceGatesOnce(t *testing.T) {
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	settings := defaultConsoleSettings(now)
	settings.Response.Mode, settings.Response.Action = "enforce", "terminate"
	settings.Response.RequiredCapabilities = []string{"observation.process_exec"}
	missing := strings.Join(consolePolicyWarnings(settings, warningHeartbeat(t, now, now, "tetragon-json", nil), now), " ")
	for _, name := range []string{"observation.process_exec", "observation.process_lineage", "response.terminate"} {
		if strings.Count(missing, name) != 1 {
			t.Fatalf("implicit gate %s missing or duplicated: %q", name, missing)
		}
	}
	if len(settings.Response.RequiredCapabilities) != 1 || settings.Response.RequiredCapabilities[0] != "observation.process_exec" {
		t.Fatal("warning generation changed the saved policy")
	}
	active := map[string]model.Capability{}
	for _, name := range []string{"observation.process_exec", "observation.process_lineage", "response.terminate"} {
		active[name] = model.Capability{State: model.CapabilityLimited, Implementation: "implemented", RuntimeState: "active", VerifiedAt: &now}
	}
	audit := strings.Join(consolePolicyWarnings(settings, warningHeartbeat(t, now, now, "audit-dispatcher", active), now), " ")
	if !strings.Contains(audit, "Tetragon 실행 이벤트에서만") || strings.Contains(audit, "확인되지 않았습니다") {
		t.Fatalf("collector restriction confused with capability support: %q", audit)
	}
	warnings := consolePolicyWarnings(settings, warningHeartbeat(t, now, time.Time{}, "tetragon-json", active), now)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "로컬 opt-in과 기능 검증") {
		t.Fatalf("active gates gained false warnings: %v", warnings)
	}
}

func TestConsolePolicyWarningsKeepObserveAndMissingReportBehavior(t *testing.T) {
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	settings := defaultConsoleSettings(now)
	if warnings := consolePolicyWarnings(settings, nil, now); len(warnings) != 0 {
		t.Fatalf("observe mode applied response gates: %v", warnings)
	}
	settings.Integrity.Enabled = true
	if warnings := consolePolicyWarnings(settings, nil, now); len(warnings) != 1 || !strings.Contains(warnings[0], "적용 대기") {
		t.Fatalf("pending integrity warning changed: %v", warnings)
	}
	settings.Integrity.Enabled = false
	settings.Response.Mode = "would_block"
	for _, body := range [][]byte{nil, []byte("invalid-private-payload"), []byte(`{"status":{}}`)} {
		warnings := strings.Join(consolePolicyWarnings(settings, body, now), " ")
		if !strings.Contains(warnings, "인증된 기능 보고가 없어") || strings.Contains(warnings, "private-payload") {
			t.Fatalf("missing capability report misrepresented or raw body disclosed: %q", warnings)
		}
	}
}

func warningHeartbeat(t *testing.T, sentAt, probedAt time.Time, collector string, capabilities map[string]model.Capability) []byte {
	t.Helper()
	body, err := json.Marshal(managed.Heartbeat{SentAt: sentAt, Status: model.AgentStatus{Collector: collector, CapabilityReport: &model.CapabilityReport{ProbedAt: probedAt, Capabilities: capabilities}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
