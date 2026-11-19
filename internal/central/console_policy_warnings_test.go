package central

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
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

func TestConsolePolicyWarningsExplainExtendedResponseBeforeOtherChecks(t *testing.T) {
	now := time.Now().UTC()
	settings := defaultConsoleSettings(now)
	settings.Detection.ExtendedProcessRules = true
	settings.Integrity.Enabled = true
	for mode, want := range map[string]string{"would_block": "모의 대응 후보가 0개", "enforce": "종료 후보가 0개"} {
		settings.Response.Mode = mode
		available := model.Capability{State: model.CapabilitySupported, Provider: "pidfd", Implementation: "implemented", RuntimeState: "active", VerifiedAt: &now}
		body := warningHeartbeat(t, now, now, "tetragon-json", map[string]model.Capability{"response.terminate": available})
		warnings := consolePolicyWarnings(settings, body, now)
		if len(warnings) != 2 || !strings.Contains(warnings[0], want) || !strings.Contains(warnings[1], "무결성") {
			t.Fatalf("%s: %v", mode, warnings)
		}
		if mode == "enforce" && !strings.Contains(warnings[0], "정책 수락에는 로컬 종료 허용") {
			t.Fatal("missing enforce acceptance precondition")
		}
	}
	settings.Response.Mode = "observe"
	if warnings := consolePolicyWarnings(settings, nil, now); len(warnings) != 1 || !strings.Contains(warnings[0], "무결성") {
		t.Fatalf("unexpected observe warning: %v", warnings)
	}
}

func TestConsolePolicyWarningsOnlyCheckEffectiveSensorScopes(t *testing.T) {
	now := time.Now().UTC()
	settings := defaultConsoleSettings(now)
	settings.Detection.WebServices = []string{"api.service"}
	file := managed.ServiceObservationPolicy{Service: "api.service", ProtectedDirs: []string{"/srv/site"}}
	network := managed.ServiceObservationPolicy{Service: "API.service", AllowedTCPDestinations: []managed.TCPDestination{{CIDR: netip.MustParsePrefix("192.0.2.0/24")}}}
	scopes := []managed.ServiceObservationPolicy{file, network}
	settings.Detection.ServiceObservations = &scopes
	sentAt, collector := now, "tetragon-json"
	report := func(caps map[string]model.Capability) []byte {
		return warningHeartbeat(t, sentAt, now, collector, caps)
	}
	verified := model.Capability{Implementation: "implemented", RuntimeState: "active", VerifiedAt: &now}
	fileOnly := map[string]model.Capability{"observation.file": verified}
	text := func(body []byte) string { return strings.Join(consolePolicyWarnings(settings, body, now), " ") }
	if got := text(report(fileOnly)); !strings.Contains(got, "관측 범위 1개") || strings.Contains(got, "센서") {
		t.Fatalf("unmatched TCP scope counted as effective: %q", got)
	}
	settings.Detection.WebServices = append(settings.Detection.WebServices, "API.service")
	if got := text(report(fileOnly)); !strings.Contains(got, "TCP 연결") || strings.Contains(got, "파일 쓰기") || strings.Contains(got, "불일치") {
		t.Fatalf("missing TCP receipt: %q", got)
	}
	both := map[string]model.Capability{"observation.file": verified, "observation.network": verified}
	if got := text(report(both)); got != "" {
		t.Fatalf("current receipts warned: %q", got)
	}
	checkBoth := func(body []byte) {
		t.Helper()
		got := text(body)
		if !strings.Contains(got, "파일 쓰기 / TCP 연결") {
			t.Fatalf("missing sensor warnings: %q", got)
		}
	}
	checkBoth(nil)
	checkBoth(report(map[string]model.Capability{"detection.service_observations": verified}))
	old := now.Add(-6 * time.Minute)
	stale := model.Capability{Implementation: "implemented", RuntimeState: "active", VerifiedAt: &old}
	checkBoth(report(map[string]model.Capability{"observation.file": stale, "observation.network": stale}))
	collector = "audit-dispatcher"
	checkBoth(report(both))
	collector, sentAt = "tetragon-json", now.Add(-3*time.Minute)
	checkBoth(report(both))

	settings.Detection.Enabled = false
	if got := text(nil); got != "" {
		t.Fatalf("disabled detection: %q", got)
	}
	settings.Detection.Enabled = true
	emptyScopes := []managed.ServiceObservationPolicy{}
	for _, scopes := range []*[]managed.ServiceObservationPolicy{nil, &emptyScopes} {
		settings.Detection.ServiceObservations = scopes
		if got := text(nil); got != "" {
			t.Fatalf("inherited or empty scopes: %q", got)
		}
	}
}

func TestConsoleExtendedEnforceShowsHostAcceptanceSeparately(t *testing.T) {
	now := time.Now().UTC()
	settings := defaultConsoleSettings(now)
	settings.Detection.ExtendedProcessRules = true
	settings.Response.Mode = "enforce"
	for _, tc := range []struct {
		name    string
		state   model.CapabilityState
		runtime string
		sentAt  time.Time
		probeAt *time.Time
		want    string
	}{
		{"local-opt-out", model.CapabilitySupported, "available", now, nil, "로컬 opt-in이 비활성화"},
		{"local-opt-out-without-passive-state", "", "available", now, nil, "미확인"},
		{"unsupported", model.CapabilityUnsupported, "inactive", now, nil, "pidfd를 지원하지 않아"},
		{"unreported", "", "", now, nil, "미확인"},
		{"stale", model.CapabilitySupported, "available", now.Add(-3 * time.Minute), nil, "미확인"},
		{"active-without-proof", model.CapabilitySupported, "active", now, nil, "미확인"},
		{"accepted", model.CapabilitySupported, "active", now, &now, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := map[string]model.Capability{}
			if tc.runtime != "" {
				caps["response.terminate"] = model.Capability{State: tc.state, Provider: "pidfd", Implementation: "implemented", RuntimeState: tc.runtime, VerifiedAt: tc.probeAt}
			}
			body := warningHeartbeat(t, tc.sentAt, now, "tetragon-json", caps)
			warnings := consolePolicyWarnings(settings, body, now)
			if len(warnings) == 0 || !strings.Contains(warnings[0], "후보가 0개") {
				t.Fatalf("missing candidate policy warning: %v", warnings)
			}
			if tc.want == "" {
				if len(warnings) != 1 {
					t.Fatalf("unexpected action or acceptance warning: %v", warnings)
				}
			} else if len(warnings) != 2 || !strings.Contains(warnings[1], tc.want) {
				t.Fatalf("acceptance warnings: %v, want %q", warnings, tc.want)
			}
		})
	}
}

func TestConsolePolicyWarningsFitGroupPreviewAtFleetLimit(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	f.server.now = func() time.Time { return now }
	settings := defaultConsoleSettings(now)
	settings.Response.Mode, settings.Response.Action = "enforce", "terminate"
	settings.Response.RequiredCapabilities = []string{"response.terminate"}
	settings.Integrity.Enabled = true
	settings.Detection.WebServices = []string{"api.service"}
	scopes := []managed.ServiceObservationPolicy{{Service: "api.service", ProtectedDirs: []string{"/srv"}, AllowedTCPDestinations: []managed.TCPDestination{{CIDR: netip.MustParsePrefix("192.0.2.0/24")}}}}
	settings.Detection.ServiceObservations = &scopes
	active := model.Capability{Implementation: "implemented", RuntimeState: "active", VerifiedAt: &now}
	heartbeat := managed.Heartbeat{SentAt: now, Status: model.AgentStatus{Collector: "tetragon-json", CapabilityReport: &model.CapabilityReport{Capabilities: map[string]model.Capability{
		"detection.service_observations": {Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}},
		"response.terminate":             {State: model.CapabilitySupported, Implementation: "implemented", RuntimeState: "available"},
		"observation.process_exec":       active, "observation.process_lineage": active,
	}}}}
	ids := make([]string, consoleMaxTargets)
	tx, err := f.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := range ids {
		ids[i] = fmt.Sprintf("node-%04d", i)
		heartbeat.AgentID, heartbeat.EnrollmentID = ids[i], fmt.Sprintf("%032d", i)
		body, err := json.Marshal(heartbeat)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("INSERT INTO agents(agent_id,enrollment_id,cert_serial,enrolled_at_ns,heartbeat_json) VALUES(?,?,?,?,?)", ids[i], heartbeat.EnrollmentID, ids[i], now.UnixNano(), body); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "template", Name: "경고 시험", Settings: settings}), 200, nil)
	consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "Group", AgentIDs: ids}), 200, nil)
	var preview struct {
		Token   string                `json:"preview_token"`
		Targets []consoleDeployTarget `json:"targets"`
	}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "template", GroupIDs: []string{"web"}}), 200, &preview)
	if len(preview.Targets) != consoleMaxTargets {
		t.Fatalf("preview targets=%d", len(preview.Targets))
	}
	for _, target := range preview.Targets {
		warnings := strings.Join(target.Warnings, " ")
		if !strings.Contains(warnings, "로컬 opt-in이 비활성화") || !strings.Contains(warnings, "파일 쓰기 / TCP 연결") || !strings.Contains(warnings, "무결성") {
			t.Fatalf("HTTP preview lost warnings: %v", target.Warnings)
		}
	}
	snapshot, err := f.server.decodeConsolePreview(preview.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != len(preview.Targets) {
		t.Fatal("missing signed enrollment targets")
	}
	for i, target := range snapshot.Targets {
		reported := preview.Targets[i]
		if len(target.Warnings) != 0 || target.AgentID != reported.AgentID || target.EnrollmentID != reported.EnrollmentID || target.NextRevision != reported.NextRevision {
			t.Fatalf("unexpected signed target: %+v", target)
		}
	}
	snapshot.Targets = preview.Targets
	duplicated, err := json.Marshal(snapshot)
	if err != nil || len(duplicated) <= previewMaxBytes {
		t.Fatalf("fixture did not exercise token limit: %d bytes, %v", len(duplicated), err)
	}
	consoleWant(t, f.deploy(t, preview.Token), 200, nil)
	var assigned int
	if err := f.store.db.QueryRow("SELECT COUNT(*) FROM policies WHERE revision=1").Scan(&assigned); err != nil || assigned != consoleMaxTargets {
		t.Fatalf("assigned=%d, err=%v", assigned, err)
	}
}

func TestConsoleDeployAcceptsPreviouslySignedWarnings(t *testing.T) {
	f := setup(t)
	f.enroll(t, "legacy-agent")
	f.consoleDrafts(t, []string{"legacy-agent"})
	now := time.Now().UTC()
	snapshot, err := f.server.decodeConsolePreview(f.preview(t), now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Targets[0].Warnings = []string{"이전 미리보기 경고"}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(f.material.PolicyKey, append([]byte(previewDomain), body...))
	legacy := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(signature)
	consoleWant(t, f.deploy(t, legacy), 200, nil)
	consoleWant(t, f.deploy(t, legacy), 409, nil)
}

func warningHeartbeat(t *testing.T, sentAt, probedAt time.Time, collector string, capabilities map[string]model.Capability) []byte {
	t.Helper()
	body, err := json.Marshal(managed.Heartbeat{SentAt: sentAt, Status: model.AgentStatus{Collector: collector, CapabilityReport: &model.CapabilityReport{ProbedAt: probedAt, Capabilities: capabilities}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
