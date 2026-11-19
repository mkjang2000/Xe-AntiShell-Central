package central

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func TestConsoleServiceScopeAcceptsLegacyAndRejectsMixedSelectors(t *testing.T) {
	tests := []struct {
		name, mode            string
		services, executables []string
		valid                 bool
	}{
		{name: "legacy executable and service", services: []string{"old-service"}, executables: []string{"nginx"}, valid: true},
		{name: "explicit unit", mode: serviceScopeSelected, services: []string{"workers@blue.service"}, valid: true},
		{name: "selected empty", mode: serviceScopeSelected},
		{name: "selected executable", mode: serviceScopeSelected, services: []string{"nginx.service"}, executables: []string{"nginx"}},
		{name: "selected pattern", mode: serviceScopeSelected, services: []string{"nginx*.service"}},
		{name: "selected alias", mode: serviceScopeSelected, services: []string{"nginx"}},
		{name: "selected case duplicate", mode: serviceScopeSelected, services: []string{"Nginx.service", "nginx.service"}},
		{name: "all listing", mode: serviceScopeAllListening, valid: true},
		{name: "all executable", mode: serviceScopeAllListening, executables: []string{"nginx"}},
		{name: "all with extra service", mode: serviceScopeAllListening, services: []string{"nginx.service"}},
		{name: "unsupported mode", mode: "invented", services: []string{"nginx.service"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := defaultConsoleSettings(time.Now())
			settings.ServiceScope = test.mode
			settings.Detection.WebServices = test.services
			settings.Detection.WebExecutables = test.executables
			err := settings.validate()
			if test.valid && err != nil || !test.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate() = %v, valid = %t", err, test.valid)
			}
			if test.mode == "" {
				body, err := json.Marshal(settings)
				if err != nil || strings.Contains(string(body), "service_scope") {
					t.Fatalf("legacy settings changed: %s, %v", body, err)
				}
			}
		})
	}
}

func reportConsoleServiceScope(t *testing.T, f *fixture, agent managed.EnrollResponse, cert *x509.Certificate, sent, sampled time.Time, state string, names ...string) {
	t.Helper()
	listeners := make([]serviceListener, 0, len(names))
	for i, name := range names {
		listeners = append(listeners, serviceListener{Service: name, Port: uint16(440 + i), Family: "ipv4", Binding: "loopback"})
	}
	snapshot, err := json.Marshal(serviceInventorySample{State: state, SampledAt: &sampled, Listeners: listeners})
	if err != nil {
		t.Fatal(err)
	}
	report := &model.CapabilityReport{Capabilities: map[string]model.Capability{
		serviceInventoryCapability: {Name: serviceInventoryCapability, Details: map[string]string{"contract": "1", "state": state, "snapshot": string(snapshot)}},
	}}
	heartbeat := managed.Heartbeat{AgentID: agent.AgentID, EnrollmentID: agent.EnrollmentID, SentAt: sent, Status: model.AgentStatus{CapabilityReport: report}}
	consoleWant(t, f.request(t, http.MethodPost, "/v1/heartbeat", heartbeat, cert, ""), http.StatusOK, nil)
}

func saveConsoleServiceScope(t *testing.T, f *fixture, mode string, names []string, now time.Time) {
	t.Helper()
	settings := defaultConsoleSettings(now)
	settings.ServiceScope, settings.Detection.WebServices = mode, names
	settings.Detection.WebExecutables = nil
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "scoped", Name: "서비스 범위", Settings: settings}), http.StatusOK, nil)
}

type consoleServiceScopePreview struct {
	Token          string                  `json:"preview_token"`
	ServiceTargets []consoleServiceTargets `json:"service_targets"`
}

func previewConsoleServiceScope(t *testing.T, f *fixture, agents ...string) consoleServiceScopePreview {
	t.Helper()
	var preview consoleServiceScopePreview
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "scoped", AgentIDs: agents}), http.StatusOK, &preview)
	if preview.Token == "" {
		t.Fatal("no preview token")
	}
	return preview
}

func TestConsoleAllListeningFreezesEachHostsServiceSet(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	a, ca, _ := f.enroll(t, "scope-agent-a")
	b, cb, _ := f.enroll(t, "scope-agent-b")
	c, cc, _ := f.enroll(t, "scope-agent-c")
	saveConsoleServiceScope(t, f, serviceScopeAllListening, nil, now)

	reportConsoleServiceScope(t, f, a, ca, now, now, "complete", "php-fpm.service", "nginx.service", "", "nginx.service")
	reportConsoleServiceScope(t, f, b, cb, now, now, "complete", "app.service")
	reportConsoleServiceScope(t, f, c, cc, now, now, "complete", "nginx.service", "php-fpm.service")
	preview := previewConsoleServiceScope(t, f, c.AgentID, b.AgentID, a.AgentID)
	want := []consoleServiceTargets{
		{AgentIDs: []string{a.AgentID, c.AgentID}, Services: []string{"nginx.service", "php-fpm.service"}},
		{AgentIDs: []string{b.AgentID}, Services: []string{"app.service"}},
	}
	if !reflect.DeepEqual(preview.ServiceTargets, want) {
		t.Fatalf("preview service targets = %#v, want %#v", preview.ServiceTargets, want)
	}
	decoded, err := f.server.decodeConsolePreview(preview.Token, now)
	if err != nil || len(decoded.Targets) != 3 ||
		decoded.Targets[0].ServiceScopeHash == "" ||
		decoded.Targets[0].ServiceScopeHash != decoded.Targets[2].ServiceScopeHash ||
		decoded.Targets[0].ServiceScopeHash == decoded.Targets[1].ServiceScopeHash ||
		decoded.Targets[0].listeningServices != nil {
		t.Fatalf("service names or hashes in preview token: %+v, %v", decoded.Targets, err)
	}

	client := updateConsoleClient(t, f)
	body, err := json.Marshal(map[string]any{"preview_token": preview.Token, "canary": a.AgentID})
	if err != nil {
		t.Fatal(err)
	}
	blocked := client("POST", "/api/policy-trials", body, "application/json")
	consoleWant(t, blocked, http.StatusBadRequest, nil)
	if !strings.Contains(blocked.Body.String(), "발견된 모든 서비스 모드") {
		t.Fatalf("unexpected trial rejection: %s", blocked.Body.String())
	}

	now = now.Add(time.Second)
	reportConsoleServiceScope(t, f, b, cb, now, now, "complete", "replacement.service")
	consoleWant(t, f.deploy(t, preview.Token), http.StatusConflict, nil)
	for _, agent := range []managed.EnrollResponse{a, b, c} {
		if _, err := f.store.LatestPolicy(ctx, agent.AgentID, agent.EnrollmentID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("partial assignment on conflict for %s: %v", agent.AgentID, err)
		}
	}

	preview = previewConsoleServiceScope(t, f, a.AgentID, b.AgentID, c.AgentID)
	now = now.Add(time.Second)
	reportConsoleServiceScope(t, f, a, ca, now, now, "complete", "nginx.service", "php-fpm.service")
	reportConsoleServiceScope(t, f, b, cb, now, now, "complete", "", "replacement.service", "replacement.service")
	var deployed consoleServiceScopePreview
	consoleWant(t, f.deploy(t, preview.Token), http.StatusOK, &deployed)
	if !reflect.DeepEqual(deployed.ServiceTargets, preview.ServiceTargets) {
		t.Fatalf("deployed scopes diverged from preview: %#v vs %#v", deployed.ServiceTargets, preview.ServiceTargets)
	}
	for _, agent := range []managed.EnrollResponse{a, b, c} {
		signed, err := f.store.LatestPolicy(ctx, agent.AgentID, agent.EnrollmentID)
		names := []string{"nginx.service", "php-fpm.service"}
		if agent.AgentID == b.AgentID {
			names = []string{"replacement.service"}
		}
		if err != nil || !slices.Equal(signed.Policy.Detection.WebServices, names) || len(signed.Policy.Detection.WebExecutables) != 0 {
			t.Fatalf("unexpected signed scope for %s: %v, %v", agent.AgentID, signed.Policy.Detection.WebServices, err)
		}
		var stored []byte
		err = f.store.db.QueryRowContext(ctx, "SELECT settings_json FROM console_policy_settings WHERE agent_id=? AND enrollment_id=? AND revision=?", agent.AgentID, agent.EnrollmentID, signed.Policy.Revision).Scan(&stored)
		var settings ConsoleSettings
		if err != nil || json.Unmarshal(stored, &settings) != nil || settings.ServiceScope != serviceScopeAllListening || len(settings.Detection.WebServices) != 0 {
			t.Fatalf("raw template settings were changed by expansion: %s, %v", stored, err)
		}
	}
}

func TestConsoleAllListeningRejectsUnavailableInventory(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	agent, cert, _ := f.enroll(t, "scope-agent")
	saveConsoleServiceScope(t, f, serviceScopeAllListening, nil, now)
	request := consolePreviewRequest{TemplateID: "scoped", AgentIDs: []string{agent.AgentID}}
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", request), http.StatusBadRequest, nil)
	reportConsoleServiceScope(t, f, agent, cert, now, now, "complete", "")
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", request), http.StatusBadRequest, nil)
	reportConsoleServiceScope(t, f, agent, cert, now, now, "partial", "known.service")
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", request), http.StatusBadRequest, nil)
	reportConsoleServiceScope(t, f, agent, cert, now, now.Add(-4*time.Minute), "complete", "known.service")
	consoleWant(t, f.console(t, "POST", "/api/deploy/preview", request), http.StatusBadRequest, nil)
	reportConsoleServiceScope(t, f, agent, cert, now, now, "complete", "known.service")
	preview := previewConsoleServiceScope(t, f, agent.AgentID)
	now = now.Add(4 * time.Minute)
	consoleWant(t, f.deploy(t, preview.Token), http.StatusConflict, nil)
}

func TestConsoleAllListeningChecksResolvedWireSize(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	agent, cert, _ := f.enroll(t, "scope-agent")

	settings := defaultConsoleSettings(now)
	settings.ServiceScope, settings.Detection.WebExecutables = serviceScopeAllListening, nil
	for i := range 251 {
		settings.Detection.AllowedPairs = append(settings.Detection.AllowedPairs, fmt.Sprintf("%s%03d:%s", strings.Repeat("a", 120), i, strings.Repeat("b", 124)))
	}
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "scoped", Name: "서비스 범위", Settings: settings}), http.StatusOK, nil)

	var services []string
	for i := range 16 {
		services = append(services, fmt.Sprintf("%s%03d.service", strings.Repeat("p", 240), i))
	}
	reportConsoleServiceScope(t, f, agent, cert, now, now, "complete", services...)
	response := f.console(t, "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "scoped", AgentIDs: []string{agent.AgentID}})
	consoleWant(t, response, http.StatusBadRequest, nil)
	if !strings.Contains(response.Body.String(), "정책 설정이 너무 큽니다") {
		t.Fatalf("unexpected size error: %s", response.Body.String())
	}
}

func TestConsoleSelectedServiceDeploysWithoutInventory(t *testing.T) {
	f := setup(t)
	now := time.Now()
	agent, _, _ := f.enroll(t, "scope-agent")
	saveConsoleServiceScope(t, f, serviceScopeSelected, []string{"manual.service"}, now)
	preview := previewConsoleServiceScope(t, f, agent.AgentID)
	if preview.ServiceTargets != nil {
		t.Fatalf("resolved inventory appeared for manually selected services: %#v", preview.ServiceTargets)
	}
	consoleWant(t, f.deploy(t, preview.Token), http.StatusOK, nil)
	signed, err := f.store.LatestPolicy(context.Background(), agent.AgentID, agent.EnrollmentID)
	if err != nil || !slices.Equal(signed.Policy.Detection.WebServices, []string{"manual.service"}) || len(signed.Policy.Detection.WebExecutables) != 0 {
		t.Fatalf("signed policy for selected service: %v, %v", signed.Policy.Detection.WebServices, err)
	}
}
