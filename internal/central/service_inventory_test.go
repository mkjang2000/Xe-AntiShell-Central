package central

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func inventoryHeartbeatFixture(t *testing.T, agent, enrollment, state string, sampledAt, sentAt time.Time, listeners []serviceListener) managed.Heartbeat {
	t.Helper()
	details := map[string]string{"contract": "1", "state": state}
	if !sampledAt.IsZero() {
		raw, err := json.Marshal(serviceInventorySample{State: state, SampledAt: &sampledAt, Listeners: listeners})
		if err != nil {
			t.Fatal(err)
		}
		details["snapshot"] = string(raw)
	}
	return managed.Heartbeat{AgentID: agent, EnrollmentID: enrollment, SentAt: sentAt, Status: model.AgentStatus{
		CapabilityReport: &model.CapabilityReport{Capabilities: map[string]model.Capability{serviceInventoryCapability: {Details: details}}},
	}}
}

func TestServiceInventoryHeartbeatProjection(t *testing.T) {
	const agent, enrollment = "web-a", "enrollment-a"
	now := time.Date(2026, 11, 19, 4, 0, 0, 0, time.UTC)
	listeners := []serviceListener{
		{Service: "nginx.service", Port: 443, Family: "ipv6", Binding: "wildcard"},
		{Port: 8081, Family: "ipv4", Binding: "loopback"},
		{Service: "apache2.service", Port: 80, Family: "ipv4", Binding: "interface"},
		{Service: "nginx.service", Port: 443, Family: "ipv6", Binding: "wildcard"},
	}
	for _, test := range []struct {
		name, state         string
		sampled, sent, recv time.Time
		want                string
		wantRows            int
		change              func(*managed.Heartbeat)
	}{
		{name: "fresh", state: "complete", sampled: now.Add(-time.Minute), sent: now, recv: now, want: "complete", wantRows: 3},
		{name: "partial", state: "partial", sampled: now.Add(-time.Minute), sent: now, recv: now, want: "partial", wantRows: 3},
		{name: "no receipt", state: "complete", sampled: now.Add(-time.Minute), sent: now, want: "pending"},
		{name: "reported pending", state: "pending", sent: now, recv: now, want: "pending"},
		{name: "unavailable", state: "unavailable", sent: now, recv: now, want: "unavailable"},
		{name: "no contract", state: "pending", sent: now, recv: now, want: "unsupported", change: func(h *managed.Heartbeat) {
			delete(h.Status.CapabilityReport.Capabilities[serviceInventoryCapability].Details, "contract")
		}},
		{name: "old capture", state: "complete", sampled: now.Add(-3*time.Minute - time.Second), sent: now, recv: now, want: "stale", wantRows: 3},
		{name: "old receipt", state: "complete", sampled: now.Add(-time.Minute), sent: now, recv: now.Add(-4 * time.Minute), want: "stale", wantRows: 3},
		{name: "future capture", state: "complete", sampled: now.Add(6 * time.Second), sent: now, recv: now, want: "stale", wantRows: 3},
		{name: "declared stale", state: "complete", sampled: now.Add(-time.Minute), sent: now, recv: now, want: "stale", wantRows: 3, change: func(h *managed.Heartbeat) {
			h.Status.CapabilityReport.Capabilities[serviceInventoryCapability].Details["state"] = "stale"
		}},
		{name: "old registration", state: "complete", sampled: now, sent: now, recv: now, want: "malformed", change: func(h *managed.Heartbeat) { h.EnrollmentID = "previous" }},
		{name: "invalid row", state: "complete", sampled: now, sent: now, recv: now, want: "malformed", change: func(h *managed.Heartbeat) {
			d := h.Status.CapabilityReport.Capabilities[serviceInventoryCapability].Details
			d["snapshot"] = strings.Replace(d["snapshot"], "\"port\":443", "\"address\":\"10.1.2.3\",\"port\":443", 1)
		}},
		{name: "too many rows", state: "complete", sampled: now, sent: now, recv: now, want: "malformed", change: func(h *managed.Heartbeat) {
			rows := make([]serviceListener, 65)
			for i := range rows {
				rows[i] = serviceListener{Port: uint16(100 + i), Family: "ipv4", Binding: "wildcard"}
			}
			payload, _ := json.Marshal(serviceInventorySample{State: "complete", SampledAt: &now, Listeners: rows})
			h.Status.CapabilityReport.Capabilities[serviceInventoryCapability].Details["snapshot"] = string(payload)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			hb := inventoryHeartbeatFixture(t, agent, enrollment, test.state, test.sampled, test.sent, listeners)
			if test.change != nil {
				test.change(&hb)
			}
			got := serviceInventoryFromHeartbeat(hb, agent, enrollment, test.recv, now)
			if got.State != test.want || got.Listeners == nil || len(got.Listeners) != test.wantRows {
				t.Fatalf("got %+v, expected %s with %d rows", got, test.want, test.wantRows)
			}
			names, err := got.deploymentServices()
			if got.State == "complete" {
				if err != nil || !reflect.DeepEqual(names, []string{"apache2.service", "nginx.service"}) ||
					got.Listeners[0].Service != "apache2.service" || got.SampledAt == nil || !got.SampledAt.Equal(test.sampled) {
					t.Fatalf("unexpected deployment names/evidence %v/%v/%+v", names, err, got)
				}
			} else if names != nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid state was eligible: %s %v %v", got.State, names, err)
			}
		})
	}
}

func TestServiceInventoryUsesOnlyUnambiguousUnits(t *testing.T) {
	at := time.Now().UTC()
	rows := []serviceListener{{Port: 8080, Family: "ipv4", Binding: "loopback"}}
	for _, listeners := range [][]serviceListener{
		rows,
		{{Service: "NGINX.service", Port: 443, Family: "ipv6", Binding: "wildcard"}, {Service: "nginx.service", Port: 80, Family: "ipv4", Binding: "wildcard"}},
	} {
		report := inventoryHeartbeatFixture(t, "agent", "enrollment", "complete", at, at, listeners)
		inventory := serviceInventoryFromHeartbeat(report, "agent", "enrollment", at, at)
		if names, err := inventory.deploymentServices(); inventory.State != "complete" || names != nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("ambiguous inventory %+v %v %v", inventory, names, err)
		}
	}
}

func TestAgentServiceInventoryConsoleFollowsCurrentEnrollment(t *testing.T) {
	f := setup(t)
	a, cert, _ := f.enroll(t, "inventory-agent")
	path := "/api/agents/" + a.AgentID + "/service-inventory"
	var result serviceInventoryResponse
	consoleWant(t, f.console(t, http.MethodGet, path, nil), 200, &result)
	if result.State != "pending" || result.AgentID != a.AgentID || result.EnrollmentID != a.EnrollmentID {
		t.Fatalf("unassigned agent lookup %+v", result)
	}
	now := f.server.now().UTC()
	hb := inventoryHeartbeatFixture(t, a.AgentID, a.EnrollmentID, "complete", now, now, []serviceListener{
		{Service: "nginx.service", Port: 443, Family: "ipv4", Binding: "wildcard"}, {Port: 9000, Family: "ipv6", Binding: "loopback"},
	})
	consoleWant(t, f.request(t, http.MethodPost, "/v1/heartbeat", hb, cert, ""), 200, nil)
	result = serviceInventoryResponse{}
	consoleWant(t, f.console(t, http.MethodGet, path, nil), 200, &result)
	if result.State != "complete" || len(result.Listeners) != 2 || result.Listeners[0].Service != "nginx.service" ||
		result.SampledAt == nil || result.ReceivedAt == nil {
		t.Fatalf("unexpected console inventory %+v", result)
	}
	replacement, _, _ := f.enroll(t, a.AgentID)
	result = serviceInventoryResponse{}
	consoleWant(t, f.console(t, http.MethodGet, path, nil), 200, &result)
	if result.State != "pending" || len(result.Listeners) != 0 || result.EnrollmentID != replacement.EnrollmentID || result.EnrollmentID == a.EnrollmentID {
		t.Fatalf("previous enrollment leaked %+v", result)
	}
	consoleWant(t, f.request(t, http.MethodPost, "/admin/revoke", map[string]string{"agent_id": a.AgentID}, nil, f.operator(t)), 200, nil)
	consoleWant(t, f.console(t, http.MethodGet, path, nil), 404, nil)
}
