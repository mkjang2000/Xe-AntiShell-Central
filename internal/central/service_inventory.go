package central

import (
	"cmp"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const (
	serviceInventoryCapability = "inventory.listening_services"
	serviceInventoryMaxBytes   = 8 << 10
	serviceInventoryMaxRows    = 64
	serviceInventoryMaxAge     = 3 * time.Minute
	serviceInventoryFutureSkew = 5 * time.Second
)

type serviceListener struct {
	Service string `json:"service,omitempty"`
	Port    uint16 `json:"port"`
	Family  string `json:"family"`
	Binding string `json:"binding"`
}

type serviceInventorySample struct {
	State     string            `json:"state"`
	SampledAt *time.Time        `json:"sampled_at,omitempty"`
	Listeners []serviceListener `json:"listeners"`
}

type serviceInventory struct {
	serviceInventorySample
	ReceivedAt *time.Time `json:"received_at,omitempty"`
}

type serviceInventoryResponse struct {
	serviceInventory
	AgentID      string `json:"agent_id"`
	EnrollmentID string `json:"enrollment_id"`
}

func serviceInventoryFromHeartbeat(report managed.Heartbeat, agentID, enrollmentID string, receivedAt, now time.Time) serviceInventory {
	out := serviceInventory{serviceInventorySample: serviceInventorySample{State: "pending", Listeners: []serviceListener{}}}
	if receivedAt.IsZero() || receivedAt.Equal(time.Unix(0, 0)) {
		return out
	}
	receivedAt = receivedAt.UTC()
	out.ReceivedAt = &receivedAt
	out.State = "malformed"
	if report.AgentID != agentID || report.EnrollmentID != enrollmentID {
		return out
	}
	if report.Status.CapabilityReport == nil {
		out.State = "unsupported"
		return out
	}
	capability, ok := report.Status.CapabilityReport.Capabilities[serviceInventoryCapability]
	if !ok || capability.Details["contract"] != "1" {
		out.State = "unsupported"
		return out
	}
	state, raw := capability.Details["state"], capability.Details["snapshot"]
	switch state {
	case "pending", "unavailable":
		if raw == "" {
			out.State = state
			if !serviceInventoryFresh(receivedAt, now) || !serviceInventoryFresh(report.SentAt, now) {
				out.State = "stale"
			}
			return out
		}
		if state == "pending" {
			return out
		}
	case "complete", "partial", "stale":
	default:
		return out
	}
	sample, ok := parseServiceInventorySample(raw, state)
	if !ok {
		return out
	}
	out.serviceInventorySample = sample
	if !serviceInventoryFresh(receivedAt, now) || !serviceInventoryFresh(report.SentAt, now) ||
		!serviceInventoryFresh(*out.SampledAt, now) || out.SampledAt.After(report.SentAt.Add(serviceInventoryFutureSkew)) ||
		out.SampledAt.After(receivedAt.Add(serviceInventoryFutureSkew)) {
		out.State = "stale"
	}
	return out
}

func parseServiceInventorySample(raw, state string) (serviceInventorySample, bool) {
	var sample serviceInventorySample
	if len(raw) == 0 || len(raw) > serviceInventoryMaxBytes {
		return sample, false
	}
	quoted, _ := json.Marshal(raw)
	if len(quoted) > serviceInventoryMaxBytes ||
		managed.DecodeStrict([]byte(raw), serviceInventoryMaxBytes, &sample) != nil ||
		sample.SampledAt == nil || sample.SampledAt.IsZero() ||
		sample.Listeners == nil || len(sample.Listeners) > serviceInventoryMaxRows {
		return sample, false
	}
	if state == "stale" {
		if sample.State != "complete" && sample.State != "partial" {
			return sample, false
		}
	} else if sample.State != state || state == "unavailable" && len(sample.Listeners) != 0 {
		return sample, false
	}
	for _, row := range sample.Listeners {
		if row.Service != "" && !managed.ValidApplicationService(row.Service) || row.Port == 0 ||
			row.Family != "ipv4" && row.Family != "ipv6" ||
			row.Binding != "wildcard" && row.Binding != "loopback" && row.Binding != "interface" {
			return sample, false
		}
	}
	slices.SortFunc(sample.Listeners, compareServiceListener)
	sample.Listeners = slices.Compact(sample.Listeners)
	at := sample.SampledAt.UTC()
	sample.SampledAt = &at
	sample.State = state
	return sample, true
}

func compareServiceListener(a, b serviceListener) int {
	order := strings.Compare(a.Service, b.Service)
	if a.Service == "" || b.Service == "" {
		order = -order
	}
	return cmp.Or(order, cmp.Compare(a.Port, b.Port), strings.Compare(a.Family, b.Family), strings.Compare(a.Binding, b.Binding))
}

func serviceInventoryFresh(at, now time.Time) bool {
	return !at.IsZero() && !at.Before(now.Add(-serviceInventoryMaxAge)) && !at.After(now.Add(serviceInventoryFutureSkew))
}

// Existing detectors compare service names without regard to case. Refuse a
// listing with two distinct names that would collapse into the same rule.
func (inventory serviceInventory) deploymentServices() ([]string, error) {
	if inventory.State != "complete" {
		reason := "서비스 인벤토리를 사용할 수 없습니다"
		switch inventory.State {
		case "pending":
			reason = "서비스 인벤토리 수집을 기다리고 있습니다"
		case "unsupported":
			reason = "서비스 인벤토리를 지원하는 에이전트 RPM 38 이상이 필요합니다"
		case "partial":
			reason = "서비스 인벤토리가 일부만 수집되었습니다"
		case "stale":
			reason = "서비스 인벤토리 보고가 오래되었거나 시각을 확인할 수 없습니다"
		case "malformed":
			reason = "서비스 인벤토리 보고 형식 또는 등록을 확인할 수 없습니다"
		}
		return nil, fmt.Errorf("%w: %s", ErrInvalid, reason)
	}
	names := []string{}
	seen := make(map[string]string)
	for _, row := range inventory.Listeners {
		if row.Service == "" {
			continue
		}
		key := strings.ToLower(row.Service)
		if previous, exists := seen[key]; exists {
			if previous != row.Service {
				return nil, fmt.Errorf("%w: 대소문자만 다른 서비스가 있어 자동 선택할 수 없습니다", ErrInvalid)
			}
			continue
		}
		seen[key] = row.Service
		names = append(names, row.Service)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: 이름을 확인한 TCP 대기 서비스가 없습니다", ErrInvalid)
	}
	slices.Sort(names)
	return names, nil
}

func (s *Server) consoleAgentServiceInventory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !identifierPattern.MatchString(id) {
		s.consoleError(w, "service inventory input", ErrInvalid)
		return
	}
	var enrollment string
	var raw []byte
	var received int64
	err := s.store.db.QueryRowContext(r.Context(), "SELECT enrollment_id,heartbeat_json,last_seen_at_ns FROM agents WHERE agent_id=? AND revoked=0", id).Scan(&enrollment, &raw, &received)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		s.consoleError(w, "service inventory agent", err)
		return
	}
	var heartbeat managed.Heartbeat
	if err := json.Unmarshal(raw, &heartbeat); err != nil {
		// The current enrollment's stored data is unusable. Return the
		// inventory state without exposing that data in the response.
		heartbeat = managed.Heartbeat{}
	}
	respond(w, http.StatusOK, serviceInventoryResponse{
		serviceInventory: serviceInventoryFromHeartbeat(heartbeat, id, enrollment, time.Unix(0, received), s.now().UTC()),
		AgentID:          id,
		EnrollmentID:     enrollment,
	})
}
