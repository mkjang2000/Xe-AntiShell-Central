package central

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// Privilege policy fields must never be sent to old strict-decoding agents.
// Engine support is independent of actual credential-hook receipt: requiring
// receipt here would prevent activation of a newly installed sensor.
func requirePrivilegePolicySupport(detection managed.DetectionPolicy, body []byte, agentID, enrollmentID string, now time.Time) error {
	if !detection.PrivilegeRules {
		return nil
	}
	var heartbeat managed.Heartbeat
	if json.Unmarshal(body, &heartbeat) != nil || heartbeat.AgentID != agentID || heartbeat.EnrollmentID != enrollmentID || heartbeat.SentAt.IsZero() || heartbeat.SentAt.Before(now.Add(-2*time.Minute)) || heartbeat.SentAt.After(now.Add(time.Minute)) || heartbeat.Status.Collector != "tetragon-json" || heartbeat.Status.CapabilityReport == nil {
		return fmt.Errorf("%w: 전역 root·권한 변경 탐지는 현재 등록의 최신 Tetragon·엔진 지원 보고가 필요합니다. 에이전트를 먼저 업데이트하세요", ErrInvalid)
	}
	capability, ok := heartbeat.Status.CapabilityReport.Capabilities["detection.privilege_rules"]
	if !ok || capability.Implementation != "implemented" || (capability.RuntimeState != "available" && capability.RuntimeState != "active") || capability.Details["contract"] != "1" {
		return fmt.Errorf("%w: 전역 root·권한 변경 탐지를 지원하지 않는 에이전트입니다. 지원 계약1의 에이전트로 업데이트하세요", ErrInvalid)
	}
	return nil
}
