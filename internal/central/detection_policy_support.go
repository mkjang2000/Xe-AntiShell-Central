package central

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// A fresh engine contract is required for every optional wire extension.
// Observation receipts are tracked separately and may arrive after deployment.
func requireDetectionPolicySupport(detection managed.DetectionPolicy, body []byte, agentID, enrollmentID string, now time.Time) error {
	if !detection.PrivilegeRules && detection.ServiceObservations == nil && len(detection.ServiceRuleControls) == 0 {
		return nil
	}
	var heartbeat managed.Heartbeat
	if json.Unmarshal(body, &heartbeat) != nil || heartbeat.AgentID != agentID || heartbeat.EnrollmentID != enrollmentID || heartbeat.SentAt.IsZero() || heartbeat.SentAt.Before(now.Add(-2*time.Minute)) || heartbeat.SentAt.After(now.Add(time.Minute)) || heartbeat.Status.CapabilityReport == nil {
		return fmt.Errorf("%w: %s의 현재 등록에서 최신 정책 지원 보고를 확인할 수 없습니다", ErrInvalid, agentID)
	}
	supported := func(name string) bool {
		capability := heartbeat.Status.CapabilityReport.Capabilities[name]
		return capability.Implementation == "implemented" && (capability.RuntimeState == "available" || capability.RuntimeState == "active") && capability.Details["contract"] == "1"
	}
	if detection.PrivilegeRules && (heartbeat.Status.Collector != "tetragon-json" || !supported("detection.privilege_rules")) {
		return fmt.Errorf("%w: %s에서 전역 root·권한 변경 탐지 지원을 확인하세요", ErrInvalid, agentID)
	}
	if len(detection.ServiceRuleControls) > 0 && !supported("detection.service_rule_controls") {
		return fmt.Errorf("%w: %s에서 서비스별 규칙 제어·만료 예외 정책 지원을 확인하세요", ErrInvalid, agentID)
	}
	if detection.ServiceObservations != nil && !supported("detection.service_observations") {
		return fmt.Errorf("%w: %s에서 서비스별 파일·TCP 서명 정책 지원을 확인하세요", ErrInvalid, agentID)
	}
	return nil
}
