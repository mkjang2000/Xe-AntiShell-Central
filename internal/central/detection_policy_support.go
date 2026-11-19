package central

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// A fresh engine contract is required for every optional wire extension.
// Observation receipts are tracked separately and may arrive after deployment.
func requireDetectionPolicySupport(detection managed.DetectionPolicy, applications []managed.ApplicationPolicy, body []byte, agentID, enrollmentID string, now time.Time) error {
	if !requiresDetectionSupport(detection, applications) {
		return nil
	}
	return checkDetectionSupport(detection, applications, decodePolicyHeartbeat(body), agentID, enrollmentID, now)
}

func requiresDetectionSupport(d managed.DetectionPolicy, applications []managed.ApplicationPolicy) bool {
	return d.PrivilegeRules || d.ServiceObservations != nil || len(d.ServiceRuleControls) != 0 || len(applications) != 0
}

func decodePolicyHeartbeat(body []byte) managed.Heartbeat {
	var h managed.Heartbeat
	if json.Unmarshal(body, &h) != nil {
		return managed.Heartbeat{}
	}
	return h
}

func checkDetectionSupport(detection managed.DetectionPolicy, applications []managed.ApplicationPolicy, heartbeat managed.Heartbeat, agentID, enrollmentID string, now time.Time) error {
	if heartbeat.AgentID != agentID || heartbeat.EnrollmentID != enrollmentID || heartbeat.SentAt.IsZero() || heartbeat.SentAt.Before(now.Add(-2*time.Minute)) || heartbeat.SentAt.After(now.Add(time.Minute)) || heartbeat.Status.CapabilityReport == nil {
		return fmt.Errorf("%w: %s의 현재 등록에서 최신 정책 지원 보고를 확인할 수 없습니다", ErrInvalid, agentID)
	}
	supported := func(name string) bool {
		capability := heartbeat.Status.CapabilityReport.Capabilities[name]
		return capability.Implementation == "implemented" && (capability.RuntimeState == "available" || capability.RuntimeState == "active") && capability.Details["contract"] == "1"
	}
	if len(applications) != 0 && !supported(managed.ApplicationPoliciesCapability) {
		return fmt.Errorf("%w: %s에서 서비스별 독립 정책 지원을 확인하세요", ErrInvalid, agentID)
	}
	controls, scopes := len(detection.ServiceRuleControls) != 0, detection.ServiceObservations != nil
	for _, app := range applications {
		controls = controls || len(app.Detection.ServiceRuleControls) != 0
		scopes = scopes || app.Detection.ServiceObservations != nil
	}
	if detection.PrivilegeRules && (heartbeat.Status.Collector != "tetragon-json" || !supported("detection.privilege_rules")) {
		return fmt.Errorf("%w: %s에서 전역 root·권한 변경 탐지 지원을 확인하세요", ErrInvalid, agentID)
	}
	if controls && !supported("detection.service_rule_controls") {
		return fmt.Errorf("%w: %s에서 서비스별 규칙 제어·만료 예외 정책 지원을 확인하세요", ErrInvalid, agentID)
	}
	if scopes && !supported("detection.service_observations") {
		return fmt.Errorf("%w: %s에서 서비스별 파일·TCP 서명 정책 지원을 확인하세요", ErrInvalid, agentID)
	}
	return nil
}
