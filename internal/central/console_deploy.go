package central

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

const previewDomain = "xe-antishell-central/console-deploy/v1\x00"
const previewMaxBytes = 512 << 10
const previewLifetime = 5 * time.Minute

type consolePreviewRequest struct {
	TemplateID string   `json:"template_id"`
	AgentIDs   []string `json:"agent_ids"`
	GroupIDs   []string `json:"group_ids"`
}

type consoleDeployTarget struct {
	AgentID          string   `json:"agent_id"`
	EnrollmentID     string   `json:"enrollment_id"`
	CurrentRevision  uint64   `json:"current_revision"`
	NextRevision     uint64   `json:"next_revision"`
	Warnings         []string `json:"warnings"`
	ServiceScopeHash string   `json:"service_scope_hash,omitempty"`

	listeningServices []string
}

type consolePreviewGroup struct {
	ID         string `json:"id"`
	Version    int64  `json:"version"`
	Generation string `json:"generation"`
	MemberHash string `json:"member_hash"`
}

type consolePreviewToken struct {
	Nonce              string                `json:"nonce"`
	IssuedAt           time.Time             `json:"issued_at"`
	ExpiresAt          time.Time             `json:"expires_at"`
	Request            consolePreviewRequest `json:"request"`
	TemplateVersion    int64                 `json:"template_version"`
	TemplateGeneration string                `json:"template_generation"`
	TemplateHash       string                `json:"template_hash"`
	Groups             []consolePreviewGroup `json:"groups"`
	Targets            []consoleDeployTarget `json:"targets"`
}

func consoleHash(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

// Snapshot reads every deployment dependency in one database transaction.
// Generation identifiers additionally reject delete/recreate (ABA) changes.
func consoleSnapshot(ctx context.Context, tx *sql.Tx, request consolePreviewRequest, now time.Time) (consolePreviewToken, ConsoleTemplate, error) {
	var snapshot consolePreviewToken
	if !identifierPattern.MatchString(request.TemplateID) {
		return snapshot, ConsoleTemplate{}, fmt.Errorf("%w: 정책 템플릿을 선택하세요", ErrInvalid)
	}
	var err error
	if request.AgentIDs, err = normalizedIDs(request.AgentIDs, consoleMaxTargets); err != nil {
		return snapshot, ConsoleTemplate{}, err
	}
	if request.GroupIDs, err = normalizedIDs(request.GroupIDs, 64); err != nil {
		return snapshot, ConsoleTemplate{}, err
	}
	template, err := loadConsoleTemplate(ctx, tx, request.TemplateID)
	if err != nil {
		return snapshot, template, err
	}
	if err = template.Settings.validate(); err != nil {
		return snapshot, template, err
	}
	snapshot.Request = request
	snapshot.TemplateVersion, snapshot.TemplateGeneration = template.Version, template.generation
	if snapshot.TemplateHash, err = consoleHash(template.Settings); err != nil {
		return snapshot, template, err
	}
	snapshot.Groups = []consolePreviewGroup{}
	snapshot.Targets = []consoleDeployTarget{}
	selected := make(map[string]bool)
	for _, id := range request.AgentIDs {
		selected[id] = true
	}
	for _, id := range request.GroupIDs {
		group, err := loadConsoleGroup(ctx, tx, id)
		if err != nil {
			return snapshot, template, err
		}
		hash, err := consoleHash(group.AgentIDs)
		if err != nil {
			return snapshot, template, err
		}
		snapshot.Groups = append(snapshot.Groups, consolePreviewGroup{ID: id, Version: group.Version, Generation: group.generation, MemberHash: hash})
		for _, agentID := range group.AgentIDs {
			selected[agentID] = true
		}
	}
	if len(selected) < 1 || len(selected) > consoleMaxTargets {
		return snapshot, template, fmt.Errorf("%w: 배포 대상은 1~1000대여야 합니다", ErrInvalid)
	}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var unsupported []string
	allListening := template.Settings.ServiceScope == serviceScopeAllListening
	for _, id := range ids {
		var target consoleDeployTarget
		var heartbeat []byte
		var seenNS int64
		target.AgentID = id
		err = tx.QueryRowContext(ctx, "SELECT enrollment_id,desired_policy_revision,heartbeat_json,last_seen_at_ns FROM agents WHERE agent_id=? AND revoked=0", id).Scan(&target.EnrollmentID, &target.CurrentRevision, &heartbeat, &seenNS)
		if errors.Is(err, sql.ErrNoRows) {
			return snapshot, template, ErrNotFound
		}
		if err != nil {
			return snapshot, template, err
		}
		if target.CurrentRevision >= math.MaxInt64 {
			return snapshot, template, fmt.Errorf("%w: 정책 revision이 최대값에 도달했습니다", ErrInvalid)
		}
		var report managed.Heartbeat
		settings := template.Settings
		checkSupport := requiresDetectionSupport(settings.Detection, settings.Applications)
		if allListening || checkSupport || settings.Response.Mode != "observe" {
			report = decodePolicyHeartbeat(heartbeat)
		}
		target.NextRevision = target.CurrentRevision + 1
		if allListening {
			inventory := serviceInventoryFromHeartbeat(report, id, target.EnrollmentID, time.Unix(0, seenNS).UTC(), now)
			target.listeningServices, err = inventory.deploymentServices()
			if err != nil {
				unsupported = append(unsupported, id+" · "+strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
				continue
			}
			target.ServiceScopeHash, err = consoleHash(target.listeningServices)
			if err != nil {
				return snapshot, template, err
			}
			settings = settings.withListeningServices(target.listeningServices)
			if err = validateConsoleWirePolicy(settings.wirePolicy(template.ID, id, target.EnrollmentID, target.NextRevision, now)); err != nil {
				unsupported = append(unsupported, id+" · "+strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
				continue
			}
		}
		if checkSupport {
			if err = checkDetectionSupport(settings.Detection, settings.Applications, report, target.AgentID, target.EnrollmentID, now); err != nil {
				unsupported = append(unsupported, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
				continue
			}
		}
		target.Warnings = warningsForApplications(settings, report, now)
		snapshot.Targets = append(snapshot.Targets, target)
	}
	if len(unsupported) > 0 {
		return snapshot, template, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(unsupported, " / "))
	}
	return snapshot, template, nil
}

func consolePending(settings ConsoleSettings) []string {
	return consolePendingWithMeasurement(settings, false)
}

func consolePendingWithMeasurement(settings ConsoleSettings, measured bool) []string {
	pending := []string{}
	if settings.Integrity.Enabled {
		pending = append(pending, "integrity")
	}
	if settings.Integrity.PackageFiles && !measured {
		pending = append(pending, "integrity.agent_files")
	}
	return pending
}

func warningsForSettings(settings ConsoleSettings, heartbeat managed.Heartbeat, now time.Time) []string {
	warnings := []string{}
	detection := settings.Detection
	checkResponse := settings.Response.Mode != "observe"
	checkAcceptance := detection.ExtendedProcessRules && settings.Response.Mode == "enforce"
	if checkResponse && detection.ExtendedProcessRules {
		message := "확장 규칙에서는 셸도 탐지 전용이어서 모의 대응 후보가 0개입니다."
		if settings.Response.Mode == "enforce" {
			message = "확장 규칙에서는 종료 후보가 0개입니다. 정책 수락에는 로컬 종료 허용과 pidfd가 필요합니다."
		}
		warnings = append(warnings, message)
		checkResponse = false
	}
	if settings.Integrity.Enabled {
		warnings = append(warnings, "무결성 설정은 저장되지만 현재 에이전트 프로토콜에서 지원하지 않아 적용 대기 중입니다")
	}
	checkScopes := detection.Enabled && detection.ServiceObservations != nil && len(*detection.ServiceObservations) > 0
	if !checkResponse && !checkScopes && !checkAcceptance {
		return warnings
	}
	if checkAcceptance {
		if warning := enforceAcceptanceWarning(heartbeat, now); warning != "" {
			warnings = append(warnings, warning)
		}
	}
	if checkScopes {
		warnings = append(warnings, serviceObservationWarnings(detection, heartbeat, now)...)
	}
	if !checkResponse {
		return warnings
	}
	if heartbeat.Status.CapabilityReport == nil {
		warnings = append(warnings, "인증된 기능 보고가 없어 대응 기능 지원 여부를 알 수 없습니다")
	} else {
		report := heartbeat.Status.CapabilityReport
		// ProbedAt describes passive discovery, which may predate a current
		// heartbeat by days. Delivery freshness is a separate operator warning.
		if heartbeat.SentAt.IsZero() || heartbeat.SentAt.Before(now.Add(-5*time.Minute)) || heartbeat.SentAt.After(now.Add(time.Minute)) {
			warnings = append(warnings, "하트비트가 오래되었거나 시각이 올바르지 않아 현재 대응 가능 여부를 다시 확인해야 합니다")
		}
		required := append([]string(nil), settings.Response.RequiredCapabilities...)
		if settings.Response.Mode == "enforce" {
			required = append(required, "observation.process_exec", "observation.process_lineage", "response.terminate")
			if heartbeat.Status.Collector != "tetragon-json" {
				warnings = append(warnings, "현재 자동 종료는 Tetragon 실행 이벤트에서만 지원합니다. 대상 서버의 수집기를 확인하세요")
			}
		}
		seen := make(map[string]bool, len(required))
		for _, name := range required {
			if seen[name] {
				continue
			}
			seen[name] = true
			capability, ok := report.Capabilities[name]
			// Match the agent's response gate: passive State and the age of a
			// non-nil VerifiedAt are not part of this predicate. The agent still
			// checks policy, event identity and local opt-in before any action.
			if ok && capability.Implementation == "implemented" && capability.RuntimeState == "active" && capability.VerifiedAt != nil {
				continue
			}
			if ok && name == "response.terminate" && capability.RuntimeState == "available" {
				warnings = append(warnings, "프로세스 종료 기능은 사용 가능하지만 에이전트 로컬 opt-in이 비활성화되어 있습니다")
			} else {
				warnings = append(warnings, "필수 기능의 실제 동작 검증이 확인되지 않았습니다: "+name)
			}
		}
	}
	if settings.Response.Mode == "enforce" {
		warnings = append(warnings, "실제 프로세스 종료에는 에이전트의 로컬 opt-in과 기능 검증이 필요합니다")
	}
	return warnings
}

func enforceAcceptanceWarning(heartbeat managed.Heartbeat, now time.Time) string {
	report := heartbeat.Status.CapabilityReport
	if report != nil && !heartbeat.SentAt.Before(now.Add(-2*time.Minute)) && !heartbeat.SentAt.After(now.Add(time.Minute)) {
		capability := report.Capabilities["response.terminate"]
		if capability.Implementation == "implemented" && capability.Provider == "pidfd" {
			switch {
			case capability.State == model.CapabilityUnsupported:
				return "호스트에서 pidfd를 지원하지 않아 종료 정책을 수락할 수 없습니다."
			case capability.State == model.CapabilitySupported && capability.RuntimeState == "available":
				return "에이전트 로컬 opt-in이 비활성화되어 종료 정책을 수락할 수 없습니다."
			case capability.State == model.CapabilitySupported && capability.RuntimeState == "active" &&
				capability.VerifiedAt != nil && !capability.VerifiedAt.IsZero() && !capability.VerifiedAt.After(heartbeat.SentAt.Add(time.Minute)):
				return ""
			}
		}
	}
	return "종료 정책 수락에 필요한 호스트 pidfd 지원·로컬 허용 상태가 미확인입니다."
}

// Only explicit scopes are known to Central. Receipts concern the host sensor,
// not the candidate service, path or destination.
func serviceObservationWarnings(detection managed.DetectionPolicy, heartbeat managed.Heartbeat, now time.Time) []string {
	var warnings, missing []string
	var file, network bool
	unmatched := 0
	for _, scope := range *detection.ServiceObservations {
		if !slices.Contains(detection.WebServices, scope.Service) {
			unmatched++
			continue
		}
		file = file || len(scope.ProtectedDirs) > 0
		network = network || len(scope.AllowedTCPDestinations) > 0
	}
	if unmatched > 0 {
		warnings = append(warnings, fmt.Sprintf("웹 서비스명 불일치로 관측 범위 %d개가 적용되지 않습니다.", unmatched))
	}
	received := func(name string) bool {
		report := heartbeat.Status.CapabilityReport
		if report == nil || heartbeat.Status.Collector != "tetragon-json" || heartbeat.SentAt.Before(now.Add(-2*time.Minute)) || heartbeat.SentAt.After(now.Add(time.Minute)) {
			return false
		}
		sensor := report.Capabilities[name]
		return sensor.Implementation == "implemented" && sensor.RuntimeState == "active" && sensor.VerifiedAt != nil &&
			!sensor.VerifiedAt.Before(now.Add(-5*time.Minute)) && !sensor.VerifiedAt.After(now.Add(time.Minute))
	}
	if file && !received("observation.file") {
		missing = append(missing, "파일 쓰기")
	}
	if network && !received("observation.network") {
		missing = append(missing, "TCP 연결")
	}
	if len(missing) != 0 {
		warnings = append(warnings, "최근 호스트 센서 수신 미확인 · "+strings.Join(missing, " / "))
	}
	return warnings
}

func (s *Server) encodeConsolePreview(snapshot consolePreviewToken) (string, error) {
	// Warnings describe the latest heartbeat and are recomputed on deploy.
	// Keep them in the HTTP response without repeating them in the signed token.
	snapshot.Targets = slices.Clone(snapshot.Targets)
	for i := range snapshot.Targets {
		snapshot.Targets[i].Warnings = nil
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	if len(body) > previewMaxBytes {
		return "", fmt.Errorf("%w: 미리보기 대상과 경고가 너무 많습니다", ErrInvalid)
	}
	signature := ed25519.Sign(s.material.PolicyKey, append([]byte(previewDomain), body...))
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Server) decodeConsolePreview(token string, now time.Time) (consolePreviewToken, error) {
	var snapshot consolePreviewToken
	if len(token) > base64.RawURLEncoding.EncodedLen(previewMaxBytes)+128 {
		return snapshot, ErrConflict
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return snapshot, ErrConflict
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(body) > previewMaxBytes {
		return snapshot, ErrConflict
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(s.material.PolicyKey.Public().(ed25519.PublicKey), append([]byte(previewDomain), body...), signature) {
		return snapshot, ErrConflict
	}
	if managed.DecodeStrict(body, previewMaxBytes, &snapshot) != nil || snapshot.Nonce == "" || snapshot.IssuedAt.IsZero() || snapshot.IssuedAt.After(now.Add(time.Minute)) || !now.Before(snapshot.ExpiresAt) || !snapshot.ExpiresAt.After(snapshot.IssuedAt) || snapshot.ExpiresAt.Sub(snapshot.IssuedAt) > previewLifetime {
		return consolePreviewToken{}, ErrConflict
	}
	return snapshot, nil
}

func (s *Server) consolePreview(w http.ResponseWriter, r *http.Request) {
	var request consolePreviewRequest
	if !consoleDecode(w, r, 256<<10, &request) {
		return
	}
	now := s.now().UTC()
	tx, err := s.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.consoleError(w, "preview transaction", err)
		return
	}
	defer tx.Rollback()
	snapshot, template, err := consoleSnapshot(r.Context(), tx, request, now)
	var current []consoleCurrentPolicy
	if err == nil {
		current, err = consoleCurrentPolicies(r.Context(), tx, snapshot.Targets)
	}
	_ = tx.Rollback()
	if err == nil {
		snapshot.Nonce, err = randomToken()
	}
	if err != nil {
		s.consoleError(w, "deployment preview", err)
		return
	}
	snapshot.IssuedAt, snapshot.ExpiresAt = now, now.Add(previewLifetime)
	token, err := s.encodeConsolePreview(snapshot)
	if err != nil {
		s.consoleError(w, "preview signing", err)
		return
	}
	response := map[string]any{"preview_token": token, "template": template, "targets": snapshot.Targets, "current_policies": current, "pending_features": consolePending(template.Settings)}
	if template.Settings.ServiceScope == serviceScopeAllListening {
		response["service_targets"] = consoleServiceTargetGroups(snapshot.Targets)
	}
	respond(w, http.StatusOK, response)
}

func sameConsoleSnapshot(before, after consolePreviewToken) bool {
	if before.TemplateVersion != after.TemplateVersion || before.TemplateGeneration != after.TemplateGeneration || before.TemplateHash != after.TemplateHash || len(before.Groups) != len(after.Groups) || len(before.Targets) != len(after.Targets) {
		return false
	}
	for index, group := range before.Groups {
		if group != after.Groups[index] {
			return false
		}
	}
	for index, target := range before.Targets {
		current := after.Targets[index]
		if target.AgentID != current.AgentID || target.EnrollmentID != current.EnrollmentID || target.CurrentRevision != current.CurrentRevision || target.NextRevision != current.NextRevision ||
			target.ServiceScopeHash != current.ServiceScopeHash {
			return false
		}
	}
	return true
}

func (s *Server) consoleDeploy(w http.ResponseWriter, r *http.Request) {
	var request struct {
		PreviewToken string `json:"preview_token"`
		Confirm      bool   `json:"confirm"`
	}
	if !consoleDecode(w, r, 1<<20, &request) {
		return
	}
	if !request.Confirm {
		s.consoleError(w, "deployment confirmation", fmt.Errorf("%w: 배포 확인이 필요합니다", ErrInvalid))
		return
	}
	now := s.now().UTC()
	before, err := s.decodeConsolePreview(request.PreviewToken, now)
	if err != nil {
		s.consoleError(w, "preview verification", err)
		return
	}
	tx, err := s.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.consoleError(w, "deployment transaction", err)
		return
	}
	defer tx.Rollback()
	after, template, err := consoleSnapshot(r.Context(), tx, before.Request, now)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) || err == nil && !sameConsoleSnapshot(before, after) {
		err = ErrConflict
	}
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "deployment snapshot", err)
		return
	}
	settings, err := json.Marshal(template.Settings)
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "deployment settings", err)
		return
	}
	for _, target := range after.Targets {
		effective := template.Settings.withListeningServices(target.listeningServices)
		policy := effective.wirePolicy(template.ID, target.AgentID, target.EnrollmentID, target.NextRevision, now)
		err = s.issueConsolePolicy(r.Context(), tx, policy, target.CurrentRevision, settings, now, map[string]any{"revision": target.NextRevision, "policy_id": policy.ID, "enrollment_id": target.EnrollmentID, "template_version": template.Version, "pending_features": consolePending(template.Settings)})
		if err != nil {
			_ = tx.Rollback()
			s.consoleError(w, "deployment assignment", err)
			return
		}
	}
	if err = appendAudit(r.Context(), tx, "", "console.policy.deployed", map[string]any{"template_id": template.ID, "template_version": template.Version, "target_count": len(after.Targets), "pending_features": consolePending(template.Settings)}, now); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "deployment commit", err)
		return
	}
	response := map[string]any{"targets": after.Targets, "pending_features": consolePending(template.Settings), "deployed_at": now}
	if template.Settings.ServiceScope == serviceScopeAllListening {
		response["service_targets"] = consoleServiceTargetGroups(after.Targets)
	}
	respond(w, http.StatusOK, response)
}
