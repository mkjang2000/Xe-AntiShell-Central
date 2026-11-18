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
	"sort"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
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
	AgentID         string   `json:"agent_id"`
	EnrollmentID    string   `json:"enrollment_id"`
	CurrentRevision uint64   `json:"current_revision"`
	NextRevision    uint64   `json:"next_revision"`
	Warnings        []string `json:"warnings"`
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
	for _, id := range ids {
		var target consoleDeployTarget
		var heartbeat []byte
		target.AgentID = id
		err = tx.QueryRowContext(ctx, "SELECT enrollment_id,desired_policy_revision,heartbeat_json FROM agents WHERE agent_id=? AND revoked=0", id).Scan(&target.EnrollmentID, &target.CurrentRevision, &heartbeat)
		if errors.Is(err, sql.ErrNoRows) {
			return snapshot, template, ErrNotFound
		}
		if err != nil {
			return snapshot, template, err
		}
		if target.CurrentRevision >= math.MaxInt64 {
			return snapshot, template, fmt.Errorf("%w: 정책 revision이 최대값에 도달했습니다", ErrInvalid)
		}
		if err = requireDetectionPolicySupport(template.Settings.Detection, heartbeat, target.AgentID, target.EnrollmentID, now); err != nil {
			unsupported = append(unsupported, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
			continue
		}
		target.NextRevision = target.CurrentRevision + 1
		target.Warnings = consolePolicyWarnings(template.Settings, heartbeat, now)
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

func consolePolicyWarnings(settings ConsoleSettings, body []byte, now time.Time) []string {
	warnings := []string{}
	if settings.Integrity.Enabled {
		warnings = append(warnings, "무결성 설정은 저장되지만 현재 에이전트 프로토콜에서 지원하지 않아 적용 대기 중입니다")
	}
	if settings.Response.Mode == "observe" {
		return warnings
	}
	var heartbeat managed.Heartbeat
	if json.Unmarshal(body, &heartbeat) != nil || heartbeat.Status.CapabilityReport == nil {
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

func (s *Server) encodeConsolePreview(snapshot consolePreviewToken) (string, error) {
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
	respond(w, http.StatusOK, map[string]any{"preview_token": token, "template": template, "targets": snapshot.Targets, "pending_features": consolePending(template.Settings)})
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
		if target.AgentID != current.AgentID || target.EnrollmentID != current.EnrollmentID || target.CurrentRevision != current.CurrentRevision || target.NextRevision != current.NextRevision {
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
	for _, target := range after.Targets {
		policy := template.Settings.wirePolicy(template.ID, target.AgentID, target.EnrollmentID, target.NextRevision, now)
		var settings []byte
		settings, err = json.Marshal(template.Settings)
		if err == nil {
			err = s.issueConsolePolicy(r.Context(), tx, policy, target.CurrentRevision, settings, now, map[string]any{"revision": target.NextRevision, "policy_id": policy.ID, "enrollment_id": target.EnrollmentID, "template_version": template.Version, "pending_features": consolePending(template.Settings)})
		}
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
	respond(w, http.StatusOK, map[string]any{"targets": after.Targets, "pending_features": consolePending(template.Settings), "deployed_at": now})
}
