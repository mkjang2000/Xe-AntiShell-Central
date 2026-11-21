package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const agentConfigurationPreviewDomain = "xe-antishell-central/agent-configuration-preview/v1\x00"

type agentConfigurationRequest struct {
	AgentIDs []string                      `json:"agent_ids"`
	Set      managed.AgentConfigurationSet `json:"set"`
	Inherit  []string                      `json:"inherit,omitempty"`
}

type agentConfigurationConfirmation struct {
	PreviewToken              string `json:"preview_token"`
	Confirm                   bool   `json:"confirm"`
	ApproveRetentionReduction bool   `json:"approve_retention_reduction"`
}

func (request *agentConfigurationRequest) UnmarshalJSON(body []byte) error {
	type decodedRequest agentConfigurationRequest
	return decodeAgentConfigurationConsoleObject(body, (*decodedRequest)(request), "agent_ids", "set", "inherit")
}

func (request *agentConfigurationConfirmation) UnmarshalJSON(body []byte) error {
	type decodedConfirmation agentConfigurationConfirmation
	return decodeAgentConfigurationConsoleObject(body, (*decodedConfirmation)(request), "preview_token", "confirm", "approve_retention_reduction")
}

func decodeAgentConfigurationConsoleObject(body []byte, output any, keys ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(keys))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !slices.Contains(keys, key) || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return ErrInvalid
		}
	}
	return managed.DecodeStrict(body, len(body), output)
}

type agentConfigurationTarget struct {
	AgentID            string                              `json:"agent_id"`
	EnrollmentID       string                              `json:"enrollment_id"`
	DesiredRevision    uint64                              `json:"desired_revision"`
	AppliedRevision    uint64                              `json:"applied_revision"`
	NextRevision       uint64                              `json:"next_revision"`
	Effective          managed.AgentConfigurationEffective `json:"effective"`
	RetentionReduction bool                                `json:"retention_reduction"`
	RetentionImpact    *agentConfigurationRetentionImpact  `json:"retention_impact,omitempty"`
	assignment         managed.AgentConfiguration
}

type agentConfigurationPreview struct {
	Actor      string                    `json:"actor"`
	IssuedAt   time.Time                 `json:"issued_at"`
	ExpiresAt  time.Time                 `json:"expires_at"`
	Request    agentConfigurationRequest `json:"request"`
	TargetHash string                    `json:"target_hash"`
}

func (s *Server) authorizeAgentConfiguration(w http.ResponseWriter, r *http.Request) (console.Account, bool) {
	account, ok := console.AuthenticatedAccount(r.Context())
	permission := console.PermissionAgentConfigurationWrite
	if r.Method == http.MethodGet {
		permission = console.PermissionAgentConfigurationRead
	}
	if !ok || !account.Can(permission, selectedSite(r.Context())) {
		s.consoleError(w, "agent configuration authorization", ErrUnauthorized)
		return console.Account{}, false
	}
	return account, true
}

func (s *Server) consoleAgentConfiguration(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAgentConfiguration(w, r); !ok {
		return
	}
	ctx := r.Context()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		s.consoleError(w, "agent configuration state transaction", err)
		return
	}
	defer tx.Rollback()
	state, err := loadAgentConfigurationState(ctx, tx, r.PathValue("id"), s.now().UTC())
	if err != nil {
		s.consoleError(w, "agent configuration state", err)
		return
	}
	_ = tx.Rollback()
	respond(w, http.StatusOK, state)
}

func prepareAgentConfiguration(ctx context.Context, tx *sql.Tx, request agentConfigurationRequest, now time.Time) ([]agentConfigurationTarget, bool, error) {
	if request.Set.Monitoring == nil && request.Set.Retention == nil && request.Set.LocalPanel == nil && len(request.Inherit) == 0 {
		return nil, false, fmt.Errorf("%w: 변경할 원격 설정이 없습니다", ErrInvalid)
	}
	if err := managed.ValidateAgentConfigurationChanges(request.Set, request.Inherit); err != nil {
		return nil, false, fmt.Errorf("%w: 원격 설정 값이나 상속 항목을 확인하세요", ErrInvalid)
	}
	if len(request.AgentIDs) == 0 {
		return nil, false, fmt.Errorf("%w: 원격 설정 대상 에이전트를 선택하세요", ErrInvalid)
	}
	targets := make([]agentConfigurationTarget, 0, len(request.AgentIDs))
	reduces := false
	for _, id := range request.AgentIDs {
		if err := requireAgentSite(ctx, tx, id); err != nil {
			return nil, false, err
		}
		state, err := loadAgentConfigurationState(ctx, tx, id, now)
		if err != nil {
			return nil, false, err
		}
		if !state.Supported || !state.Fresh || state.Report == nil {
			return nil, false, fmt.Errorf("%w: %s에서 현재 등록의 최신 원격 설정 보고를 확인하세요", ErrInvalid, id)
		}
		if state.AssignmentState == "pending" {
			return nil, false, fmt.Errorf("%w: %s에 아직 적용되지 않은 원격 설정이 있습니다", ErrInvalid, id)
		}
		report := state.Report
		if report.RequestedRevision > state.DesiredRevision || state.DesiredRevision >= math.MaxInt64 {
			return nil, false, ErrConflict
		}
		previous, err := assignedAgentConfiguration(ctx, tx, state.AgentID, state.EnrollmentID, report.AppliedRevision)
		if err != nil {
			return nil, false, err
		}
		set, inherit, err := managed.MergeAgentConfiguration(previous.Set, previous.Inherit, request.Set, request.Inherit)
		if err != nil {
			return nil, false, err
		}
		effective := report.Effective
		if set.Retention != nil && set.Retention.ObservationHistoryMinutes > effective.MaxObservationHistoryMinutes {
			return nil, false, fmt.Errorf("%w: %s의 로컬 관측 보존 상한을 초과합니다", ErrInvalid, id)
		}
		target := agentConfigurationTarget{
			AgentID: id, EnrollmentID: state.EnrollmentID, DesiredRevision: state.DesiredRevision,
			AppliedRevision: report.AppliedRevision, NextRevision: state.DesiredRevision + 1, Effective: effective,
		}
		target.RetentionImpact = estimateAgentRetention(state.heartbeat, effective, set, inherit, now)
		target.RetentionReduction = target.RetentionImpact != nil
		t := managed.AgentConfiguration{
			SchemaVersion: managed.SchemaVersion, AgentID: id, EnrollmentID: state.EnrollmentID,
			BaseRevision: report.AppliedRevision, Revision: target.NextRevision,
			IssuedAt: now, ExpiresAt: now.Add(agentConfigurationLifetime), Set: set, Inherit: inherit,
		}
		target.assignment = t
		reduces = reduces || target.RetentionReduction
		targets = append(targets, target)
	}
	return targets, reduces, nil
}

// Expiry estimates may move as more observations arrive. Bind the effective
// settings, identities and revisions used to authorize the change.
func hashAgentConfigurationTargets(targets []agentConfigurationTarget) (string, error) {
	witness := slices.Clone(targets)
	for i := range witness {
		witness[i].RetentionImpact = nil
	}
	return consoleHash(witness)
}

func (s *Server) encodeAgentConfigurationPreview(snapshot agentConfigurationPreview) (string, error) {
	body, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	if len(body) > previewMaxBytes {
		return "", ErrInvalid
	}
	sig := ed25519.Sign(s.material.PolicyKey, append([]byte(agentConfigurationPreviewDomain), body...))
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Server) decodeAgentConfigurationPreview(token, actor string, now time.Time) (agentConfigurationPreview, error) {
	var snapshot agentConfigurationPreview
	if len(token) > base64.RawURLEncoding.EncodedLen(previewMaxBytes)+128 {
		return snapshot, ErrConflict
	}
	body64, sign64, ok := strings.Cut(token, ".")
	if !ok {
		return snapshot, ErrConflict
	}
	body, err := base64.RawURLEncoding.DecodeString(body64)
	sig, sigErr := base64.RawURLEncoding.DecodeString(sign64)
	if err != nil || sigErr != nil || len(body) > previewMaxBytes ||
		!ed25519.Verify(s.material.PolicyKey.Public().(ed25519.PublicKey), append([]byte(agentConfigurationPreviewDomain), body...), sig) {
		return snapshot, ErrConflict
	}
	if managed.DecodeStrict(body, previewMaxBytes, &snapshot) != nil || snapshot.Actor != actor ||
		snapshot.IssuedAt.IsZero() || snapshot.IssuedAt.After(now.Add(time.Minute)) || !snapshot.ExpiresAt.Equal(snapshot.IssuedAt.Add(previewLifetime)) || !now.Before(snapshot.ExpiresAt) {
		return agentConfigurationPreview{}, ErrConflict
	}
	return snapshot, nil
}

func (s *Server) consoleAgentConfigurationPreview(w http.ResponseWriter, r *http.Request) {
	account, ok := s.authorizeAgentConfiguration(w, r)
	if !ok {
		return
	}
	var request agentConfigurationRequest
	if !consoleDecode(w, r, previewMaxBytes, &request) {
		return
	}
	ids, err := normalizedIDs(request.AgentIDs, consoleMaxTargets)
	if err != nil {
		s.consoleError(w, "agent configuration targets", err)
		return
	}
	request.AgentIDs = ids
	ctx, now := r.Context(), s.now().UTC()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		s.consoleError(w, "agent configuration preview transaction", err)
		return
	}
	defer tx.Rollback()
	targets, reduces, err := prepareAgentConfiguration(ctx, tx, request, now)
	_ = tx.Rollback()
	if err != nil {
		s.consoleError(w, "agent configuration preview", err)
		return
	}
	digest, err := hashAgentConfigurationTargets(targets)
	if err != nil {
		s.consoleError(w, "agent configuration preview digest", err)
		return
	}
	expires := now.Add(previewLifetime)
	token, err := s.encodeAgentConfigurationPreview(agentConfigurationPreview{
		Actor: account.Username, IssuedAt: now, ExpiresAt: expires, Request: request, TargetHash: digest,
	})
	if err != nil {
		s.consoleError(w, "agent configuration preview signing", err)
		return
	}
	respond(w, http.StatusOK, map[string]any{
		"preview_token": token, "expires_at": expires, "targets": targets, "retention_reduction_required": reduces,
	})
}

func (s *Server) consoleAgentConfigurationApply(w http.ResponseWriter, r *http.Request) {
	account, ok := s.authorizeAgentConfiguration(w, r)
	if !ok {
		return
	}
	var request agentConfigurationConfirmation
	if !consoleDecode(w, r, 1<<20, &request) {
		return
	}
	if !request.Confirm {
		s.consoleError(w, "agent configuration confirmation", fmt.Errorf("%w: 원격 설정 배포 확인이 필요합니다", ErrInvalid))
		return
	}
	ctx, now := r.Context(), s.now().UTC()
	preview, err := s.decodeAgentConfigurationPreview(request.PreviewToken, account.Username, now)
	if err != nil {
		s.consoleError(w, "agent configuration confirmation", err)
		return
	}
	targets, err := s.issueAgentConfiguration(ctx, preview, request.ApproveRetentionReduction, now)
	if err != nil {
		s.consoleError(w, "agent configuration assignment", err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"targets": targets, "issued_at": now})
}

func (s *Server) issueAgentConfiguration(ctx context.Context, preview agentConfigurationPreview, approve bool, now time.Time) ([]agentConfigurationTarget, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	targets, reduces, err := prepareAgentConfiguration(ctx, tx, preview.Request, now)
	if errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotFound) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	digest, err := hashAgentConfigurationTargets(targets)
	if err != nil {
		return nil, err
	}
	if preview.TargetHash != digest {
		return nil, ErrConflict
	}
	if reduces && !approve {
		return nil, fmt.Errorf("%w: 관측 보존 단축에 별도 동의가 필요합니다", ErrInvalid)
	}
	for _, target := range targets {
		cfg := target.assignment
		cfg.RetentionReductionApproved = target.RetentionReduction && approve
		signed, err := managed.SignAgentConfiguration(cfg, s.material.PolicyKeyID, s.material.PolicyKey)
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(signed)
		if err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO agent_configurations(agent_id,enrollment_id,revision,signed_json,expires_at_ns) VALUES(?,?,?,?,?)`,
			cfg.AgentID, cfg.EnrollmentID, cfg.Revision, body, cfg.ExpiresAt.UnixNano()); err != nil {
			return nil, err
		}
		if err = appendAudit(ctx, tx, target.AgentID, "agent_configuration.assigned", map[string]any{
			"actor": preview.Actor, "enrollment_id": cfg.EnrollmentID, "revision": cfg.Revision, "base_revision": cfg.BaseRevision,
			"set": cfg.Set, "inherit": cfg.Inherit, "retention_reduction_approved": cfg.RetentionReductionApproved,
		}, now); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return targets, nil
}
