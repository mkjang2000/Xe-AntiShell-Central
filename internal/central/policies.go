package central

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (s *Store) AssignPolicy(ctx context.Context, signed managed.SignedPolicy, now time.Time) error {
	policy := signed.Policy
	body, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enrollment string
	var current uint64
	var heartbeat []byte
	if err = tx.QueryRowContext(ctx, "SELECT enrollment_id,desired_policy_revision,heartbeat_json FROM agents WHERE agent_id=? AND revoked=0", policy.AgentID).Scan(&enrollment, &current, &heartbeat); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if enrollment != policy.EnrollmentID {
		return ErrUnauthorized
	}
	if policy.Revision <= current {
		var old []byte
		err = tx.QueryRowContext(ctx, "SELECT signed_json FROM policies WHERE agent_id=? AND enrollment_id=? AND revision=?", policy.AgentID, enrollment, policy.Revision).Scan(&old)
		if err == nil && bytes.Equal(old, body) {
			return nil
		}
		return ErrConflict
	}
	if err = requireDetectionPolicySupport(policy.Detection, policy.Applications, heartbeat, policy.AgentID, policy.EnrollmentID, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO policies(agent_id,enrollment_id,revision,signed_json) VALUES(?,?,?,?)", policy.AgentID, enrollment, policy.Revision, body); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE agents SET desired_policy_revision=? WHERE agent_id=?", policy.Revision, policy.AgentID); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, policy.AgentID, "policy.assigned", map[string]any{"revision": policy.Revision, "policy_id": policy.ID, "enrollment_id": enrollment}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LatestPolicy(ctx context.Context, agentID, enrollmentID string) (managed.SignedPolicy, error) {
	var body []byte
	err := s.db.QueryRowContext(ctx, "SELECT signed_json FROM policies WHERE agent_id=? AND enrollment_id=? ORDER BY revision DESC LIMIT 1", agentID, enrollmentID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return managed.SignedPolicy{}, ErrNotFound
	}
	if err != nil {
		return managed.SignedPolicy{}, err
	}
	var signed managed.SignedPolicy
	err = json.Unmarshal(body, &signed)
	return signed, err
}

func (s *Server) adminAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.Agents(r.Context())
	if err != nil {
		s.apiError(w, "agents", err)
		return
	}
	respond(w, http.StatusOK, agents)
}
func (s *Server) adminHistory(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.History(r.Context(), r.URL.Query().Get("agent_id"), r.URL.Query().Get("kind"), queryLimit(r))
	if err != nil {
		s.apiError(w, "history", err)
		return
	}
	respond(w, http.StatusOK, items)
}
func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.Audit(r.Context(), queryLimit(r))
	if err != nil {
		s.apiError(w, "audit", err)
		return
	}
	respond(w, http.StatusOK, items)
}
func queryLimit(r *http.Request) int {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return 100
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return number
}

func (s *Server) adminPolicy(w http.ResponseWriter, r *http.Request) {
	var policy managed.Policy
	if !decodeRequest(w, r, managed.MaxPolicyBytes, &policy) {
		return
	}
	now := s.now().UTC()
	signed, err := managed.SignPolicy(policy, s.material.PolicyKeyID, s.material.PolicyKey)
	if err != nil {
		s.apiError(w, "policy signing", ErrInvalid)
		return
	}
	if policy.IssuedAt.After(now.Add(time.Minute)) || !now.Before(policy.ExpiresAt) {
		s.apiError(w, "policy validity", ErrInvalid)
		return
	}
	if err = s.store.AssignPolicy(r.Context(), signed, now); err != nil {
		s.apiError(w, "policy assignment", err)
		return
	}
	respond(w, http.StatusCreated, signed)
}

type removalRequest struct {
	AgentID      string `json:"agent_id"`
	EnrollmentID string `json:"enrollment_id"`
	Challenge    string `json:"challenge"`
	TTLSeconds   int64  `json:"ttl_seconds"`
}

func (s *Server) adminRemoval(w http.ResponseWriter, r *http.Request) {
	var request removalRequest
	if !decodeRequest(w, r, 8<<10, &request) {
		return
	}
	tx, err := s.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.apiError(w, "removal transaction", err)
		return
	}
	defer tx.Rollback()
	var enrollment string
	err = tx.QueryRowContext(r.Context(), "SELECT enrollment_id FROM agents WHERE agent_id=? AND revoked=0", request.AgentID).Scan(&enrollment)
	if errors.Is(err, sql.ErrNoRows) {
		s.apiError(w, "removal target", ErrNotFound)
		return
	} else if err != nil {
		s.apiError(w, "removal target", err)
		return
	}
	if enrollment != request.EnrollmentID {
		s.apiError(w, "removal target", ErrUnauthorized)
		return
	}
	var policyBytes []byte
	err = tx.QueryRowContext(r.Context(), "SELECT signed_json FROM policies WHERE agent_id=? AND enrollment_id=? ORDER BY revision DESC LIMIT 1", request.AgentID, enrollment).Scan(&policyBytes)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.apiError(w, "removal policy", err)
		return
	}
	if err == nil {
		var policy managed.SignedPolicy
		if err = json.Unmarshal(policyBytes, &policy); err != nil {
			s.apiError(w, "removal policy decode", err)
			return
		}
		if policy.Policy.UninstallMode == "deny" {
			respond(w, http.StatusForbidden, map[string]string{"error": "assigned policy denies ordinary removal"})
			return
		}
	}
	if request.TTLSeconds == 0 {
		request.TTLSeconds = 300
	}
	if request.TTLSeconds < 1 || request.TTLSeconds > 900 {
		s.apiError(w, "removal lifetime", ErrInvalid)
		return
	}
	lifetime := time.Duration(request.TTLSeconds) * time.Second
	id, err := randomToken()
	if err != nil {
		s.apiError(w, "removal identifier", err)
		return
	}
	now := s.now().UTC()
	grant := managed.RemovalGrant{ID: id, AgentID: request.AgentID, EnrollmentID: enrollment, Challenge: request.Challenge, Action: "uninstall", IssuedAt: now, ExpiresAt: now.Add(lifetime)}
	signed, err := managed.SignRemovalGrant(grant, s.material.PolicyKeyID, s.material.PolicyKey)
	if err != nil {
		s.apiError(w, "removal signing", ErrInvalid)
		return
	}
	if err = appendAudit(r.Context(), tx, request.AgentID, "removal.authorized", map[string]any{"grant_id": id, "enrollment_id": enrollment, "challenge": request.Challenge, "expires_at": grant.ExpiresAt}, now); err != nil {
		s.apiError(w, "removal audit", err)
		return
	}
	if err = tx.Commit(); err != nil {
		s.apiError(w, "removal audit commit", err)
		return
	}
	respond(w, http.StatusCreated, signed)
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AgentID string `json:"agent_id"`
	}
	if !decodeRequest(w, r, 1024, &request) {
		return
	}
	if err := s.store.Revoke(r.Context(), request.AgentID, s.now().UTC()); err != nil {
		s.apiError(w, "revoke", err)
		return
	}
	respond(w, http.StatusOK, map[string]string{"result": "revoked"})
}
