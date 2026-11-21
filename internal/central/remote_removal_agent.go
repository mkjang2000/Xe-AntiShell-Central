package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const remoteRemovalRequestBytes = 4 << 10

func (s *Server) agentRemoteRemoval(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	body, err := s.desiredRemoteRemoval(r.Context(), agent)
	if err != nil {
		s.apiError(w, "remote removal order", err)
		return
	}
	if len(body) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Server) desiredRemoteRemoval(ctx context.Context, agent authenticatedAgent) ([]byte, error) {
	now := s.now().UTC()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	state, err := loadRemoteRemovalTarget(ctx, tx, agent.ID, now)
	if err != nil {
		return nil, err
	}
	if state.EnrollmentID != agent.EnrollmentID || state.Reason == "revoked" {
		return nil, nil
	}
	job, err := remoteRemovalOrder(ctx, tx, agent, "")
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !now.Before(job.ExpiresAt) || job.State != "queued" && job.State != "claimed" {
		return nil, nil
	}
	reason, err := s.remoteRemovalActorDenial(ctx, tx, job.OrderID, state.SiteID)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return nil, cancelChangedRemoteRemoval(ctx, tx, agent, job, reason, now)
	}
	if state.Reason != "" {
		return nil, nil
	}
	return job.order, nil
}

func (s *Server) agentRemoteRemovalClaim(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	var claim managed.RemoteRemovalClaim
	if !decodeRequest(w, r, remoteRemovalRequestBytes, &claim) {
		return
	}
	body, err := s.claimRemoteRemoval(r.Context(), agent, claim)
	if err != nil {
		s.apiError(w, "remote removal claim", err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Server) claimRemoteRemoval(ctx context.Context, agent authenticatedAgent, claim managed.RemoteRemovalClaim) ([]byte, error) {
	if claim.Validate() != nil {
		return nil, ErrInvalid
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	state, err := loadRemoteRemovalTarget(ctx, tx, agent.ID, now)
	if err != nil {
		return nil, err
	}
	if state.EnrollmentID != agent.EnrollmentID || state.Reason == "revoked" {
		return nil, ErrUnauthorized
	}
	job, err := remoteRemovalOrder(ctx, tx, agent, claim.OrderID)
	if err != nil {
		return nil, err
	}
	if !now.Before(job.ExpiresAt) {
		return nil, ErrConflict
	}
	reason, err := s.remoteRemovalActorDenial(ctx, tx, job.OrderID, state.SiteID)
	if err != nil {
		return nil, err
	}
	if reason != "" {
		if err := cancelChangedRemoteRemoval(ctx, tx, agent, job, reason, now); err != nil {
			return nil, err
		}
		return nil, ErrUnauthorized
	}
	if state.Reason != "" {
		return nil, ErrUnauthorized
	}
	switch job.State {
	case "claimed":
		var previous managed.SignedRemovalGrant
		if err := json.Unmarshal(job.grant, &previous); err != nil {
			return nil, err
		}
		if job.operationID != claim.OperationID || previous.Grant.Challenge != claim.Challenge {
			return nil, ErrConflict
		}
		return job.grant, nil
	case "queued":
	default:
		return nil, ErrConflict
	}
	grant := managed.RemovalGrant{
		ID: job.OrderID, AgentID: agent.ID, EnrollmentID: agent.EnrollmentID, Challenge: claim.Challenge,
		Action: "uninstall", IssuedAt: now, ExpiresAt: job.ExpiresAt,
	}
	signed, err := managed.SignRemovalGrant(grant, s.material.PolicyKeyID, s.material.PolicyKey)
	if err != nil {
		return nil, ErrInvalid
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE remote_removal_orders SET state='claimed',operation_id=?,grant_json=?,updated_at_ns=?
 WHERE id=? AND state='queued'`, claim.OperationID, body, now.UnixNano(), job.OrderID); err != nil {
		return nil, err
	}
	job.State = "claimed"
	if err = appendRemoteRemovalAudit(ctx, tx, agent, job, "", now); err != nil {
		return nil, err
	}
	return body, tx.Commit()
}

func (s *Server) agentRemoteRemovalReport(w http.ResponseWriter, r *http.Request) {
	agent, serial, reason := verifiedAgentIdentity(r)
	if reason != "" {
		respond(w, http.StatusUnauthorized, map[string]string{"error": reason})
		return
	}
	var report managed.RemoteRemovalReport
	if !decodeRequest(w, r, remoteRemovalRequestBytes, &report) {
		return
	}
	if err := s.recordRemoteRemovalReport(r.Context(), agent, serial, report); err != nil {
		s.apiError(w, "remote removal report", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) recordRemoteRemovalReport(ctx context.Context, agent authenticatedAgent, serial string, report managed.RemoteRemovalReport) error {
	if report.Validate() != nil {
		return ErrInvalid
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT revoked FROM agents WHERE agent_id=? AND enrollment_id=? AND cert_serial=?`,
		agent.ID, agent.EnrollmentID, serial).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if revoked && report.State != "succeeded" {
		return ErrUnauthorized
	}
	job, err := remoteRemovalOrder(ctx, tx, agent, report.OrderID)
	if revoked {
		// This single route accepts an exact replay of a recorded success so
		// the worker can resolve a lost HTTP reply after atomic revocation.
		if err == nil && job.State == "succeeded" && job.Code == report.Code {
			return nil
		}
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if job.expiredBeforeStart(now) {
		// Acknowledge a terminal local journal without changing the expired
		// order or a newer order for this same enrollment.
		if report.State == "failed" {
			return nil
		}
		return ErrConflict
	}
	if report.State == "started" {
		if err := s.checkRemoteRemovalStart(ctx, tx, agent, now, job); err != nil {
			return err
		}
	}
	if job.State == report.State && job.Code == report.Code {
		return nil
	}
	switch report.State {
	case "started":
		if job.State != "claimed" {
			return ErrConflict
		}
	case "succeeded":
		if job.State != "started" {
			return ErrConflict
		}
	case "failed":
		if job.State != "queued" && job.State != "claimed" && job.State != "started" {
			return ErrConflict
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE remote_removal_orders SET state=?,code=?,updated_at_ns=?,grant_json=NULL WHERE id=?`,
		report.State, report.Code, now.UnixNano(), report.OrderID); err != nil {
		return err
	}
	job.State, job.Code = report.State, report.Code
	if err = appendRemoteRemovalAudit(ctx, tx, agent, job, "", now); err != nil {
		return err
	}
	if report.State == "succeeded" {
		result, err := tx.ExecContext(ctx, `UPDATE agents SET revoked=1 WHERE agent_id=? AND enrollment_id=? AND cert_serial=? AND revoked=0`,
			agent.ID, agent.EnrollmentID, serial)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrConflict
		}
		if err = appendAudit(ctx, tx, agent.ID, "agent.revoked",
			map[string]string{"enrollment_id": agent.EnrollmentID, "order_id": job.OrderID, "reason": "remote_removal_succeeded"}, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Server) checkRemoteRemovalStart(ctx context.Context, tx *sql.Tx, agent authenticatedAgent, now time.Time, job *remoteRemovalJob) error {
	if !now.Before(job.ExpiresAt) {
		return ErrConflict
	}
	state, err := loadRemoteRemovalTarget(ctx, tx, agent.ID, now)
	if err != nil {
		return err
	}
	if state.EnrollmentID != agent.EnrollmentID || state.Reason == "revoked" {
		return ErrUnauthorized
	}
	reason, err := s.remoteRemovalActorDenial(ctx, tx, job.OrderID, state.SiteID)
	if err != nil {
		return err
	}
	if reason != "" {
		if err := cancelChangedRemoteRemoval(ctx, tx, agent, job, reason, now); err != nil {
			return err
		}
		return ErrUnauthorized
	}
	if state.Reason != "" {
		return ErrUnauthorized
	}
	return nil
}
