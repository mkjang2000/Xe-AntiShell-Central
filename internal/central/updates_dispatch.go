package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type updateJob struct {
	id, rollout, agent, enrollment, state string
	revision, sequence                    uint64
	expected                              managed.RPMPackage
	release                               managed.UpdateRelease
	plan, authorization, report           []byte
	expires                               int64
}

func loadUpdateJob(ctx context.Context, q updateReader, id string) (updateJob, error) {
	var job updateJob
	var expected, target []byte
	err := q.QueryRowContext(ctx, "SELECT id,rollout_id,agent_id,enrollment_id,revision,state,current_json,target_json,plan_json,authorization_json,report_json,report_sequence,expires_at_ns FROM update_jobs WHERE id=?", id).Scan(&job.id, &job.rollout, &job.agent, &job.enrollment, &job.revision, &job.state, &expected, &target, &job.plan, &job.authorization, &job.report, &job.sequence, &job.expires)
	if errors.Is(err, sql.ErrNoRows) {
		return job, ErrNotFound
	}
	if err != nil {
		return job, err
	}
	if err = json.Unmarshal(expected, &job.expected); err != nil {
		return job, err
	}
	err = json.Unmarshal(target, &job.release)
	return job, err
}

func currentUpdateHead(ctx context.Context, tx *sql.Tx, agent authenticatedAgent, job updateJob) error {
	var id string
	var revision uint64
	err := tx.QueryRowContext(ctx, "SELECT active_job_id,revision FROM update_heads WHERE agent_id=? AND enrollment_id=?", agent.ID, agent.EnrollmentID).Scan(&id, &revision)
	if err != nil || id != job.id || revision != job.revision || job.agent != agent.ID || job.enrollment != agent.EnrollmentID {
		return ErrConflict
	}
	return nil
}

func (s *Server) desiredUpdate(ctx context.Context, agent authenticatedAgent) ([]byte, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = currentUpdateAgent(ctx, tx, agent); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if err = expireUpdateJobs(ctx, tx, now); err != nil {
		return nil, err
	}
	var id string
	err = tx.QueryRowContext(ctx, "SELECT active_job_id FROM update_heads WHERE agent_id=? AND enrollment_id=?", agent.ID, agent.EnrollmentID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) || err == nil && id == "" {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	job, err := loadUpdateJob(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = currentUpdateHead(ctx, tx, agent, job); err != nil {
		return nil, err
	}
	if job.state != "queued" {
		if updateTerminal(job.state) || job.expires <= now.UnixNano() {
			return nil, tx.Commit()
		}
		return job.plan, tx.Commit()
	}
	var concurrent, limit, cancelled int
	err = tx.QueryRowContext(ctx, "SELECT concurrency,cancelled FROM update_rollouts WHERE id=?", job.rollout).Scan(&limit, &cancelled)
	if err != nil {
		return nil, err
	}
	if cancelled != 0 {
		return nil, tx.Commit()
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM update_jobs WHERE rollout_id=? AND state IN ('offered','downloading','ready','installing')", job.rollout).Scan(&concurrent); err != nil {
		return nil, err
	}
	if concurrent >= limit {
		return nil, tx.Commit()
	}
	// A local package/configuration change since preview must never be silently
	// absorbed into a newly issued expected-from precondition.
	var inventoryBody []byte
	err = tx.QueryRowContext(ctx, "SELECT inventory_json FROM update_inventory WHERE agent_id=? AND enrollment_id=?", agent.ID, agent.EnrollmentID).Scan(&inventoryBody)
	var inventory managed.UpdateInventory
	if err != nil || json.Unmarshal(inventoryBody, &inventory) != nil || inventory.Validate() != nil || !inventory.Enabled || !inventory.Supported || inventory.InstalledPackage == nil || *inventory.InstalledPackage != job.expected || inventory.OSFamily != job.release.OSFamily || inventory.OSMajor != job.release.OSMajor || inventory.Arch != job.release.Package.Arch {
		if _, err = tx.ExecContext(ctx, "UPDATE update_jobs SET state='failed',error_code='precondition_changed' WHERE id=?", id); err != nil {
			return nil, err
		}
		if err = expireUpdateJobs(ctx, tx, now); err != nil {
			return nil, err
		}
		return nil, tx.Commit()
	}
	plan := managed.UpdatePlan{ProtocolVersion: managed.UpdateProtocolVersion, JobID: job.id, RolloutID: job.rollout, AgentID: agent.ID, EnrollmentID: agent.EnrollmentID, Revision: job.revision, IssuedAt: now, ExpiresAt: now.Add(updatePlanTTL), Release: job.release, ExpectedPackage: job.expected}
	signed, err := managed.SignUpdatePlan(plan, s.material.PolicyKeyID, s.material.PolicyKey)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE update_jobs SET state='offered',plan_json=?,expires_at_ns=? WHERE id=? AND state='queued'", body, plan.ExpiresAt.UnixNano(), job.id)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return body, nil
}

func (s *Server) claimUpdate(ctx context.Context, agent authenticatedAgent, claim managed.UpdateClaim) ([]byte, error) {
	if claim.Validate() != nil || claim.EnrollmentID != agent.EnrollmentID {
		return nil, ErrInvalid
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = currentUpdateAgent(ctx, tx, agent); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if err = expireUpdateJobs(ctx, tx, now); err != nil {
		return nil, err
	}
	job, err := loadUpdateJob(ctx, tx, claim.JobID)
	if err != nil {
		return nil, err
	}
	if err = currentUpdateHead(ctx, tx, agent, job); err != nil || job.revision != claim.Revision {
		return nil, ErrConflict
	}
	if job.expires <= now.UnixNano() {
		return nil, ErrConflict
	}
	if len(job.authorization) > 0 {
		var signed managed.SignedUpdateAuthorization
		if json.Unmarshal(job.authorization, &signed) != nil || !now.Before(signed.Authorization.ExpiresAt) {
			return nil, ErrConflict
		}
		return job.authorization, tx.Commit()
	}
	if job.state != "ready" {
		return nil, ErrConflict
	}
	var plan managed.SignedUpdatePlan
	if json.Unmarshal(job.plan, &plan) != nil {
		return nil, ErrConflict
	}
	digest, err := managed.UpdatePlanDigest(plan.Plan)
	if err != nil {
		return nil, err
	}
	expires := now.Add(updateClaimTTL)
	if expires.After(plan.Plan.ExpiresAt) {
		expires = plan.Plan.ExpiresAt
	}
	auth := managed.UpdateAuthorization{ProtocolVersion: managed.UpdateProtocolVersion, JobID: job.id, AgentID: agent.ID, EnrollmentID: agent.EnrollmentID, Revision: job.revision, PlanSHA256: digest, IssuedAt: now, ExpiresAt: expires}
	signed, err := managed.SignUpdateAuthorization(auth, s.material.PolicyKeyID, s.material.PolicyKey)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(signed)
	if _, err = tx.ExecContext(ctx, "UPDATE update_jobs SET state='installing',authorization_json=?,install_deadline_ns=? WHERE id=?", body, now.Add(updateInstallTimeout).UnixNano(), job.id); err != nil {
		return nil, err
	}
	if err = appendAudit(ctx, tx, agent.ID, "update.install.authorized", map[string]any{"job_id": job.id, "revision": job.revision}, now); err != nil {
		return nil, err
	}
	return body, tx.Commit()
}
