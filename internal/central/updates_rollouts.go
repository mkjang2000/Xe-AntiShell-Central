package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func (s *Server) confirmUpdate(ctx context.Context, actor, clientID, token string) (string, error) {
	if !identifierPattern.MatchString(clientID) || len(token) > base64PreviewLimit() {
		return "", ErrInvalid
	}
	requestKey := actor + ":" + clientID
	tokenHash, _ := consoleHash(token)
	s.updateBlobs.mu.Lock()
	defer s.updateBlobs.mu.Unlock()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var oldID, oldHash string
	err = tx.QueryRowContext(ctx, "SELECT id,snapshot_hash FROM update_rollouts WHERE request_key=?", requestKey).Scan(&oldID, &oldHash)
	if err == nil {
		if oldHash != tokenHash {
			return "", ErrConflict
		}
		return oldID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	now := s.now().UTC()
	before, err := s.decodeUpdatePreview(token, now)
	if err != nil {
		return "", err
	}
	if err = expireUpdateJobs(ctx, tx, now); err != nil {
		return "", err
	}
	after, release, err := updateSnapshot(ctx, tx, before.Request, now)
	if err != nil || !sameUpdateSnapshot(before, after) {
		return "", ErrConflict
	}
	eligible := 0
	for _, target := range after.Targets {
		if target.Eligible {
			eligible++
		}
	}
	if eligible == 0 {
		return "", ErrInvalid
	}
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	id = "rollout-" + id
	_, err = tx.ExecContext(ctx, "INSERT INTO update_rollouts(id,release_id,created_by,created_at_ns,expires_at_ns,concurrency,request_key,snapshot_hash) VALUES(?,?,?,?,?,?,?,?)", id, release.ID, actor, now.UnixNano(), now.Add(updateQueueTTL).UnixNano(), after.Request.Concurrency, requestKey, tokenHash)
	if err != nil {
		return "", err
	}
	targetBody, _ := json.Marshal(release.UpdateRelease)
	for _, target := range after.Targets {
		if !target.Eligible {
			continue
		}
		job, err := randomToken()
		if err != nil {
			return "", err
		}
		job = "job-" + job
		currentBody, _ := json.Marshal(target.CurrentPackage)
		if _, err = tx.ExecContext(ctx, "INSERT INTO update_heads(agent_id,enrollment_id) VALUES(?,?) ON CONFLICT DO NOTHING", target.AgentID, target.EnrollmentID); err != nil {
			return "", err
		}
		result, err := tx.ExecContext(ctx, "UPDATE update_heads SET revision=?,active_job_id=? WHERE agent_id=? AND enrollment_id=? AND revision=? AND active_job_id=''", target.CurrentRevision+1, job, target.AgentID, target.EnrollmentID, target.CurrentRevision)
		if err != nil {
			return "", err
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return "", ErrConflict
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO update_jobs(id,rollout_id,agent_id,enrollment_id,revision,state,current_json,target_json,expires_at_ns) VALUES(?,?,?,?,?,'queued',?,?,?)", job, id, target.AgentID, target.EnrollmentID, target.CurrentRevision+1, currentBody, targetBody, now.Add(updateQueueTTL).UnixNano())
		if err != nil {
			return "", err
		}
	}
	if err = appendAudit(ctx, tx, "", "update.rollout.created", map[string]any{"rollout_id": id, "actor": actor, "release_id": release.ID, "eligible": eligible, "excluded": len(after.Targets) - eligible}, now); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func base64PreviewLimit() int { return (previewMaxBytes+2)/3*4 + 128 }

func (s *Server) cancelUpdate(ctx context.Context, id, actor string) (int, int, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if err = expireUpdateJobs(ctx, tx, s.now().UTC()); err != nil {
		return 0, 0, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE update_rollouts SET cancelled=1 WHERE id=?", id)
	if err != nil {
		return 0, 0, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return 0, 0, ErrNotFound
	}
	var installing int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM update_jobs WHERE rollout_id=? AND state='installing'", id).Scan(&installing); err != nil {
		return 0, 0, err
	}
	result, err = tx.ExecContext(ctx, "UPDATE update_jobs SET state='cancelled' WHERE rollout_id=? AND authorization_json IS NULL AND state IN ('queued','offered','downloading','ready')", id)
	if err != nil {
		return 0, 0, err
	}
	cancelled, _ := result.RowsAffected()
	if err = expireUpdateJobs(ctx, tx, s.now().UTC()); err != nil {
		return 0, 0, err
	}
	if err = appendAudit(ctx, tx, "", "update.rollout.cancelled", map[string]any{"rollout_id": id, "actor": actor, "cancelled": cancelled, "installing": installing}, s.now().UTC()); err != nil {
		return 0, 0, err
	}
	return int(cancelled), installing, tx.Commit()
}
