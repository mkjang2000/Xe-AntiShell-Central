package central

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
)

type remoteRemovalSelection struct {
	AgentIDs []string `json:"agent_ids,omitempty"`
	GroupID  string   `json:"group_id,omitempty"`
	SiteID   string   `json:"site_id,omitempty"`
}

func (request *remoteRemovalSelection) UnmarshalJSON(body []byte) error {
	type decoded remoteRemovalSelection
	return decodeAgentConfigurationConsoleObject(body, (*decoded)(request), "agent_ids", "group_id", "site_id")
}

func (request *remoteRemovalSelection) normalize() error {
	selectors := 0
	if len(request.AgentIDs) != 0 {
		selectors++
		ids, err := normalizedIDs(request.AgentIDs, consoleMaxTargets)
		if err != nil {
			return err
		}
		request.AgentIDs = ids
	}
	for _, id := range []string{request.GroupID, request.SiteID} {
		if id == "" {
			continue
		}
		if !identifierPattern.MatchString(id) {
			return ErrInvalid
		}
		selectors++
	}
	if selectors != 1 {
		return fmt.Errorf("%w: 에이전트, 그룹, 사이트 중 한 가지 범위를 선택하세요", ErrInvalid)
	}
	return nil
}

type remoteRemovalBatchTarget struct {
	AgentID      string            `json:"agent_id"`
	EnrollmentID string            `json:"enrollment_id"`
	SiteID       string            `json:"site_id"`
	Eligible     bool              `json:"eligible"`
	Reason       string            `json:"reason,omitempty"`
	Job          *remoteRemovalJob `json:"job,omitempty"`
}

type remoteRemovalBatch struct {
	BatchID   string                     `json:"batch_id"`
	CreatedAt time.Time                  `json:"created_at"`
	Targets   []remoteRemovalBatchTarget `json:"targets"`
}

type remoteRemovalWitness struct {
	Targets         []remoteRemovalBatchTarget `json:"targets"`
	GroupVersion    int64                      `json:"group_version,omitempty"`
	GroupGeneration string                     `json:"group_generation,omitempty"`
}

func remoteRemovalSelectionIDs(ctx context.Context, tx *sql.Tx, actor console.Account, request remoteRemovalSelection) ([]string, string, remoteRemovalWitness, error) {
	var witness remoteRemovalWitness
	if request.GroupID != "" {
		group, err := loadConsoleGroup(ctx, tx, request.GroupID)
		if err != nil {
			return nil, "", witness, err
		}
		if err := authorizeRemoteRemovalSite(ctx, actor, group.SiteID); err != nil {
			return nil, "", witness, err
		}
		ids, err := normalizedIDs(group.AgentIDs, consoleMaxTargets)
		witness.GroupVersion, witness.GroupGeneration = group.Version, group.generation
		return ids, group.SiteID, witness, err
	}
	if request.SiteID == "" {
		return request.AgentIDs, "", witness, nil
	}
	if err := authorizeRemoteRemovalSite(ctx, actor, request.SiteID); err != nil {
		return nil, "", witness, err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sites WHERE site_id=?)", request.SiteID).Scan(&exists); err != nil {
		return nil, "", witness, err
	}
	if !exists {
		return nil, "", witness, ErrNotFound
	}
	rows, err := tx.QueryContext(ctx, "SELECT agent_id FROM agents WHERE site_id=? ORDER BY agent_id LIMIT ?", request.SiteID, consoleMaxTargets+1)
	if err != nil {
		return nil, "", witness, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, "", witness, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, "", witness, err
	}
	if len(ids) > consoleMaxTargets {
		return nil, "", witness, fmt.Errorf("%w: 사이트에서 한 번에 최대 %d대를 선택할 수 있습니다", ErrInvalid, consoleMaxTargets)
	}
	return ids, request.SiteID, witness, nil
}

func remoteRemovalTargets(ctx context.Context, tx *sql.Tx, actor console.Account, request remoteRemovalSelection, now time.Time) (remoteRemovalWitness, int, error) {
	ids, expectedSite, result, err := remoteRemovalSelectionIDs(ctx, tx, actor, request)
	if err != nil {
		return result, 0, err
	}
	result.Targets = make([]remoteRemovalBatchTarget, 0, len(ids))
	eligible := 0
	for _, id := range ids {
		state, err := loadRemoteRemovalTarget(ctx, tx, id, now)
		if errors.Is(err, ErrNotFound) && expectedSite != "" {
			// A previously known group member may no longer have a
			// registration. Show only the saved member ID and bound site.
			result.Targets = append(result.Targets, remoteRemovalBatchTarget{AgentID: id, SiteID: expectedSite, Reason: "unavailable"})
			continue
		}
		if err != nil {
			return result, 0, err
		}
		if expectedSite != "" && state.SiteID != expectedSite {
			result.Targets = append(result.Targets, remoteRemovalBatchTarget{AgentID: id, SiteID: expectedSite, Reason: "unavailable"})
			continue
		}
		if err := authorizeRemoteRemovalSite(ctx, actor, state.SiteID); err != nil {
			return result, 0, err
		}
		target := remoteRemovalBatchTarget{AgentID: id, EnrollmentID: state.EnrollmentID, SiteID: state.SiteID, Reason: state.Reason}
		if target.Reason == "" {
			pending, err := remoteRemovalPending(ctx, tx, id, state.EnrollmentID, now)
			if err != nil {
				return result, 0, err
			}
			if pending {
				target.Reason = "removal_busy"
			}
		}
		target.Eligible = target.Reason == ""
		if target.Eligible {
			eligible++
		}
		result.Targets = append(result.Targets, target)
	}
	return result, eligible, nil
}

func (s *Server) createRemoteRemovalBatch(ctx context.Context, actor console.Account, preview remoteRemovalPreview) (remoteRemovalBatch, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return remoteRemovalBatch{}, err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	existing, err := s.readRemoteRemovalBatch(ctx, tx, actor, preview.BatchID, now)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return remoteRemovalBatch{}, err
	}
	if !now.Before(preview.ExpiresAt) {
		return remoteRemovalBatch{}, ErrConflict
	}
	witness, eligible, err := remoteRemovalTargets(ctx, tx, actor, preview.Selection, now)
	if err != nil {
		return remoteRemovalBatch{}, err
	}
	digest, err := consoleHash(witness)
	if err != nil {
		return remoteRemovalBatch{}, err
	}
	if digest != preview.TargetHash || eligible != preview.Eligible || eligible == 0 {
		return remoteRemovalBatch{}, fmt.Errorf("%w: 제거 대상이나 상태가 바뀌었습니다. 미리보기를 다시 확인하세요", ErrConflict)
	}
	batch := remoteRemovalBatch{BatchID: preview.BatchID, CreatedAt: now, Targets: make([]remoteRemovalBatchTarget, 0, eligible)}
	if _, err := tx.ExecContext(ctx, "INSERT INTO remote_removal_batches(id,actor,actor_version,created_at_ns) VALUES(?,?,?,?)",
		batch.BatchID, actor.Username, actor.Version, now.UnixNano()); err != nil {
		return remoteRemovalBatch{}, err
	}
	for _, target := range witness.Targets {
		if !target.Eligible {
			continue
		}
		state := remoteRemovalState{AgentID: target.AgentID, EnrollmentID: target.EnrollmentID, SiteID: target.SiteID}
		job, err := s.insertRemoteRemovalOrder(ctx, tx, state, actor, batch.BatchID, now)
		if err != nil {
			return remoteRemovalBatch{}, err
		}
		target.Job = job
		batch.Targets = append(batch.Targets, target)
	}
	return batch, tx.Commit()
}

func (s *Server) readRemoteRemovalBatch(ctx context.Context, tx *sql.Tx, actor console.Account, id string, now time.Time) (remoteRemovalBatch, error) {
	var batch remoteRemovalBatch
	var createdNS int64
	err := tx.QueryRowContext(ctx, "SELECT id,created_at_ns FROM remote_removal_batches WHERE id=?", id).Scan(&batch.BatchID, &createdNS)
	if errors.Is(err, sql.ErrNoRows) {
		return batch, ErrNotFound
	}
	if err != nil {
		return batch, err
	}
	batch.CreatedAt = time.Unix(0, createdNS).UTC()
	rows, err := tx.QueryContext(ctx, `SELECT r.agent_id,r.enrollment_id,i.site_id,r.id,COALESCE(a.enrollment_id,''),COALESCE(a.revoked,1),COALESCE(a.site_id=i.site_id,0)
 FROM remote_removal_orders r JOIN remote_removal_intents i ON i.order_id=r.id
 LEFT JOIN agents a ON a.agent_id=r.agent_id
 WHERE i.batch_id=? ORDER BY r.agent_id`, id)
	if err != nil {
		return batch, err
	}
	type batchRow struct {
		target            remoteRemovalBatchTarget
		orderID           string
		currentEnrollment string
		revoked           bool
		sameSite          bool
	}
	var matching []batchRow
	for rows.Next() {
		var entry batchRow
		if err := rows.Scan(&entry.target.AgentID, &entry.target.EnrollmentID, &entry.target.SiteID, &entry.orderID, &entry.currentEnrollment, &entry.revoked, &entry.sameSite); err != nil {
			rows.Close()
			return batch, err
		}
		if authorizeRemoteRemovalSite(ctx, actor, entry.target.SiteID) == nil {
			matching = append(matching, entry)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return batch, err
	}
	if err := rows.Close(); err != nil {
		return batch, err
	}
	if len(matching) == 0 {
		return remoteRemovalBatch{}, ErrNotFound
	}
	batch.Targets = make([]remoteRemovalBatchTarget, 0, len(matching))
	for _, entry := range matching {
		target := entry.target
		target.Eligible = true
		job, err := remoteRemovalOrder(ctx, tx, authenticatedAgent{target.AgentID, target.EnrollmentID}, entry.orderID)
		if err != nil {
			return batch, err
		}
		target.Job = job
		unstarted := job.State == "queued" || job.State == "claimed"
		projectRemoteRemovalJob(job, now, entry.revoked || !entry.sameSite || entry.currentEnrollment != target.EnrollmentID)
		if unstarted && !entry.sameSite && job.State == "cancelled" {
			job.Code = "site_changed"
		}
		batch.Targets = append(batch.Targets, target)
	}
	return batch, nil
}
