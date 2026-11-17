package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func loadUpdateRollout(ctx context.Context, q updateReader, id string) (ConsoleUpdateRollout, error) {
	var item ConsoleUpdateRollout
	var created, expires int64
	err := q.QueryRowContext(ctx, "SELECT id,release_id,created_by,created_at_ns,expires_at_ns,concurrency,cancelled,paused,stop_reason FROM update_rollouts WHERE id=?", id).Scan(&item.ID, &item.ReleaseID, &item.CreatedBy, &created, &expires, &item.Concurrency, &item.Cancelled, &item.Paused, &item.StopReason)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrNotFound
	}
	if err != nil {
		return item, err
	}
	item.CreatedAt = time.Unix(0, created).UTC()
	item.ExpiresAt = time.Unix(0, expires).UTC()
	item.Counters = map[string]int{}
	rows, err := q.QueryContext(ctx, "SELECT state,count(*) FROM update_jobs WHERE rollout_id=? GROUP BY state", id)
	if err != nil {
		return item, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int
		if err = rows.Scan(&state, &count); err != nil {
			return item, err
		}
		item.Counters[state] = count
	}
	return item, rows.Err()
}

func (s *Server) updateRolloutDetail(ctx context.Context, id, after string, limit int) (ConsoleUpdateRollout, []ConsoleUpdateJob, string, error) {
	if len(after) > 128 || limit < 1 || limit > 1000 {
		return ConsoleUpdateRollout{}, nil, "", ErrInvalid
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ConsoleUpdateRollout{}, nil, "", err
	}
	defer tx.Rollback()
	if err = expireUpdateJobs(ctx, tx, s.now().UTC()); err != nil {
		return ConsoleUpdateRollout{}, nil, "", err
	}
	rollout, err := loadUpdateRollout(ctx, tx, id)
	if err != nil {
		return rollout, nil, "", err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,rollout_id,agent_id,enrollment_id,revision,state,current_json,target_json,report_json,report_at_ns,error_code,expires_at_ns,last_report_late FROM update_jobs WHERE rollout_id=? AND id>? ORDER BY id LIMIT ?", id, after, limit+1)
	if err != nil {
		return rollout, nil, "", err
	}
	jobs := []ConsoleUpdateJob{}
	for rows.Next() {
		var job ConsoleUpdateJob
		var current, target, report []byte
		var received, expires int64
		if err = rows.Scan(&job.ID, &job.RolloutID, &job.AgentID, &job.EnrollmentID, &job.Revision, &job.State, &current, &target, &report, &received, &job.ErrorCode, &expires, &job.LateReport); err != nil {
			break
		}
		var release managed.UpdateRelease
		if err = json.Unmarshal(current, &job.CurrentPackage); err != nil {
			break
		}
		if err = json.Unmarshal(target, &release); err != nil {
			break
		}
		job.TargetPackage = release.Package
		if len(report) > 0 {
			var value managed.UpdateReport
			if err = json.Unmarshal(report, &value); err != nil {
				break
			}
			job.ObservedPackage = value.InstalledPackage
			job.CollectionCheck = value.CollectionCheck
		}
		job.Terminal = updateTerminal(job.State)
		job.StoppedAfterFailure = job.ErrorCode == "rollout_stopped"
		job.LastReportAt = timePointer(received)
		job.ExpiresAt = time.Unix(0, expires).UTC()
		jobs = append(jobs, job)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return rollout, nil, "", err
	}
	next := ""
	if len(jobs) > limit {
		jobs = jobs[:limit]
		next = jobs[len(jobs)-1].ID
	}
	if err = tx.Commit(); err != nil {
		return rollout, nil, "", err
	}
	return rollout, jobs, next, nil
}

func (s *Server) listUpdateRollouts(ctx context.Context, after string, limit int) ([]ConsoleUpdateRollout, string, error) {
	if len(after) > 128 || limit < 1 || limit > 200 {
		return nil, "", ErrInvalid
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = expireUpdateJobs(ctx, tx, s.now().UTC()); err != nil {
		return nil, "", err
	}
	var before int64
	if after != "" {
		if err = tx.QueryRowContext(ctx, "SELECT created_at_ns FROM update_rollouts WHERE id=?", after).Scan(&before); err != nil {
			return nil, "", ErrInvalid
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM update_rollouts WHERE ?='' OR created_at_ns<? OR (created_at_ns=? AND id<?) ORDER BY created_at_ns DESC,id DESC LIMIT ?", after, before, before, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(ids) > limit {
		ids = ids[:limit]
		next = ids[len(ids)-1]
	}
	items := []ConsoleUpdateRollout{}
	for _, id := range ids {
		item, err := loadUpdateRollout(ctx, tx, id)
		if err != nil {
			return nil, "", err
		}
		items = append(items, item)
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return items, next, nil
}
