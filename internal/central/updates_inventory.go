package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func currentUpdateAgent(ctx context.Context, tx *sql.Tx, agent authenticatedAgent) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM agents WHERE agent_id=? AND enrollment_id=? AND revoked=0", agent.ID, agent.EnrollmentID).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrUnauthorized
	}
	return nil
}

func expireUpdateJobs(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE update_jobs SET state='expired',error_code='expired' WHERE expires_at_ns<=? AND state IN ('queued','offered','downloading','ready')`, now.UnixNano())
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE update_jobs SET state='failed',error_code='interrupted' WHERE state='installing' AND install_deadline_ns>0 AND install_deadline_ns<=?`, now.UnixNano())
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE update_jobs SET state='cancelled',error_code='target_mismatch' WHERE state IN ('queued','offered','downloading','ready') AND NOT EXISTS(SELECT 1 FROM agents a WHERE a.agent_id=update_jobs.agent_id AND a.enrollment_id=update_jobs.enrollment_id AND a.revoked=0)`)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE update_rollouts SET paused=1,stop_reason=CASE WHEN EXISTS(SELECT 1 FROM update_jobs j WHERE j.rollout_id=update_rollouts.id AND j.state='failed' AND j.error_code='interrupted') THEN 'interrupted' WHEN EXISTS(SELECT 1 FROM update_jobs j WHERE j.rollout_id=update_rollouts.id AND j.state='failed') THEN 'failed' ELSE 'expired' END WHERE paused=0 AND EXISTS(SELECT 1 FROM update_jobs j WHERE j.rollout_id=update_rollouts.id AND j.state IN ('failed','expired'))`)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE update_jobs SET state='cancelled',error_code='rollout_stopped' WHERE authorization_json IS NULL AND state IN ('queued','offered','downloading','ready') AND EXISTS(SELECT 1 FROM update_rollouts r WHERE r.id=update_jobs.rollout_id AND r.paused=1)`)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE update_heads SET active_job_id='' WHERE active_job_id<>'' AND EXISTS(SELECT 1 FROM update_jobs j WHERE j.id=update_heads.active_job_id AND j.state IN ('succeeded','failed','expired','cancelled'))`)
	}
	return err
}

func (s *Server) recordUpdateInventory(ctx context.Context, agent authenticatedAgent, inventory managed.UpdateInventory) error {
	now := s.now().UTC()
	if inventory.Validate() != nil || inventory.ObservedAt.After(now.Add(time.Minute)) || inventory.ObservedAt.Before(now.Add(-10*time.Minute)) {
		return ErrInvalid
	}
	body, _ := json.Marshal(inventory)
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = currentUpdateAgent(ctx, tx, agent); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO update_inventory(agent_id,enrollment_id,inventory_json,received_at_ns) VALUES(?,?,?,?) ON CONFLICT(agent_id,enrollment_id) DO UPDATE SET inventory_json=excluded.inventory_json,received_at_ns=excluded.received_at_ns`, agent.ID, agent.EnrollmentID, body, now.UnixNano())
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO update_heads(agent_id,enrollment_id) VALUES(?,?) ON CONFLICT DO NOTHING", agent.ID, agent.EnrollmentID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) listUpdateAgents(ctx context.Context, after, search string, limit int) ([]ConsoleUpdateAgent, string, int, error) {
	if len(after) > 128 || len(search) > 128 || limit < 1 || limit > 200 {
		return nil, "", 0, ErrInvalid
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", 0, err
	}
	defer tx.Rollback()
	if err = expireUpdateJobs(ctx, tx, s.now().UTC()); err != nil {
		return nil, "", 0, err
	}
	pattern := "%" + strings.ToLower(search) + "%"
	var total int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agents WHERE revoked=0 AND (lower(agent_id) LIKE ? OR lower(hostname) LIKE ?)", pattern, pattern).Scan(&total); err != nil {
		return nil, "", 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.agent_id,a.enrollment_id,a.hostname,i.inventory_json,coalesce(i.received_at_ns,0),coalesce(h.active_job_id,'') FROM agents a LEFT JOIN update_inventory i ON i.agent_id=a.agent_id AND i.enrollment_id=a.enrollment_id LEFT JOIN update_heads h ON h.agent_id=a.agent_id AND h.enrollment_id=a.enrollment_id WHERE a.revoked=0 AND a.agent_id>? AND (lower(a.agent_id) LIKE ? OR lower(a.hostname) LIKE ?) ORDER BY a.agent_id LIMIT ?`, after, pattern, pattern, limit+1)
	if err != nil {
		return nil, "", 0, err
	}
	items := []ConsoleUpdateAgent{}
	for rows.Next() {
		var item ConsoleUpdateAgent
		var body []byte
		var ns int64
		if err = rows.Scan(&item.AgentID, &item.EnrollmentID, &item.Hostname, &body, &ns, &item.ActiveJobID); err != nil {
			break
		}
		if len(body) > 0 {
			item.Inventory = new(managed.UpdateInventory)
			err = json.Unmarshal(body, item.Inventory)
			if err != nil {
				break
			}
		}
		item.ReceivedAt = timePointer(ns)
		items = append(items, item)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, "", 0, err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = items[len(items)-1].AgentID
	}
	if err = tx.Commit(); err != nil {
		return nil, "", 0, err
	}
	return items, next, total, nil
}
