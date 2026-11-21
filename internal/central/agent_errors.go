package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const historySchema = `
CREATE TABLE IF NOT EXISTS console_agent_error_state(agent_id TEXT NOT NULL,kind TEXT NOT NULL,signature TEXT NOT NULL,category TEXT NOT NULL,PRIMARY KEY(agent_id,kind));
CREATE TABLE IF NOT EXISTS console_agent_errors(id INTEGER PRIMARY KEY AUTOINCREMENT,agent_id TEXT NOT NULL,kind TEXT NOT NULL,transition TEXT NOT NULL,category TEXT NOT NULL,recorded_at_ns INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS console_agent_errors_page_idx ON console_agent_errors(recorded_at_ns DESC,id DESC);
CREATE INDEX IF NOT EXISTS console_agent_errors_agent_idx ON console_agent_errors(agent_id,recorded_at_ns DESC,id DESC);
CREATE INDEX IF NOT EXISTS records_history_kind_idx ON records(kind,received_at_ns DESC,agent_id DESC,record_id DESC);
CREATE INDEX IF NOT EXISTS records_history_detection_bundle_idx ON records(received_at_ns DESC,agent_id DESC,record_id DESC) WHERE kind='event_bundle' AND json_array_length(payload,'$.findings')>0;
CREATE INDEX IF NOT EXISTS audit_history_page_idx ON audit(created_at_ns DESC,audit_id DESC);
CREATE INDEX IF NOT EXISTS audit_history_agent_idx ON audit(agent_id,created_at_ns DESC,audit_id DESC);
`

type agentErrorState struct{ kind, signature, category string }

func heartbeatErrors(heartbeat managed.Heartbeat) []agentErrorState {
	status := heartbeat.Status
	collector := ""
	if status.CollectorHealth != nil {
		collector = status.CollectorHealth.LastError
		if collector == "" && !status.CollectorHealth.Running && status.Collector != "" && (status.Mode == "active" || status.Mode == "error" || status.Mode == "degraded") {
			collector = "collector stream is not running"
		}
	}
	agent := status.LastError
	if agent == "" && (status.Health == "error" || status.Health == "degraded" || status.Mode == "error") {
		agent = "agent health " + string(status.Health) + " mode " + string(status.Mode)
	}
	policy := heartbeat.PolicyError
	if policy == "" && heartbeat.PolicyStatus.Error != "" {
		policy = heartbeat.PolicyStatus.Error
	}
	if policy == "" && heartbeat.PolicyStatus.Result == "rejected" {
		policy = "policy rejected"
	}
	result := []agentErrorState{{kind: "agent"}, {kind: "collector"}, {kind: "policy"}}
	for index, text := range []string{agent, collector, policy} {
		if text == "" {
			continue
		}
		digest := sha256.Sum256([]byte(text))
		result[index].signature = hex.EncodeToString(digest[:])
		result[index].category = errorCategory(text)
	}
	return result
}

func errorCategory(text string) string {
	text = strings.ToLower(text)
	for _, test := range []struct{ category, match string }{
		{"storage_order", "last-seen time precedes"}, {"parsing", "parse"}, {"parsing", "malformed"},
		{"policy_rejected", "policy rejected"}, {"storage", "storage:"}, {"storage", "database"}, {"tls", "x509"}, {"tls", "tls"},
		{"permission", "permission"}, {"timeout", "timeout"}, {"timeout", "deadline"},
		{"connection", "connection"}, {"policy", "policy"}, {"collector", "collector"},
	} {
		if strings.Contains(text, test.match) {
			return test.category
		}
	}
	return "runtime"
}

// Keep raw diagnostics in the existing latest heartbeat only. Historical rows
// retain fixed categories; hashes detect changes without retaining error text.
func recordHeartbeatErrors(ctx context.Context, tx *sql.Tx, agentID string, heartbeat managed.Heartbeat, now time.Time, baseline bool) error {
	for _, state := range heartbeatErrors(heartbeat) {
		var previous, category string
		err := tx.QueryRowContext(ctx, "SELECT signature,category FROM console_agent_error_state WHERE agent_id=? AND kind=?", agentID, state.kind).Scan(&previous, &category)
		missing := errors.Is(err, sql.ErrNoRows)
		if err != nil && !missing {
			return err
		}
		if baseline && !missing {
			continue
		}
		transition := ""
		if state.signature != previous {
			switch {
			case state.signature == "":
				transition, state.category = "recovered", category
			case previous == "":
				transition = "occurred"
			default:
				transition = "changed"
			}
			if baseline {
				transition = "baseline"
			}
		}
		if transition != "" {
			if _, err = tx.ExecContext(ctx, "INSERT INTO console_agent_errors(agent_id,kind,transition,category,recorded_at_ns,site_id) VALUES(?,?,?,?,?,COALESCE((SELECT site_id FROM agents WHERE agent_id=?),'default'))", agentID, state.kind, transition, state.category, now.UnixNano(), agentID); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO console_agent_error_state(agent_id,kind,signature,category) VALUES(?,?,?,?) ON CONFLICT(agent_id,kind) DO UPDATE SET signature=excluded.signature,category=excluded.category", agentID, state.kind, state.signature, state.category); err != nil {
			return err
		}
	}
	return nil
}

func initializeErrorHistory(ctx context.Context, tx *sql.Tx) error {
	cursor := ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT a.agent_id,a.heartbeat_json FROM agents a WHERE a.heartbeat_json IS NOT NULL AND a.agent_id>?
AND NOT EXISTS(SELECT 1 FROM console_agent_error_state s WHERE s.agent_id=a.agent_id AND s.kind='agent') ORDER BY a.agent_id LIMIT 100`, cursor)
		if err != nil {
			return err
		}
		type baseline struct {
			id        string
			heartbeat managed.Heartbeat
		}
		var snapshots []baseline
		for rows.Next() {
			var item baseline
			var body []byte
			if err = rows.Scan(&item.id, &body); err != nil {
				break
			}
			if err = json.Unmarshal(body, &item.heartbeat); err != nil {
				break
			}
			snapshots = append(snapshots, item)
		}
		if err == nil {
			err = rows.Err()
		}
		_ = rows.Close()
		if err != nil {
			return err
		}
		if len(snapshots) == 0 {
			return nil
		}
		now := time.Now().UTC()
		for _, item := range snapshots {
			if err = recordHeartbeatErrors(ctx, tx, item.id, item.heartbeat, now, true); err != nil {
				return err
			}
			cursor = item.id
		}
	}
}
