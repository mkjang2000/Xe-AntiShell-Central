package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const defaultSiteID = "default"

const siteSchema = `
CREATE TABLE IF NOT EXISTS sites(site_id TEXT PRIMARY KEY,name TEXT NOT NULL,version INTEGER NOT NULL);
INSERT INTO sites(site_id,name,version) VALUES('default','기본 사이트',1) ON CONFLICT(site_id) DO NOTHING;
`

func initializeSites(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, siteSchema); err != nil {
		return err
	}
	for _, column := range []struct{ table, definition string }{
		{"agents", "TEXT NOT NULL DEFAULT 'default'"},
		{"enrollment_tokens", "TEXT NOT NULL DEFAULT 'default'"},
		{"console_groups", "TEXT NOT NULL DEFAULT 'default'"},
		{"records", "TEXT NOT NULL DEFAULT 'default'"},
		{"console_agent_errors", "TEXT NOT NULL DEFAULT 'default'"},
		{"audit", "TEXT REFERENCES sites(site_id)"},
	} {
		var present bool
		err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pragma_table_info(?) WHERE name='site_id')", column.table).Scan(&present)
		if err != nil {
			return err
		}
		if !present {
			if _, err := tx.ExecContext(ctx, "ALTER TABLE "+column.table+" ADD COLUMN site_id "+column.definition); err != nil {
				return err
			}
			if column.table == "audit" {
				// Legacy entries associated with agents predate multiple sites.
				if _, err := tx.ExecContext(ctx, "UPDATE audit SET site_id=? WHERE agent_id<>''", defaultSiteID); err != nil {
					return err
				}
			}
		}
	}
	_, err := tx.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS agents_site_idx ON agents(site_id,agent_id);
CREATE INDEX IF NOT EXISTS agents_tokens_site_idx ON enrollment_tokens(site_id,agent_id);
CREATE INDEX IF NOT EXISTS console_groups_site_idx ON console_groups(site_id,id);
CREATE INDEX IF NOT EXISTS records_site_idx ON records(site_id,received_at_ns DESC,agent_id DESC,kind DESC,record_id DESC);
CREATE INDEX IF NOT EXISTS records_site_detection_finding_idx ON records(site_id,received_at_ns DESC,agent_id DESC,record_id DESC) WHERE kind='finding';
CREATE INDEX IF NOT EXISTS records_site_detection_bundle_idx ON records(site_id,received_at_ns DESC,agent_id DESC,record_id DESC) WHERE kind='event_bundle' AND json_array_length(payload,'$.findings')>0;
CREATE INDEX IF NOT EXISTS audit_site_idx ON audit(site_id,created_at_ns DESC,audit_id DESC);
CREATE INDEX IF NOT EXISTS agent_errors_site_idx ON console_agent_errors(site_id,recorded_at_ns DESC,id DESC); `)
	return err
}

// Existing rollouts can span different sites. Keep them visible to global
// accounts until explicitly scoped rollouts are created on this version.
func initializeSiteRolloutScope(ctx context.Context, tx *sql.Tx) error {
	var present bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pragma_table_info('update_rollouts') WHERE name='site_id')").Scan(&present); err != nil {
		return err
	}
	if !present {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE update_rollouts ADD COLUMN site_id TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS update_rollouts_site_idx ON update_rollouts(site_id,created_at_ns DESC,id DESC)")
	return err
}

type site struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int64  `json:"version"`
}

type siteContextKey struct{}

// selectedSite is empty for a permitted all-sites request or internal callers.
func selectedSite(ctx context.Context) string {
	id, _ := ctx.Value(siteContextKey{}).(string)
	return id
}

func (s *Store) SiteExists(ctx context.Context, siteID string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM sites WHERE site_id=?)", siteID).Scan(&exists)
	return exists, err
}

func (s *Store) listSites(ctx context.Context) ([]site, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT site_id,name,version FROM sites ORDER BY site_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sites := []site{}
	for rows.Next() {
		var item site
		if err := rows.Scan(&item.ID, &item.Name, &item.Version); err != nil {
			return nil, err
		}
		sites = append(sites, item)
	}
	return sites, rows.Err()
}

func (s *Store) saveSite(ctx context.Context, item site, actor string, now time.Time) (site, error) {
	item.Name = strings.TrimSpace(item.Name)
	if err := validateConsoleMetadata(item.ID, item.Name, "", item.Version); err != nil {
		return item, err
	}
	if item.Version == math.MaxInt64 {
		return item, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return item, err
	}
	defer tx.Rollback()
	var changed sql.Result
	if item.Version == 0 {
		changed, err = tx.ExecContext(ctx, "INSERT INTO sites(site_id,name,version) VALUES(?,?,1) ON CONFLICT(site_id) DO NOTHING", item.ID, item.Name)
	} else {
		changed, err = tx.ExecContext(ctx, "UPDATE sites SET name=?,version=version+1 WHERE site_id=? AND version=?", item.Name, item.ID, item.Version)
	}
	if err != nil {
		return item, err
	}
	count, err := changed.RowsAffected()
	if err != nil {
		return item, err
	}
	if count != 1 {
		return item, ErrConflict
	}
	item.Version++
	if err := appendSiteAudit(ctx, tx, item.ID, "", "site.saved", map[string]any{"site_id": item.ID, "version": item.Version, "actor": actor}, now); err != nil {
		return item, err
	}
	return item, tx.Commit()
}

type siteQueryRow interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func agentSite(ctx context.Context, query siteQueryRow, agentID string) (string, error) {
	var siteID string
	err := query.QueryRowContext(ctx, "SELECT site_id FROM agents WHERE agent_id=?", agentID).Scan(&siteID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return siteID, err
}

func requireAgentSite(ctx context.Context, query siteQueryRow, agentID string) error {
	selected := selectedSite(ctx)
	if selected == "" {
		return nil
	}
	actual, err := agentSite(ctx, query, agentID)
	if err != nil {
		return err
	}
	if selected != actual {
		return ErrNotFound
	}
	return nil
}

func (s *Store) moveAgentSite(ctx context.Context, agentID, enrollmentID, destination, actor string, now time.Time) error {
	if !identifierPattern.MatchString(agentID) || !identifierPattern.MatchString(destination) || enrollmentID == "" || len(enrollmentID) > 160 {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous string
	if err := tx.QueryRowContext(ctx, "SELECT site_id FROM agents WHERE agent_id=? AND enrollment_id=?", agentID, enrollmentID).Scan(&previous); errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	} else if err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sites WHERE site_id=?)", destination).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if previous == destination {
		return nil
	}
	// A pending package job was authorized for the previous site.
	removing, err := remoteRemovalPending(ctx, tx, agentID, enrollmentID, now)
	if err != nil {
		return err
	}
	if err := expireUpdateJobs(ctx, tx, now); err != nil {
		return err
	}
	var updating bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM update_heads h JOIN update_jobs j ON j.id=h.active_job_id
WHERE h.agent_id=? AND h.enrollment_id=? AND j.state IN ('queued','offered','downloading','ready','installing'))`,
		agentID, enrollmentID).Scan(&updating); err != nil {
		return err
	}
	if removing || updating {
		return fmt.Errorf("%w: 패키지 작업이 진행 중인 에이전트입니다", ErrConflict)
	}
	if err = removeAgentSiteGroupMembership(ctx, tx, previous, agentID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE agents SET site_id=?,last_seen_at_ns=0,heartbeat_json=NULL WHERE agent_id=? AND enrollment_id=? AND site_id=?", destination, agentID, enrollmentID, previous); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM console_agent_error_state WHERE agent_id=?", agentID); err != nil {
		return err
	}
	// A previously minted token cannot restore the earlier site membership.
	if _, err := tx.ExecContext(ctx, "DELETE FROM enrollment_tokens WHERE agent_id=? AND used=0", agentID); err != nil {
		return err
	}
	if err := appendSiteAudit(ctx, tx, previous, agentID, "site.agent.departed", map[string]string{"site_id": previous, "actor": actor}, now); err != nil {
		return err
	}
	if err := appendSiteAudit(ctx, tx, destination, agentID, "site.agent.arrived", map[string]string{"site_id": destination, "actor": actor}, now); err != nil {
		return err
	}
	return tx.Commit()
}

func removeAgentSiteGroupMembership(ctx context.Context, tx *sql.Tx, siteID, agentID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT g.id FROM console_groups g,json_each(g.agent_ids_json) j
WHERE g.site_id=? AND j.value=?`, siteID, agentID)
	if err != nil {
		return err
	}
	var groups []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		groups = append(groups, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, id := range groups {
		group, err := loadConsoleGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		var retained []string
		for _, member := range group.AgentIDs {
			if member != agentID {
				retained = append(retained, member)
			}
		}
		if retained == nil {
			retained = []string{}
		}
		body, err := json.Marshal(retained)
		if err != nil {
			return err
		}
		if _, err = saveConsoleRecord(ctx, tx, "console_groups", group.ID, group.Name, group.Description, group.Version, "agent_ids_json", body); err != nil {
			return err
		}
	}
	return nil
}
