package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const remoteRemovalSchema = `
CREATE TABLE IF NOT EXISTS remote_removal_orders(
 id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,
 issued_at_ns INTEGER NOT NULL,expires_at_ns INTEGER NOT NULL,updated_at_ns INTEGER NOT NULL,
 actor TEXT NOT NULL,state TEXT NOT NULL,code TEXT NOT NULL DEFAULT '',
 order_json BLOB NOT NULL,operation_id TEXT NOT NULL DEFAULT '',grant_json BLOB,
 CHECK (state IN ('queued','claimed','started','succeeded','failed','expired','cancelled')));
CREATE INDEX IF NOT EXISTS remote_removal_orders_target ON remote_removal_orders(agent_id,enrollment_id,issued_at_ns DESC);
CREATE UNIQUE INDEX IF NOT EXISTS remote_removal_orders_active ON remote_removal_orders(agent_id,enrollment_id)
 WHERE state IN ('queued','claimed','started');
CREATE TABLE IF NOT EXISTS remote_removal_batches(
 id TEXT PRIMARY KEY,actor TEXT NOT NULL,actor_version INTEGER NOT NULL,created_at_ns INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_removal_intents(
 order_id TEXT PRIMARY KEY REFERENCES remote_removal_orders(id),site_id TEXT NOT NULL,
 actor_version INTEGER NOT NULL,batch_id TEXT REFERENCES remote_removal_batches(id));
CREATE INDEX IF NOT EXISTS remote_removal_batch_intents ON remote_removal_intents(batch_id);
UPDATE remote_removal_orders SET state='cancelled',grant_json=NULL
 WHERE state IN ('queued','claimed')
 AND NOT EXISTS(SELECT 1 FROM remote_removal_intents i WHERE i.order_id=remote_removal_orders.id);
`

const remoteRemovalFreshness = 2 * time.Minute

const activeRemoteRemovalCondition = "(r.state='started' OR (r.state IN ('queued','claimed') AND r.expires_at_ns>?))"

type remoteRemovalJob struct {
	OrderID      string    `json:"order_id"`
	State        string    `json:"state"`
	Code         string    `json:"code,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	operationID  string
	order, grant []byte
}

type remoteRemovalState struct {
	AgentID      string            `json:"agent_id"`
	EnrollmentID string            `json:"enrollment_id"`
	SiteID       string            `json:"site_id"`
	Supported    bool              `json:"supported"`
	Enabled      bool              `json:"enabled"`
	Fresh        bool              `json:"fresh"`
	CanRequest   bool              `json:"can_request"`
	Reason       string            `json:"reason"`
	Job          *remoteRemovalJob `json:"job,omitempty"`
}

const remoteRemovalJobFields = "id,state,code,issued_at_ns,expires_at_ns,updated_at_ns,operation_id,order_json,grant_json"

func readRemoteRemovalJob(row *sql.Row) (*remoteRemovalJob, error) {
	var job remoteRemovalJob
	var issued, expires, updated int64
	err := row.Scan(&job.OrderID, &job.State, &job.Code, &issued, &expires, &updated, &job.operationID, &job.order, &job.grant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	job.IssuedAt = time.Unix(0, issued).UTC()
	job.ExpiresAt = time.Unix(0, expires).UTC()
	job.UpdatedAt = time.Unix(0, updated).UTC()
	return &job, nil
}

func remoteRemovalOrder(ctx context.Context, tx *sql.Tx, agent authenticatedAgent, orderID string) (*remoteRemovalJob, error) {
	if orderID == "" {
		return readRemoteRemovalJob(tx.QueryRowContext(ctx, "SELECT "+remoteRemovalJobFields+" FROM remote_removal_orders WHERE agent_id=? AND enrollment_id=? ORDER BY issued_at_ns DESC,rowid DESC LIMIT 1", agent.ID, agent.EnrollmentID))
	}
	return readRemoteRemovalJob(tx.QueryRowContext(ctx, "SELECT "+remoteRemovalJobFields+" FROM remote_removal_orders WHERE agent_id=? AND enrollment_id=? AND id=?", agent.ID, agent.EnrollmentID, orderID))
}

func loadRemoteRemovalTarget(ctx context.Context, tx *sql.Tx, agentID string, now time.Time) (remoteRemovalState, error) {
	state := remoteRemovalState{AgentID: agentID}
	if !identifierPattern.MatchString(agentID) {
		return state, ErrInvalid
	}
	var revoked, updateBusy bool
	var seen int64
	var desiredRevision uint64
	var rawHeartbeat, rawPolicy []byte
	err := tx.QueryRowContext(ctx, `SELECT a.enrollment_id,a.site_id,a.revoked,a.heartbeat_json,a.last_seen_at_ns,a.desired_policy_revision,p.signed_json,
 EXISTS(SELECT 1 FROM update_heads h JOIN update_jobs j ON j.id=h.active_job_id
 WHERE h.agent_id=a.agent_id AND h.enrollment_id=a.enrollment_id
 AND ((j.state IN ('queued','offered','downloading','ready') AND j.expires_at_ns>?)
 OR (j.state='installing' AND (j.install_deadline_ns=0 OR j.install_deadline_ns>?))))
 FROM agents a LEFT JOIN policies p ON p.agent_id=a.agent_id AND p.enrollment_id=a.enrollment_id
 AND p.revision=a.desired_policy_revision WHERE a.agent_id=?`, now.UnixNano(), now.UnixNano(), agentID).
		Scan(&state.EnrollmentID, &state.SiteID, &revoked, &rawHeartbeat, &seen, &desiredRevision, &rawPolicy, &updateBusy)
	if errors.Is(err, sql.ErrNoRows) {
		return state, ErrNotFound
	}
	if err != nil {
		return state, err
	}

	hb := decodePolicyHeartbeat(rawHeartbeat)
	if hb.AgentID == agentID && hb.EnrollmentID == state.EnrollmentID && hb.Status.CapabilityReport != nil {
		details := hb.Status.CapabilityReport.Capabilities[managed.RemoteRemovalCapability].Details
		state.Enabled = details["enabled"] == "true"
		state.Supported = details["contract"] == managed.RemoteRemovalContract && (state.Enabled || details["enabled"] == "false")
		state.Enabled = state.Enabled && state.Supported
		received := time.Unix(0, seen)
		state.Fresh = state.Supported && seen > 0 && !received.Before(now.Add(-remoteRemovalFreshness)) &&
			!received.After(now) && !hb.SentAt.Before(now.Add(-remoteRemovalFreshness)) && !hb.SentAt.After(now.Add(time.Minute))
	}
	var denied bool
	if desiredRevision != 0 {
		var signed managed.SignedPolicy
		if err = json.Unmarshal(rawPolicy, &signed); err != nil {
			return state, errors.New("invalid stored removal policy")
		}
		denied = signed.Policy.UninstallMode == "deny"
	}
	switch {
	case revoked:
		state.Reason = "revoked"
	case !state.Supported:
		state.Reason = "unsupported"
	case !state.Enabled:
		state.Reason = "disabled"
	case !state.Fresh:
		state.Reason = "stale"
	case denied:
		state.Reason = "policy_denied"
	case updateBusy:
		state.Reason = "update_busy"
	}
	return state, nil
}

func remoteRemovalPending(ctx context.Context, tx *sql.Tx, agentID, enrollmentID string, now time.Time) (bool, error) {
	var pending bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remote_removal_orders r WHERE r.agent_id=? AND r.enrollment_id=?
 AND `+activeRemoteRemovalCondition+`)`, agentID, enrollmentID, now.UnixNano()).Scan(&pending)
	return pending, err
}

func (j *remoteRemovalJob) expiredBeforeStart(now time.Time) bool {
	return j.State == "expired" || (j.State == "queued" || j.State == "claimed") && !now.Before(j.ExpiresAt)
}

func (s *Server) newRemoteRemovalOrder(ctx context.Context, agentID, enrollmentID string, actor console.Account) (*remoteRemovalJob, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	state, err := loadRemoteRemovalTarget(ctx, tx, agentID, now)
	if err != nil {
		return nil, err
	}
	if err := authorizeRemoteRemovalSite(ctx, actor, state.SiteID); err != nil {
		return nil, err
	}
	if state.EnrollmentID != enrollmentID || state.Reason != "" {
		return nil, fmt.Errorf("%w: 대상의 현재 등록과 원격 제거 상태를 다시 확인하세요", ErrConflict)
	}
	pending, err := remoteRemovalPending(ctx, tx, agentID, enrollmentID, now)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrConflict
	}
	job, err := s.insertRemoteRemovalOrder(ctx, tx, state, actor, "", now)
	if err != nil {
		return nil, err
	}
	return job, tx.Commit()
}

func authorizeRemoteRemovalSite(ctx context.Context, actor console.Account, siteID string) error {
	scope := selectedSite(ctx)
	if siteID == "" || scope != "" && scope != siteID || !actor.Can(console.PermissionAgentRemove, siteID) {
		return ErrNotFound
	}
	return nil
}

func (s *Server) insertRemoteRemovalOrder(ctx context.Context, tx *sql.Tx, state remoteRemovalState, actor console.Account, batchID string, now time.Time) (*remoteRemovalJob, error) {
	agentID, enrollmentID := state.AgentID, state.EnrollmentID
	// Only a durable start acknowledgement can lead to package removal.
	// An expired request or claim can be replaced without waiting for a report.
	if _, err := tx.ExecContext(ctx, `UPDATE remote_removal_orders SET state='expired',updated_at_ns=?,grant_json=NULL
 WHERE agent_id=? AND enrollment_id=? AND state IN ('queued','claimed') AND expires_at_ns<=?`,
		now.UnixNano(), agentID, enrollmentID, now.UnixNano()); err != nil {
		return nil, err
	}
	id, err := randomToken()
	if err != nil {
		return nil, err
	}
	order := managed.RemoteRemovalOrder{Contract: managed.RemoteRemovalContract, ID: "removal-" + id, AgentID: agentID, EnrollmentID: enrollmentID, IssuedAt: now, ExpiresAt: now.Add(managed.MaxRemoteRemovalLifetime)}
	signed, err := managed.SignRemoteRemovalOrder(order, s.material.PolicyKeyID, s.material.PolicyKey)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	job := &remoteRemovalJob{OrderID: order.ID, State: "queued", IssuedAt: order.IssuedAt, ExpiresAt: order.ExpiresAt, UpdatedAt: now}
	if _, err = tx.ExecContext(ctx, `INSERT INTO remote_removal_orders
 (id,agent_id,enrollment_id,issued_at_ns,expires_at_ns,updated_at_ns,actor,state,order_json)
 VALUES(?,?,?,?,?,?,?,'queued',?)`, order.ID, agentID, enrollmentID, now.UnixNano(), order.ExpiresAt.UnixNano(), now.UnixNano(), actor.Username, body); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO remote_removal_intents (order_id,site_id,actor_version,batch_id) VALUES (?,?,?,NULLIF(?,''))`,
		job.OrderID, state.SiteID, actor.Version, batchID); err != nil {
		return nil, err
	}
	if err = appendRemoteRemovalAudit(ctx, tx, authenticatedAgent{agentID, enrollmentID}, job, actor.Username, now); err != nil {
		return nil, err
	}
	return job, nil
}

// SetRemoteRemovalAccountLoader connects the managed API to the console's
// current account store. Set it before starting either HTTP listener.
func (s *Server) SetRemoteRemovalAccountLoader(loader func(context.Context, string) (console.Account, error)) {
	s.removalActors = loader
}

func (s *Server) remoteRemovalActorDenial(ctx context.Context, tx *sql.Tx, orderID, siteID string) (string, error) {
	if s.removalActors == nil {
		return "", errors.New("remote removal account directory unavailable")
	}
	var username, requestedSite string
	var version int64
	err := tx.QueryRowContext(ctx, `SELECT r.actor,i.site_id,i.actor_version FROM remote_removal_orders r
 JOIN remote_removal_intents i ON i.order_id=r.id WHERE r.id=?`, orderID).Scan(&username, &requestedSite, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "authorization_changed", nil
	}
	if err != nil {
		return "", err
	}
	if requestedSite != siteID {
		return "site_changed", nil
	}
	account, err := s.removalActors(ctx, username)
	if errors.Is(err, console.ErrAccountNotFound) {
		return "authorization_changed", nil
	}
	if err != nil {
		return "", err
	}
	if account.Username != username || account.Version != version || !account.Can(console.PermissionAgentRemove, siteID) {
		return "authorization_changed", nil
	}
	return "", nil
}

// Only a pre-start job can be cancelled on a changed permission or site.
// The same database transaction that examined the order records the terminal
// result, so a previously granted challenge cannot later get a start receipt.
func cancelChangedRemoteRemoval(ctx context.Context, tx *sql.Tx, agent authenticatedAgent, job *remoteRemovalJob, reason string, now time.Time) error {
	if job.State != "queued" && job.State != "claimed" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE remote_removal_orders SET state='cancelled',code=?,updated_at_ns=?,grant_json=NULL
 WHERE id=? AND state IN ('queued','claimed')`, reason, now.UnixNano(), job.OrderID); err != nil {
		return err
	}
	job.State, job.Code, job.UpdatedAt = "cancelled", reason, now
	if err := appendRemoteRemovalAudit(ctx, tx, agent, job, "", now); err != nil {
		return err
	}
	return tx.Commit()
}

func appendRemoteRemovalAudit(ctx context.Context, tx *sql.Tx, agent authenticatedAgent, job *remoteRemovalJob, actor string, now time.Time) error {
	details := map[string]string{"order_id": job.OrderID, "enrollment_id": agent.EnrollmentID}
	var batchID, siteID sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT batch_id,site_id FROM remote_removal_intents WHERE order_id=?", job.OrderID).Scan(&batchID, &siteID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if batchID.Valid {
		details["batch_id"] = batchID.String
	}
	if actor != "" {
		details["actor"] = actor
	}
	if job.Code != "" {
		details["code"] = job.Code
	}
	if siteID.Valid {
		return appendSiteAudit(ctx, tx, siteID.String, agent.ID, "removal.remote."+job.State, details, now)
	}
	return appendAudit(ctx, tx, agent.ID, "removal.remote."+job.State, details, now)
}
