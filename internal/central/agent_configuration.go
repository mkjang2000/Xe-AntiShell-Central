package central

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const agentConfigurationSchema = `
CREATE TABLE IF NOT EXISTS agent_configurations(
  agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,revision INTEGER NOT NULL,
  signed_json BLOB NOT NULL,expires_at_ns INTEGER NOT NULL,rejected_at_ns INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(agent_id,enrollment_id,revision));
`

const (
	agentConfigurationLifetime  = 15 * time.Minute
	agentConfigurationFreshness = 2 * time.Minute
)

type agentConfigurationState struct {
	AgentID         string                            `json:"agent_id"`
	EnrollmentID    string                            `json:"enrollment_id"`
	Supported       bool                              `json:"supported"`
	Fresh           bool                              `json:"fresh"`
	DesiredRevision uint64                            `json:"desired_revision"`
	Report          *managed.AgentConfigurationReport `json:"report,omitempty"`
	AssignmentState string                            `json:"assignment_state"`
	heartbeat       managed.Heartbeat
}

func loadAgentConfigurationState(ctx context.Context, tx *sql.Tx, agentID string, now time.Time) (agentConfigurationState, error) {
	state := agentConfigurationState{AgentID: agentID, AssignmentState: "local"}
	if !identifierPattern.MatchString(agentID) {
		return state, ErrInvalid
	}
	var heartbeat []byte
	var receivedNS int64
	var expiresNS, rejectedNS sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT a.enrollment_id,a.heartbeat_json,a.last_seen_at_ns,
 COALESCE(c.revision,0),c.expires_at_ns,c.rejected_at_ns FROM agents a LEFT JOIN agent_configurations c
 ON (c.agent_id,c.enrollment_id,c.revision)=(a.agent_id,a.enrollment_id,
 (SELECT max(revision) FROM agent_configurations WHERE agent_id=a.agent_id AND enrollment_id=a.enrollment_id))
 WHERE a.agent_id=? AND a.revoked=0`, agentID).Scan(&state.EnrollmentID, &heartbeat, &receivedNS, &state.DesiredRevision, &expiresNS, &rejectedNS)
	if errors.Is(err, sql.ErrNoRows) {
		return state, ErrNotFound
	}
	if err != nil {
		return state, err
	}
	state.heartbeat = decodePolicyHeartbeat(heartbeat)
	state.Report, state.Supported, state.Fresh = readAgentConfigurationReport(state.heartbeat, agentID, state.EnrollmentID, receivedNS, now)
	if state.DesiredRevision == 0 {
		return state, nil
	}
	switch {
	case rejectedNS.Int64 != 0:
		state.AssignmentState = "rejected"
	case state.Report != nil && state.Report.AppliedRevision == state.DesiredRevision:
		state.AssignmentState = "applied"
	case expiresNS.Valid && now.UnixNano() >= expiresNS.Int64:
		state.AssignmentState = "expired"
	default:
		state.AssignmentState = "pending"
	}
	return state, nil
}

func readAgentConfigurationReport(h managed.Heartbeat, agentID, enrollmentID string, receivedNS int64, now time.Time) (*managed.AgentConfigurationReport, bool, bool) {
	if h.AgentID != agentID || h.EnrollmentID != enrollmentID || h.Status.CapabilityReport == nil {
		return nil, false, false
	}
	capability := h.Status.CapabilityReport.Capabilities[managed.AgentConfigurationCapability]
	if capability.Details["contract"] != managed.AgentConfigurationContract {
		return nil, false, false
	}
	received := time.Unix(0, receivedNS)
	fresh := receivedNS != 0 && !received.Before(now.Add(-agentConfigurationFreshness)) && !received.After(now) &&
		!h.SentAt.Before(now.Add(-agentConfigurationFreshness)) && !h.SentAt.After(now.Add(time.Minute))
	var report managed.AgentConfigurationReport
	raw := capability.Details["snapshot"]
	if managed.DecodeStrict([]byte(raw), managed.MaxAgentConfigurationBytes, &report) != nil || !validAgentConfigurationReport(report) {
		return nil, true, fresh
	}
	return &report, true, fresh
}

func validAgentConfigurationReport(report managed.AgentConfigurationReport) bool {
	if report.AppliedRevision > report.RequestedRevision || report.RequestedRevision > math.MaxInt64 || len(report.Error) > 1024 {
		return false
	}
	switch report.Result {
	case "local":
		if report.AppliedRevision != 0 || report.RequestedRevision != 0 {
			return false
		}
	case "applied":
		if report.AppliedRevision == 0 || report.AppliedRevision != report.RequestedRevision || report.AppliedAt == nil {
			return false
		}
	case "rejected":
		if report.RequestedRevision <= report.AppliedRevision {
			return false
		}
	default:
		return false
	}
	cfg := report.Effective
	return cfg.SampleIntervalSeconds >= 5 && cfg.SampleIntervalSeconds <= 3600 &&
		cfg.HeartbeatIntervalSeconds >= 5 && cfg.HeartbeatIntervalSeconds <= 3600 &&
		cfg.ObservationHistoryMinutes >= 0 && cfg.ObservationHistoryMinutes <= 1440 &&
		cfg.MaxObservationHistoryMinutes >= 0 && cfg.MaxObservationHistoryMinutes <= 1440 &&
		cfg.RetentionDays >= 1 && cfg.RetentionDays <= 3650 &&
		cfg.LocalObservationHistoryMinutes >= 0 && cfg.LocalObservationHistoryMinutes <= 1440 &&
		cfg.LocalRetentionDays >= 1 && cfg.LocalRetentionDays <= 3650 &&
		(cfg.PanelAccess == "allow" || cfg.PanelAccess == "block")
}

// Keep a terminal rejection across restarts of the enrolled agent. The heartbeat
// already authenticated the sender and updated the current enrollment in this
// transaction. An unsupported or malformed capability does not affect delivery.
func recordAgentConfigurationRejection(ctx context.Context, tx *sql.Tx, agentID string, hb managed.Heartbeat, now time.Time) error {
	report, _, fresh := readAgentConfigurationReport(hb, agentID, hb.EnrollmentID, now.UnixNano(), now)
	if !fresh || report == nil || report.Result != "rejected" {
		return nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_configurations SET rejected_at_ns=?
WHERE agent_id=? AND enrollment_id=? AND revision=? AND rejected_at_ns=0 AND revision=(
 SELECT max(revision) FROM agent_configurations WHERE agent_id=? AND enrollment_id=?)`,
		now.UnixNano(), agentID, hb.EnrollmentID, report.RequestedRevision, agentID, hb.EnrollmentID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return err
	}
	return appendAudit(ctx, tx, agentID, "agent_configuration.rejected", map[string]any{
		"enrollment_id": hb.EnrollmentID, "revision": report.RequestedRevision, "applied_revision": report.AppliedRevision,
	}, now)
}

func assignedAgentConfiguration(ctx context.Context, tx *sql.Tx, agentID, enrollmentID string, revision uint64) (managed.AgentConfiguration, error) {
	if revision == 0 {
		return managed.AgentConfiguration{}, nil
	}
	var body []byte
	var rejectedAt int64
	err := tx.QueryRowContext(ctx, "SELECT signed_json,rejected_at_ns FROM agent_configurations WHERE agent_id=? AND enrollment_id=? AND revision=?",
		agentID, enrollmentID, revision).Scan(&body, &rejectedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return managed.AgentConfiguration{}, fmt.Errorf("%w: 적용된 원격 설정의 원본을 찾을 수 없습니다", ErrConflict)
	}
	if err != nil {
		return managed.AgentConfiguration{}, err
	}
	var signed managed.SignedAgentConfiguration
	if err = managed.DecodeStrict(body, managed.MaxAgentConfigurationBytes, &signed); err != nil {
		return managed.AgentConfiguration{}, err
	}
	config := signed.Configuration
	if rejectedAt != 0 || config.AgentID != agentID || config.EnrollmentID != enrollmentID || config.Revision != revision {
		return managed.AgentConfiguration{}, ErrConflict
	}
	return config, nil
}

func (s *Server) agentConfiguration(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	var signed []byte
	var rejectedAt, expiresAt int64
	now := s.now().UTC()
	err := s.store.db.QueryRowContext(r.Context(), `SELECT c.signed_json,c.rejected_at_ns,c.expires_at_ns FROM agent_configurations c
 JOIN agents a ON (a.agent_id,a.enrollment_id)=(c.agent_id,c.enrollment_id)
 WHERE c.agent_id=? AND c.enrollment_id=? AND a.revoked=0 ORDER BY c.revision DESC LIMIT 1`,
		agent.ID, agent.EnrollmentID).Scan(&signed, &rejectedAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		s.apiError(w, "agent configuration read", err)
		return
	}
	if rejectedAt != 0 || now.UnixNano() >= expiresAt {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var body managed.SignedAgentConfiguration
	if err = managed.DecodeStrict(signed, managed.MaxAgentConfigurationBytes, &body); err != nil {
		s.apiError(w, "agent configuration decode", err)
		return
	}
	if !body.Configuration.ExpiresAt.After(now) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	respond(w, http.StatusOK, body)
}
