package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type applicationStatus struct {
	State           string `json:"state"`
	DesiredRevision uint64 `json:"desired_revision"`
	ActiveRevision  uint64 `json:"active_revision,omitempty"`
	ReportedDigest  string `json:"reported_digest,omitempty"`
}

func matchesReportedPolicy(signed managed.SignedPolicy, status managed.PolicyStatus) bool {
	if !integrity.ValidDigest(status.PolicySHA256) || status.ActiveRevision != signed.Policy.Revision {
		return false
	}
	digest, err := integrity.PolicyDigest(signed)
	return err == nil && digest == status.PolicySHA256
}

// Only the immutable signed policy that matches a current agent receipt may be
// presented as applied. On a rejected replacement it can still be a prior revision.
func reportedApplicationPolicy(ctx context.Context, tx *sql.Tx, desired managed.SignedPolicy, raw []byte, seen int64, revoked bool, now time.Time) (*managed.Policy, applicationStatus, error) {
	p := desired.Policy
	out := applicationStatus{State: "unverified", DesiredRevision: p.Revision}
	var hb managed.Heartbeat
	if revoked {
		out.State = "stale"
		return nil, out, nil
	}
	if json.Unmarshal(raw, &hb) != nil || hb.AgentID != p.AgentID || hb.EnrollmentID != p.EnrollmentID {
		return nil, out, nil
	}
	fresh := func(at time.Time) bool {
		return !at.Before(now.Add(-2*time.Minute)) && !at.After(now.Add(time.Minute))
	}
	if !fresh(hb.SentAt) || !fresh(time.Unix(0, seen)) || hb.PolicyStatus.Result == "stale" {
		out.State = "stale"
		return nil, out, nil
	}
	status := hb.PolicyStatus
	out.ActiveRevision = status.ActiveRevision
	if status.ActiveRevision == 0 || status.ActiveRevision > p.Revision || (status.Result != "applied" && status.Result != "rejected") {
		return nil, out, nil
	}
	if status.PolicySHA256 != "" {
		if !integrity.ValidDigest(status.PolicySHA256) {
			out.State = "mismatch"
			return nil, out, nil
		}
		out.ReportedDigest = status.PolicySHA256
	}
	if status.DesiredRevision < status.ActiveRevision || status.DesiredRevision > p.Revision || (status.ActiveRevision == p.Revision && status.Result != "applied") {
		return nil, out, nil
	}
	signed := desired
	if status.ActiveRevision != p.Revision {
		var body []byte
		err := tx.QueryRowContext(ctx, "SELECT signed_json FROM policies WHERE agent_id=? AND enrollment_id=? AND revision=?", p.AgentID, p.EnrollmentID, status.ActiveRevision).Scan(&body)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, out, nil
		}
		if err != nil {
			return nil, out, err
		}
		if err = json.Unmarshal(body, &signed); err != nil {
			return nil, out, err
		}
	}
	legacy := status.PolicySHA256 == "" && len(signed.Policy.Applications) == 0
	if status.PolicySHA256 == "" && !legacy {
		return nil, out, nil
	}
	if !legacy && !matchesReportedPolicy(signed, status) {
		out.State = "mismatch"
		return nil, out, nil
	}
	if !now.Before(signed.Policy.ExpiresAt) {
		out.State = "stale"
		return nil, out, nil
	}
	out.State = "applied"
	if status.ActiveRevision != p.Revision {
		out.State = "previous"
	}
	if legacy {
		out.State = "legacy_" + out.State
	}
	return &signed.Policy, out, nil
}
