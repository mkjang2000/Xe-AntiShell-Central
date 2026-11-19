package central

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const trialTicketSchema = `CREATE TABLE IF NOT EXISTS policy_trial_tickets(trial TEXT NOT NULL,phase TEXT NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,digest TEXT NOT NULL,expires_at_ns INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(trial,phase,action));`

type trialAction struct {
	Action string `json:"action"`
	Phase  string `json:"phase"`
	Token  string `json:"confirmation,omitempty"`
	Note   string `json:"note,omitempty"`
}
type trialActionPlan struct {
	Next     string            `json:"next_phase"`
	Targets  []string          `json:"targets"`
	Expected map[string]uint64 `json:"new_revisions"`
	Token    string            `json:"confirmation,omitempty"`
	Expires  time.Time         `json:"expires_at"`
}

func (t policyTrial) plan(ctx context.Context, tx *sql.Tx, req trialAction, now time.Time) (trialActionPlan, error) {
	out := trialActionPlan{Expected: map[string]uint64{}}
	if req.Phase != t.Phase {
		return out, ErrConflict
	}
	switch {
	case req.Action == "canary" && t.Phase == "prepared":
		out.Next = "canary"
	case req.Action == "promote" && t.Phase == "canary":
		out.Next = "expanded"
	case req.Action == "restore" && t.Phase == "canary":
		out.Next = "restoring_canary"
	case req.Action == "restore" && t.Phase == "expanded":
		out.Next = "restoring_all"
	default:
		return out, ErrInvalid
	}
	if req.Action != "restore" {
		current, _, err := consoleSnapshot(ctx, tx, t.Snapshot.Request, now)
		if err != nil {
			return out, err
		}
		expected := t.Snapshot
		expected.Targets = append([]consoleDeployTarget(nil), t.Snapshot.Targets...)
		for i, a := range expected.Targets {
			expected.Targets[i].CurrentRevision = t.revision(a)
			expected.Targets[i].NextRevision = t.revision(a) + 1
		}
		if !sameConsoleSnapshot(expected, current) {
			return out, ErrConflict
		}
	}
	for _, a := range t.Snapshot.Targets {
		// A recovery touches only the agents previously assigned by this trial.
		if req.Action == "restore" && t.Phase == "canary" && a.AgentID != t.Canary {
			continue
		}
		st, err := t.status(ctx, tx, a, now)
		if err != nil {
			return out, err
		}
		if st.State == "superseded" {
			return out, ErrConflict
		}
		if req.Action != "restore" && st.State != "applied" {
			return out, fmt.Errorf("%w: %s의 정상 하트비트와 실제 적용 리비전을 확인하세요", ErrConflict, a.AgentID)
		}
		if req.Action != "restore" {
			input, err := t.input(ctx, tx, a)
			if err != nil {
				return out, err
			}
			for _, d := range []managed.DetectionPolicy{input.Current.Detection, input.Candidate.Detection} {
				for _, rule := range d.ServiceRuleControls {
					if rule.Allows(input.EvaluatedAt) != rule.Allows(now) {
						return out, fmt.Errorf("%w: 평가 후 규칙 예외가 만료되었습니다. 새 비교가 필요합니다", ErrConflict)
					}
				}
			}
		}
		if req.Action == "canary" && a.AgentID != t.Canary {
			continue
		}
		if req.Action == "promote" && a.AgentID == t.Canary {
			continue
		}
		if req.Action != "restore" && !st.Compared {
			return out, fmt.Errorf("%w: %s의 비교 결과가 필요합니다", ErrInvalid, a.AgentID)
		}
		if req.Action == "restore" {
			in, err := t.policies(ctx, tx, a)
			if err != nil {
				return out, err
			}
			_, _, hb, err := trialHeartbeat(ctx, tx, a)
			if err != nil {
				return out, err
			}
			if err = requireDetectionPolicySupport(in.Current.Detection, in.Current.Applications, hb, a.AgentID, a.EnrollmentID, now); err != nil {
				return out, err
			}
		}
		out.Targets = append(out.Targets, a.AgentID)
		out.Expected[a.AgentID] = st.Expected + 1
	}
	if len(out.Targets) == 0 && req.Action != "promote" {
		return out, fmt.Errorf("%w: 단계 배포에 추가 대상이 없습니다", ErrInvalid)
	}
	return out, nil
}

func (s *Server) trialAction(ctx context.Context, tx *sql.Tx, t policyTrial, req trialAction, actor string, confirm bool, now time.Time) (trialActionPlan, error) {
	var out trialActionPlan
	if confirm {
		var digest, issuedActor string
		var expiry int64
		var used bool
		err := tx.QueryRowContext(ctx, "SELECT digest,actor,expires_at_ns,used FROM policy_trial_tickets WHERE trial=? AND phase=? AND action=?", t.ID, req.Phase, req.Action).Scan(&digest, &issuedActor, &expiry, &used)
		if errors.Is(err, sql.ErrNoRows) {
			return out, ErrConflict
		}
		if err != nil {
			return out, err
		}
		hash, _ := consoleHash(req.Token)
		if req.Token == "" || actor != issuedActor || subtle.ConstantTimeCompare([]byte(digest), []byte(hash)) != 1 {
			return out, ErrConflict
		}
		if used {
			return trialActionPlan{Next: t.Phase}, nil
		}
		if now.UnixNano() >= expiry {
			return out, ErrConflict
		}
		if len(req.Note) > 2048 || !validText(req.Note, true) || req.Action == "promote" && req.Note == "" {
			return out, fmt.Errorf("%w: 선행 호스트에서 확인한 수집·경보·부하 결과를 입력하세요", ErrInvalid)
		}
	}
	out, err := t.plan(ctx, tx, req, now)
	if err != nil {
		return out, err
	}
	if !confirm {
		out.Token, err = randomToken()
		if err != nil {
			return out, err
		}
		digest, _ := consoleHash(out.Token)
		out.Expires = now.Add(previewLifetime)
		_, err = tx.ExecContext(ctx, `INSERT INTO policy_trial_tickets VALUES(?,?,?,?,?,?,0) ON CONFLICT(trial,phase,action) DO UPDATE SET actor=excluded.actor,digest=excluded.digest,expires_at_ns=excluded.expires_at_ns,used=0`, t.ID, t.Phase, req.Action, actor, digest, out.Expires.UnixNano())
		return out, err
	}
	for _, id := range out.Targets {
		a, _ := t.target(id)
		rev := out.Expected[id]
		policy := t.Template.Settings.wirePolicy(t.Template.ID, id, a.EnrollmentID, rev, now)
		settings, err := json.Marshal(t.Template.Settings)
		if err != nil {
			return out, err
		}
		if req.Action == "restore" {
			in, err := t.policies(ctx, tx, a)
			if err != nil {
				return out, err
			}
			policy = in.Current
			life := policy.ExpiresAt.Sub(policy.IssuedAt)
			policy.Revision = rev
			policy.IssuedAt = now
			policy.ExpiresAt = now.Add(life)
			settings = nil
			err = tx.QueryRowContext(ctx, "SELECT settings_json FROM console_policy_settings WHERE agent_id=? AND enrollment_id=? AND revision=?", id, a.EnrollmentID, a.CurrentRevision).Scan(&settings)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return out, err
			}
		}
		if err = s.issueConsolePolicy(ctx, tx, policy, rev-1, settings, now, map[string]any{"trial": t.ID, "actor": actor, "action": req.Action, "revision": rev, "enrollment_id": a.EnrollmentID, "policy_id": policy.ID}); err != nil {
			return out, err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE policy_trial_tickets SET used=1 WHERE trial=? AND phase=? AND action=?", t.ID, t.Phase, req.Action); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE policy_trials SET phase=? WHERE id=?", out.Next, t.ID); err != nil {
		return out, err
	}
	return out, appendAudit(ctx, tx, "", "policy.trial."+req.Action, map[string]any{"trial": t.ID, "actor": actor, "targets": len(out.Targets), "note": req.Note}, now)
}

func (s *Server) issueConsolePolicy(ctx context.Context, tx *sql.Tx, p managed.Policy, previous uint64, settings []byte, now time.Time, audit map[string]any) error {
	signed, err := managed.SignPolicy(p, s.material.PolicyKeyID, s.material.PolicyKey)
	if err != nil {
		return fmt.Errorf("%w: 이 대상에 적용할 수 없는 정책입니다", ErrInvalid)
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO policies(agent_id,enrollment_id,revision,signed_json) VALUES(?,?,?,?)", p.AgentID, p.EnrollmentID, p.Revision, body); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "UPDATE agents SET desired_policy_revision=? WHERE agent_id=? AND enrollment_id=? AND desired_policy_revision=? AND revoked=0", p.Revision, p.AgentID, p.EnrollmentID, previous)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	if len(settings) > 0 {
		if _, err = tx.ExecContext(ctx, "INSERT INTO console_policy_settings(agent_id,enrollment_id,revision,settings_json) VALUES(?,?,?,?)", p.AgentID, p.EnrollmentID, p.Revision, settings); err != nil {
			return err
		}
	}
	return appendAudit(ctx, tx, p.AgentID, "policy.assigned", audit, now)
}
