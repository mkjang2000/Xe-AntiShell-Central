package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const trialSchema = `CREATE TABLE IF NOT EXISTS policy_trials(id TEXT PRIMARY KEY,canary TEXT NOT NULL,phase TEXT NOT NULL,snapshot BLOB NOT NULL,template BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS policy_trial_reports(trial TEXT NOT NULL REFERENCES policy_trials(id),agent_id TEXT NOT NULL,sample_hash TEXT NOT NULL,report BLOB NOT NULL,PRIMARY KEY(trial,agent_id));`

type policyTrial struct {
	ID       string              `json:"id"`
	Canary   string              `json:"canary"`
	Phase    string              `json:"phase"`
	Snapshot consolePreviewToken `json:"-"`
	Template ConsoleTemplate     `json:"-"`
}
type trialStatus struct {
	Agent    string `json:"agent_id"`
	Baseline uint64 `json:"baseline"`
	Expected uint64 `json:"expected"`
	Desired  uint64 `json:"desired"`
	Active   uint64 `json:"active"`
	State    string `json:"state"`
	Compared bool   `json:"compared"`
}

func loadTrial(ctx context.Context, tx *sql.Tx, id string) (policyTrial, error) {
	var t policyTrial
	var snap, tpl []byte
	err := tx.QueryRowContext(ctx, "SELECT id,canary,phase,snapshot,template FROM policy_trials WHERE id=?", id).Scan(&t.ID, &t.Canary, &t.Phase, &snap, &tpl)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	if err = json.Unmarshal(snap, &t.Snapshot); err != nil {
		return t, err
	}
	return t, json.Unmarshal(tpl, &t.Template)
}
func (t policyTrial) target(agent string) (consoleDeployTarget, error) {
	for _, a := range t.Snapshot.Targets {
		if a.AgentID == agent {
			return a, nil
		}
	}
	return consoleDeployTarget{}, ErrNotFound
}
func (t policyTrial) revision(a consoleDeployTarget) uint64 {
	switch t.Phase {
	case "expanded":
		return a.NextRevision
	case "restoring_all":
		return a.NextRevision + 1
	case "canary":
		if a.AgentID == t.Canary {
			return a.NextRevision
		}
	case "restoring_canary":
		if a.AgentID == t.Canary {
			return a.NextRevision + 1
		}
	}
	return a.CurrentRevision
}
func trialHeartbeat(ctx context.Context, tx *sql.Tx, a consoleDeployTarget) (string, uint64, []byte, error) {
	var enrollment string
	var desired uint64
	var hb []byte
	err := tx.QueryRowContext(ctx, "SELECT enrollment_id,desired_policy_revision,heartbeat_json FROM agents WHERE agent_id=? AND revoked=0", a.AgentID).Scan(&enrollment, &desired, &hb)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return enrollment, desired, hb, err
}
func (t policyTrial) status(ctx context.Context, tx *sql.Tx, a consoleDeployTarget, now time.Time) (trialStatus, error) {
	out := trialStatus{Agent: a.AgentID, Baseline: a.CurrentRevision, Expected: t.revision(a), State: "pending"}
	enroll, desired, b, err := trialHeartbeat(ctx, tx, a)
	if errors.Is(err, ErrNotFound) {
		out.State = "superseded"
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Desired = desired
	var hb managed.Heartbeat
	_ = json.Unmarshal(b, &hb)
	out.Active = hb.PolicyStatus.ActiveRevision
	switch {
	case enroll != a.EnrollmentID || desired != out.Expected:
		out.State = "superseded"
	case hb.AgentID != a.AgentID || hb.EnrollmentID != enroll || hb.SentAt.Before(now.Add(-2*time.Minute)) || hb.SentAt.After(now.Add(time.Minute)):
		out.State = "stale"
	case hb.PolicyStatus.Result == "rejected" || hb.PolicyStatus.Result == "stale":
		out.State = hb.PolicyStatus.Result
	case hb.Status.Health != "healthy":
		out.State = "unhealthy"
	case out.Active == desired && hb.PolicyStatus.DesiredRevision == desired && hb.PolicyStatus.Result == "applied" && hb.PolicyStatus.AppliedAt != nil && !hb.PolicyStatus.AppliedAt.IsZero() && !hb.PolicyStatus.AppliedAt.After(now.Add(time.Minute)):
		var bytes []byte
		err := tx.QueryRowContext(ctx, "SELECT signed_json FROM policies WHERE agent_id=? AND enrollment_id=? AND revision=?", a.AgentID, a.EnrollmentID, desired).Scan(&bytes)
		if err != nil {
			return out, err
		}
		var signed managed.SignedPolicy
		if err = json.Unmarshal(bytes, &signed); err != nil {
			return out, err
		}
		if len(signed.Policy.Applications) != 0 && !matchesReportedPolicy(signed, hb.PolicyStatus) {
			out.State = "unverified"
		} else if !now.Before(signed.Policy.ExpiresAt) {
			out.State = "stale"
		} else {
			out.State = "applied"
		}
	}
	err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM policy_trial_reports WHERE trial=? AND agent_id=?)", t.ID, a.AgentID).Scan(&out.Compared)
	return out, err
}
func (t policyTrial) policies(ctx context.Context, tx *sql.Tx, a consoleDeployTarget) (managed.PolicyImpactInput, error) {
	var source []byte
	err := tx.QueryRowContext(ctx, "SELECT signed_json FROM policies WHERE agent_id=? AND enrollment_id=? AND revision=?", a.AgentID, a.EnrollmentID, a.CurrentRevision).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		return managed.PolicyImpactInput{}, fmt.Errorf("%w: 이전 서명 정책과 적용 리비전이 필요합니다", ErrInvalid)
	}
	if err != nil {
		return managed.PolicyImpactInput{}, err
	}
	var old managed.SignedPolicy
	if err = json.Unmarshal(source, &old); err != nil {
		return managed.PolicyImpactInput{}, err
	}
	return managed.PolicyImpactInput{TrialID: t.ID, EvaluatedAt: t.Snapshot.IssuedAt, Current: old.Policy, Candidate: t.Template.Settings.wirePolicy(t.Template.ID, a.AgentID, a.EnrollmentID, a.NextRevision, t.Snapshot.IssuedAt)}, nil
}
func (t policyTrial) input(ctx context.Context, tx *sql.Tx, a consoleDeployTarget) (managed.PolicyImpactInput, error) {
	in, err := t.policies(ctx, tx, a)
	if err == nil && (len(in.Current.Applications) != 0 || len(in.Candidate.Applications) != 0) {
		return managed.PolicyImpactInput{}, errApplicationComparison
	}
	return in, err
}

var errApplicationComparison = fmt.Errorf("%w: 현재 표본 비교기는 서비스별 독립 정책을 평가하지 않습니다. 일반 배포에서 대상 한 대를 선택해 확인하세요", ErrInvalid)

func (s *Server) createTrial(ctx context.Context, tx *sql.Tx, before consolePreviewToken, canary, actor string, now time.Time) (policyTrial, error) {
	id := "trial-" + before.Nonce
	t := policyTrial{ID: id, Canary: canary, Phase: "prepared", Snapshot: before}
	snap, tpl, err := consoleSnapshot(ctx, tx, before.Request, now)
	if err != nil {
		return t, err
	}
	if !sameConsoleSnapshot(before, snap) {
		return t, ErrConflict
	}
	if len(tpl.Settings.Applications) != 0 {
		return t, errApplicationComparison
	}
	t.Template = tpl
	if _, err = t.target(canary); err != nil {
		return t, ErrInvalid
	}
	if previous, err := loadTrial(ctx, tx, id); err == nil {
		if previous.Canary != canary {
			return t, ErrConflict
		}
		return previous, nil
	} else if !errors.Is(err, ErrNotFound) {
		return t, err
	}
	for _, a := range before.Targets {
		if a.CurrentRevision == 0 || a.NextRevision >= math.MaxInt64 {
			return t, fmt.Errorf("%w: 각 대상에 복구 가능한 서명 정책 리비전이 필요합니다", ErrInvalid)
		}
		st, err := t.status(ctx, tx, a, now)
		if err != nil {
			return t, err
		}
		if st.State != "applied" {
			return t, fmt.Errorf("%w: 현재 정책의 실제 적용과 정상 하트비트를 확인하세요", ErrInvalid)
		}
		if _, err = t.input(ctx, tx, a); err != nil {
			return t, err
		}
	}
	snapBody, err := json.Marshal(before)
	if err != nil {
		return t, err
	}
	templateBody, err := json.Marshal(tpl)
	if err != nil {
		return t, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO policy_trials VALUES(?,?,?,?,?)", id, canary, t.Phase, snapBody, templateBody)
	if err != nil {
		return t, err
	}
	return t, appendAudit(ctx, tx, "", "policy.trial.prepared", map[string]any{"trial": id, "actor": actor, "template": tpl.ID, "canary": canary}, now)
}
func (t policyTrial) review(ctx context.Context, tx *sql.Tx, a consoleDeployTarget, report managed.PolicyImpactReport, actor string, now time.Time) error {
	if t.Phase != "prepared" && t.Phase != "canary" {
		return ErrConflict
	}
	in, err := t.input(ctx, tx, a)
	if err != nil {
		return err
	}
	if err = report.ValidateFor(in); err != nil {
		return ErrInvalid
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var sample string
	err = tx.QueryRowContext(ctx, "SELECT sample_hash FROM policy_trial_reports WHERE trial=? LIMIT 1", t.ID).Scan(&sample)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if sample != "" && sample != report.SampleDigest {
		return ErrConflict
	}
	var old []byte
	err = tx.QueryRowContext(ctx, "SELECT report FROM policy_trial_reports WHERE trial=? AND agent_id=?", t.ID, a.AgentID).Scan(&old)
	if err == nil {
		if string(old) == string(body) {
			return nil
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO policy_trial_reports VALUES(?,?,?,?)", t.ID, a.AgentID, report.SampleDigest, body)
	if err != nil {
		return err
	}
	return appendAudit(ctx, tx, a.AgentID, "policy.trial.compared", map[string]any{"trial": t.ID, "actor": actor, "input": report.InputDigest, "sample": report.SampleDigest}, now)
}
