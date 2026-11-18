package central

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func fileAssignment(ctx context.Context, q updateReader, a authenticatedAgent, now time.Time) (*contract.Assignment, ConsoleIntegrity, error) {
	var settings ConsoleSettings
	var signed managed.SignedPolicy
	var sb, pb []byte
	err := q.QueryRowContext(ctx, `SELECT s.settings_json,p.signed_json FROM agents a JOIN console_policy_settings s ON (s.agent_id,s.enrollment_id,s.revision)=(a.agent_id,a.enrollment_id,a.desired_policy_revision) JOIN policies p ON (p.agent_id,p.enrollment_id,p.revision)=(s.agent_id,s.enrollment_id,s.revision) WHERE a.agent_id=? AND a.enrollment_id=? AND a.revoked=0`, a.ID, a.EnrollmentID).Scan(&sb, &pb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, settings.Integrity, nil
	}
	if err != nil {
		return nil, settings.Integrity, err
	}
	if err = json.Unmarshal(sb, &settings); err != nil {
		return nil, settings.Integrity, err
	}
	if err = json.Unmarshal(pb, &signed); err != nil {
		return nil, settings.Integrity, err
	}
	if !settings.Integrity.PackageFiles || !now.Before(signed.Policy.ExpiresAt) {
		return nil, settings.Integrity, nil
	}
	digest, err := contract.PolicyDigest(signed)
	return &contract.Assignment{EnrollmentID: a.EnrollmentID, Revision: signed.Policy.Revision, PolicySHA256: digest}, settings.Integrity, err
}

func (s *Server) fileIntegrityDesired(w http.ResponseWriter, r *http.Request, a authenticatedAgent) {
	assign, _, err := fileAssignment(r.Context(), s.store.db, a, s.now())
	if err != nil {
		s.apiError(w, "file integrity assignment", err)
		return
	}
	if assign == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	respond(w, http.StatusOK, assign)
}

func (s *Server) fileIntegrityReceived(w http.ResponseWriter, r *http.Request, a authenticatedAgent) {
	var report contract.Report
	if !decodeRequest(w, r, contract.MaxMessage, &report) {
		return
	}
	if err := s.saveFileReport(r.Context(), a, report); err != nil {
		s.apiError(w, "file integrity report", err)
		return
	}
	respond(w, http.StatusOK, map[string]bool{"received": true})
}

func (s *Server) saveFileReport(ctx context.Context, a authenticatedAgent, report contract.Report) error {
	now := s.now().UTC()
	if !report.Valid(now) || report.EnrollmentID != a.EnrollmentID {
		return ErrInvalid
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	assignment, _, err := fileAssignment(ctx, tx, a, now)
	if err != nil {
		return err
	}
	if assignment == nil || *assignment != report.Assignment {
		return ErrConflict
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var prev []byte
	var revision uint64
	var at int64
	err = tx.QueryRowContext(ctx, "SELECT revision,completed_at_ns,report_json FROM integrity_file_reports WHERE agent_id=? AND enrollment_id=?", a.ID, a.EnrollmentID).Scan(&revision, &at, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if revision == report.Revision && at >= report.CompletedAt.UnixNano() {
		if bytes.Equal(raw, prev) {
			return nil
		}
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO integrity_file_reports(agent_id,enrollment_id,revision,completed_at_ns,received_at_ns,report_json) VALUES(?,?,?,?,?,?) ON CONFLICT(agent_id,enrollment_id) DO UPDATE SET revision=excluded.revision,completed_at_ns=excluded.completed_at_ns,received_at_ns=excluded.received_at_ns,report_json=excluded.report_json`, a.ID, a.EnrollmentID, report.Revision, report.CompletedAt.UnixNano(), now.UnixNano(), raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type fileResult struct {
	State          string                 `json:"state"`
	Revision       uint64                 `json:"revision,omitempty"`
	Release        string                 `json:"release_sha256,omitempty"`
	ConfigBaseline string                 `json:"approved_config_sha256,omitempty"`
	PolicySHA256   string                 `json:"approved_policy_sha256,omitempty"`
	Package        string                 `json:"package,omitempty"`
	ReceivedAt     *time.Time             `json:"received_at,omitempty"`
	Files          map[string]fileVerdict `json:"files,omitempty"`
}

type fileVerdict struct {
	contract.Sample
	Expected string `json:"expected_sha256,omitempty"`
	Verdict  string `json:"verdict"`
}

func (s *Server) consoleFileIntegrity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !identifierPattern.MatchString(id) {
		s.consoleError(w, "file integrity", ErrInvalid)
		return
	}
	result, err := s.fileResults(r.Context(), id)
	if err != nil {
		s.consoleError(w, "file integrity", err)
		return
	}
	respond(w, http.StatusOK, result)
}

func (s *Server) fileResults(ctx context.Context, id string) (fileResult, error) {
	var r fileResult
	var a authenticatedAgent
	a.ID = id
	var heartbeat []byte
	var invRaw, reportRaw []byte
	var received, inventoryAt int64
	err := s.store.db.QueryRowContext(ctx, `SELECT a.enrollment_id,a.heartbeat_json,i.inventory_json,coalesce(i.received_at_ns,0),r.report_json,coalesce(r.received_at_ns,0) FROM agents a LEFT JOIN update_inventory i ON (i.agent_id,i.enrollment_id)=(a.agent_id,a.enrollment_id) LEFT JOIN integrity_file_reports r ON (r.agent_id,r.enrollment_id)=(a.agent_id,a.enrollment_id) WHERE a.agent_id=? AND a.revoked=0`, id).Scan(&a.EnrollmentID, &heartbeat, &invRaw, &inventoryAt, &reportRaw, &received)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	now := s.now().UTC()
	assign, settings, err := fileAssignment(ctx, s.store.db, a, now)
	if err != nil {
		return r, err
	}
	if assign == nil {
		r.State = "disabled"
		if settings.PackageFiles {
			r.State = "policy_expired"
		}
		return r, nil
	}
	r.Revision = assign.Revision
	r.PolicySHA256 = assign.PolicySHA256
	r.ConfigBaseline = settings.ConfigSHA256
	var hb managed.Heartbeat
	_ = json.Unmarshal(heartbeat, &hb)
	var supported bool
	if hb.Status.CapabilityReport != nil {
		c := hb.Status.CapabilityReport.Capabilities["integrity.agent_files"]
		supported = c.Implementation == "implemented" && c.Details["contract"] == "1"
	}
	if !supported {
		r.State = "unverified_support"
		return r, nil
	}
	var report contract.Report
	if len(reportRaw) == 0 {
		r.State = "awaiting_measurement"
		return r, nil
	}
	if err = json.Unmarshal(reportRaw, &report); err != nil {
		return r, err
	}
	if report.Assignment != *assign {
		r.State = "awaiting_measurement"
		return r, nil
	}
	r.ReceivedAt = timePointer(received)
	r.Package = report.Package.RunningVersion()
	var inv managed.UpdateInventory
	if len(invRaw) > 0 {
		if err = json.Unmarshal(invRaw, &inv); err != nil {
			return r, err
		}
	}
	freshInventory := inventoryAt != 0 && !inv.ObservedAt.Before(now.Add(-10*time.Minute)) && !time.Unix(0, inventoryAt).Before(now.Add(-10*time.Minute))
	packageState := ""
	if !freshInventory || inv.InstalledPackage == nil {
		packageState = "inventory_unverified"
	} else if *inv.InstalledPackage != report.Package || inv.RunningVersion != r.Package || hb.Status.Version != r.Package {
		packageState = "update_in_progress"
	}
	var files map[string]string
	var approved bool
	if packageState == "" {
		r.Release, files, approved, err = s.fileReleaseEvidence(ctx, a, report)
		if err != nil {
			return r, err
		}
	}
	if hb.PolicyStatus.ActiveRevision != assign.Revision && packageState == "" {
		packageState = "inventory_unverified"
	}
	return evaluateFileReport(r, report, files, settings.ConfigSHA256, packageState, approved, now), nil
}

// A successful job may explain measured files only if the central server
// recorded that enrollment's update before the measurement completed.
func (s *Server) fileReleaseEvidence(ctx context.Context, a authenticatedAgent, report contract.Report) (string, map[string]string, bool, error) {
	items, err := listUpdateReleases(ctx, s.store.db)
	if err != nil {
		return "", nil, false, err
	}
	for _, release := range items {
		if release.Package != report.Package {
			continue
		}
		files, err := s.packageBaselines(ctx, release)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) {
			return release.ID, nil, false, nil
		}
		if err != nil {
			return "", nil, false, err
		}
		var approved bool
		err = s.store.db.QueryRowContext(ctx, `SELECT EXISTS(
    SELECT 1 FROM update_jobs j JOIN update_rollouts u ON u.id=j.rollout_id
    WHERE j.agent_id=? AND j.enrollment_id=? AND u.release_id=? AND j.state='succeeded'
    AND j.report_at_ns BETWEEN ? AND ?)`, a.ID, a.EnrollmentID, release.ID, report.CompletedAt.Add(-contract.FreshFor).UnixNano(), report.CompletedAt.UnixNano()).Scan(&approved)
		return release.ID, files, approved, err
	}
	return "", nil, false, nil
}

// Keep each file's observed outcome and freshness alongside its expected digest.
func evaluateFileReport(r fileResult, report contract.Report, baselines map[string]string, configSHA, packageState string, approved bool, now time.Time) fileResult {
	r.Files = map[string]fileVerdict{}
	r.State = "matched"
	priority := map[string]int{"matched": 0, "baseline_missing": 1, "inventory_unverified": 2, "update_in_progress": 3, "stale": 4, "too_large": 5, "unreadable": 6, "changed_during_read": 7, "missing": 8, "mismatch": 9}
	targets := contract.Targets()
	targets["signed-policy"] = ""
	for id := range targets {
		sample := report.Samples[id]
		expected := baselines[id]
		if id == contract.ConfigID {
			expected = configSHA
		}
		if id == "signed-policy" {
			expected = report.PolicySHA256
			sample = report.RulePolicy
		}
		v := fileVerdict{Sample: sample, Expected: expected}
		switch {
		case now.Sub(sample.MeasuredAt) >= contract.FreshFor:
			v.Verdict = "stale"
		case sample.State != "measured":
			v.Verdict = sample.State
		case id != contract.ConfigID && id != "signed-policy" && packageState != "":
			v.Verdict = packageState
		case expected == "":
			v.Verdict = "baseline_missing"
		case expected != sample.SHA256:
			v.Verdict = "mismatch"
		default:
			v.Verdict = "matched"
		}
		r.Files[id] = v
		if priority[v.Verdict] > priority[r.State] {
			r.State = v.Verdict
		}
	}
	if r.State == "matched" && approved {
		r.State = "approved_update"
	}
	return r
}
