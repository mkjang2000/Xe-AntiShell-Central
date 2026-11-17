package central

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (s *Server) recordUpdateReport(ctx context.Context, agent authenticatedAgent, report managed.UpdateReport) error {
	if report.Validate() != nil || report.EnrollmentID != agent.EnrollmentID || report.Sequence > 64 {
		return ErrInvalid
	}
	now := s.now().UTC()
	if report.ObservedAt.After(now.Add(time.Minute)) {
		return ErrInvalid
	}
	body, _ := json.Marshal(report)
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = currentUpdateAgent(ctx, tx, agent); err != nil {
		return err
	}
	job, err := loadUpdateJob(ctx, tx, report.JobID)
	if err != nil {
		return err
	}
	if job.agent != agent.ID || job.enrollment != agent.EnrollmentID || job.revision != report.Revision {
		return ErrConflict
	}
	var existing []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM update_reports WHERE job_id=? AND sequence=?", job.id, report.Sequence).Scan(&existing)
	if err == nil {
		if !bytes.Equal(body, existing) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err = expireUpdateJobs(ctx, tx, now); err != nil {
		return err
	}
	job, err = loadUpdateJob(ctx, tx, report.JobID)
	if err != nil {
		return err
	}
	if report.Sequence != job.sequence+1 {
		return ErrConflict
	}
	if updateTerminal(job.state) {
		if _, err = tx.ExecContext(ctx, "INSERT INTO update_reports(job_id,sequence,body,received_at_ns) VALUES(?,?,?,?)", job.id, report.Sequence, body, now.UnixNano()); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE update_jobs SET report_sequence=?,report_json=?,report_at_ns=?,last_report_late=1 WHERE id=?", report.Sequence, body, now.UnixNano(), job.id); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err = currentUpdateHead(ctx, tx, agent, job); err != nil {
		return err
	}
	if job.state == "queued" {
		return ErrConflict
	}
	rank := map[string]int{"offered": 0, "downloading": 1, "ready": 2, "installing": 3, "succeeded": 4, "failed": 4}
	if rank[report.State] < rank[job.state] {
		return ErrConflict
	}
	if report.State == "installing" && len(job.authorization) == 0 {
		return ErrConflict
	}
	if report.State == "succeeded" {
		if report.CollectionCheck != "verified" && report.CollectionCheck != "not_applicable" {
			return ErrConflict
		}
		if job.state != "installing" || len(job.authorization) == 0 {
			return ErrConflict
		}
		if report.InstalledPackage == nil || *report.InstalledPackage != job.release.Package || report.RunningVersion != job.release.Package.RunningVersion() {
			return ErrConflict
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO update_reports(job_id,sequence,body,received_at_ns) VALUES(?,?,?,?)", job.id, report.Sequence, body, now.UnixNano())
	if err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE update_jobs SET state=?,report_sequence=?,report_json=?,report_at_ns=?,error_code=? WHERE id=?", report.State, report.Sequence, body, now.UnixNano(), report.ErrorCode, job.id)
	}
	if err == nil && updateTerminal(report.State) {
		_, err = tx.ExecContext(ctx, "UPDATE update_heads SET active_job_id='' WHERE agent_id=? AND enrollment_id=? AND active_job_id=?", agent.ID, agent.EnrollmentID, job.id)
	}
	if err == nil && updateTerminal(report.State) {
		err = appendAudit(ctx, tx, agent.ID, "update.job."+report.State, map[string]any{"job_id": job.id, "revision": job.revision, "error_code": report.ErrorCode}, now)
	}
	if err == nil {
		err = expireUpdateJobs(ctx, tx, now)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
