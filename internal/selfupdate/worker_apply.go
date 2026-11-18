package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type intakeError struct {
	code    int
	message string
}

func (e intakeError) Error() string { return e.message }
func conflict(msg string) error     { return intakeError{http.StatusConflict, msg} }
func invalid(msg string) error      { return intakeError{http.StatusBadRequest, msg} }

func (w *worker) accept(ctx context.Context, s SignedManifest, body io.Reader) (workerJob, bool, error) {
	select {
	case w.intake <- struct{}{}:
		defer func() { <-w.intake }()
	default:
		return workerJob{}, false, conflict("another central update is being submitted")
	}
	if err := VerifyManifest(s); err != nil {
		return workerJob{}, false, invalid("invalid central publisher signature")
	}
	if err := hostMatches(s); err != nil {
		return workerJob{}, false, conflict(err.Error())
	}
	return w.stage(ctx, s, body, VerifyRPM)
}
func hostMatches(s SignedManifest) error {
	major, err := LocalOSMajor()
	if err != nil || major != s.Manifest.OSMajor {
		return errors.New("central RPM does not match this host operating system or architecture")
	}
	return nil
}
func (w *worker) stage(ctx context.Context, s SignedManifest, body io.Reader, verify func(context.Context, string, SignedManifest) error) (workerJob, bool, error) {
	existing := w.snapshot()
	if w.claimed || activeState(existing.State) {
		if existing.SHA256 == s.Manifest.SHA256 {
			return existing, false, nil
		}
		return workerJob{}, false, conflict("another central update is active")
	}
	old, err := w.host.installed(ctx)
	if err != nil {
		return workerJob{}, false, conflict(err.Error())
	}
	target := versionFrom(s)
	if old == target && existing.State == "succeeded" && existing.SHA256 == s.Manifest.SHA256 {
		return existing, false, nil
	}
	if !strictlyNewer(old, target) {
		return workerJob{}, false, conflict("target must be newer than the installed central RPM and match its EL and architecture")
	}
	if err = w.host.running(ctx); err != nil {
		return workerJob{}, false, conflict(err.Error())
	}
	file, err := os.CreateTemp(w.dir, ".candidate-")
	if err != nil {
		return workerJob{}, false, err
	}
	defer file.Close()
	defer os.Remove(file.Name())
	n, err := io.Copy(file, io.LimitReader(body, s.Manifest.Size+1))
	if err != nil || n != s.Manifest.Size {
		return workerJob{}, false, invalid("central RPM body does not match the signed size")
	}
	if err = file.Sync(); err != nil {
		return workerJob{}, false, err
	}
	if err = file.Close(); err != nil {
		return workerJob{}, false, err
	}
	if err = verify(ctx, file.Name(), s); err != nil {
		return workerJob{}, false, invalid("central RPM digest or package metadata does not match the signed release")
	}
	if err = w.host.newer(ctx, old, file.Name()); err != nil {
		return workerJob{}, false, conflict(err.Error())
	}
	if err = w.host.space(ctx, w.dir); err != nil {
		return workerJob{}, false, conflict(err.Error())
	}
	path := filepath.Join(w.dir, "candidate.rpm")
	if err = os.Rename(file.Name(), path); err != nil {
		return workerJob{}, false, err
	}
	j := workerJob{Status: Status{CurrentVersion: old, Target: s.Manifest.Tag, SHA256: s.Manifest.SHA256}, Previous: old, Manifest: s}
	if err = w.transition(&j, "queued", "release verified and queued"); err != nil {
		select {
		case w.intakeFailure <- err:
		default:
		}
		return workerJob{}, false, err
	}
	w.claimed = true
	return w.snapshot(), true, nil
}
func (w *worker) run(j workerJob) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	path := filepath.Join(w.dir, "candidate.rpm")
	// Only a queued job can enter the transaction. Its files are private and
	// checked again so that restart never trusts an unverified stale payload.
	old, err := w.host.installed(ctx)
	if err == nil && (old != j.Previous || !strictlyNewer(old, versionFrom(j.Manifest))) {
		err = errors.New("installed central version changed since submission")
	}
	if err == nil {
		err = hostMatches(j.Manifest)
	}
	if err == nil {
		err = VerifyRPM(ctx, path, j.Manifest)
	}
	if err == nil {
		err = w.host.running(ctx)
	}
	if err == nil {
		err = w.host.space(ctx, w.dir)
	}
	if err != nil {
		return w.completeFailure(&j, err, false)
	}
	return w.apply(ctx, &j, path)
}
func (w *worker) apply(ctx context.Context, j *workerJob, path string) error {
	if err := w.transition(j, "stopping", "stopping central for an offline backup"); err != nil {
		return err
	}
	if err := w.host.stop(ctx); err != nil {
		return w.completeFailure(j, err, true)
	}
	if !w.host.stopped(ctx) {
		return w.completeFailure(j, errors.New("central did not reach inactive state"), true)
	}
	if err := w.transition(j, "backup", "creating and comparing a private state archive"); err != nil {
		return w.completeFailure(j, err, true)
	}
	backup, err := w.host.backup(ctx, w.dir)
	if err != nil {
		return w.completeFailure(j, err, true)
	}
	j.Backup = filepath.Join(w.dir, backup)
	actual, err := w.host.installed(ctx)
	if err != nil || actual != j.Previous || !w.host.stopped(ctx) {
		return w.completeFailure(j, errors.New("service or package changed during backup"), true)
	}
	if err = w.transition(j, "installing", "applying verified central RPM"); err != nil {
		return w.completeFailure(j, err, true)
	}
	if err = w.host.install(ctx, path); err != nil {
		return w.completeFailure(j, err, true)
	}
	if err = w.transition(j, "starting", "checking installed binary and central API readiness"); err != nil {
		return w.completeFailure(j, err, true)
	}
	target := versionFrom(j.Manifest)
	if err = w.host.startAndCheck(ctx, target); err != nil {
		return w.completeFailure(j, err, false)
	}
	j.CurrentVersion = target
	if err = w.transition(j, "succeeded", "central package and running service verified"); err != nil {
		return err
	}
	if err = pruneBackups(w.dir); err != nil {
		return w.transition(j, "succeeded", "central verified; old backup cleanup requires attention")
	}
	return nil
}
func (w *worker) completeFailure(j *workerJob, cause error, restoreService bool) error {
	detail := cause.Error()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	actual, err := w.host.installed(ctx)
	if err == nil {
		j.CurrentVersion = actual
	}
	if restoreService && err == nil && (actual == j.Previous || actual == versionFrom(j.Manifest)) {
		if err = w.host.startAndCheck(ctx, actual); err == nil {
			detail += "; installed central service is ready"
		} else {
			detail += "; manual service recovery required"
		}
	}
	if err = w.transition(j, "failed", detail); err != nil {
		return errors.Join(cause, err)
	}
	return errors.New(detail)
}
func (w *worker) recover() error {
	j := w.snapshot()
	if !activeState(j.State) || j.State == "queued" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target := versionFrom(j.Manifest)
	actual, err := w.host.installed(ctx)
	if err == nil && (actual == j.Previous || actual == target) {
		j.CurrentVersion = actual
		if err = w.host.startAndCheck(ctx, actual); err == nil {
			if actual == target && (j.State == "installing" || j.State == "starting") {
				return w.transition(&j, "succeeded", "recovered transaction; installed package and running central service verified")
			}
			return w.transition(&j, "interrupted", "previous service is ready; submit the release again to retry")
		}
	}
	return w.transition(&j, "interrupted", "transaction was interrupted; inspect installed RPM, service and state backup before retrying")
}

// Bootstrap uses the same private lock, signed artifact, offline backup and
// readiness path while upgrading a server that predates socket activation.
func Bootstrap(ctx context.Context, signed SignedManifest, rpm io.Reader) (Status, error) {
	if os.Geteuid() != 0 {
		return Status{}, errors.New("central bootstrap requires root")
	}
	if _, err := os.Lstat(updaterSocket); err == nil {
		return Status{}, errors.New("central updater socket already exists; use the regular update command")
	} else if !os.IsNotExist(err) {
		return Status{}, err
	}
	w, err := acquireWorker(workerRoot, systemHost{})
	if err != nil {
		return Status{}, err
	}
	defer w.lock.Close()
	clearPartial(w.dir)
	if err = w.recover(); err != nil {
		return w.snapshot().Status, err
	}
	j, created, err := w.accept(ctx, signed, rpm)
	if err != nil {
		return w.snapshot().Status, err
	}
	if created || j.State == "queued" {
		err = w.run(j)
	}
	status := w.snapshot().Status
	if err == nil && status.State != "succeeded" {
		err = fmt.Errorf("central bootstrap ended in %s", status.State)
	}
	return status, err
}
