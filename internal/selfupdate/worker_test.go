package selfupdate

import (
	"context"
	"database/sql"
	"errors"
	_ "modernc.org/sqlite"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const oldVersion = "0.1.0-19.el9.x86_64"
const newVersion = "0.1.0-20.el9.x86_64"

type testHost struct {
	version string
	active  bool
	fail    string
	calls   []string
}

func (h *testHost) record(step string) error {
	h.calls = append(h.calls, step)
	if step == h.fail {
		return errors.New("fixture " + step + " failure")
	}
	return nil
}
func (h *testHost) installed(context.Context) (string, error) { return h.version, nil }
func (h *testHost) running(context.Context) error {
	if !h.active {
		return errors.New("not running")
	}
	return nil
}
func (h *testHost) newer(context.Context, string, string) error { return h.record("preflight") }
func (h *testHost) stop(context.Context) error {
	if err := h.record("stop"); err != nil {
		return err
	}
	h.active = false
	return nil
}
func (h *testHost) stopped(context.Context) bool { return !h.active }
func (h *testHost) backup(context.Context, string) (string, error) {
	return "backup-fixture.tar", h.record("backup")
}
func (h *testHost) space(context.Context, string) error { return h.record("space") }
func (h *testHost) install(context.Context, string) error {
	if err := h.record("install"); err != nil {
		return err
	}
	h.version = newVersion
	return nil
}
func (h *testHost) startAndCheck(_ context.Context, v string) error {
	if h.version != v {
		return errors.New("wrong installed version")
	}
	if err := h.record("start"); err != nil {
		return err
	}
	h.active = true
	return nil
}
func workerFixture(t *testing.T) (*worker, *testHost, SignedManifest) {
	t.Helper()
	h := &testHost{version: oldVersion, active: true}
	w, err := acquireWorker(filepath.Join(t.TempDir(), "worker"), h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.lock.Close() })
	m := SignedManifest{Manifest: Manifest{Tag: "v0.1.0-r20", ArtifactName: packageName + "-" + newVersion + ".rpm", SHA256: strings.Repeat("a", 64), Size: 3, OSMajor: "9"}}
	return w, h, m
}
func mockRPM(context.Context, string, SignedManifest) error { return nil }
func TestWorkerStageAndApplyOnce(t *testing.T) {
	ctx := context.Background()
	w, h, m := workerFixture(t)
	if _, err := acquireWorker(w.dir, h); err == nil {
		t.Fatal("second worker acquired root lock")
	}
	for _, size := range []string{"a", "abcd"} {
		if _, _, err := w.stage(ctx, m, strings.NewReader(size), mockRPM); err == nil {
			t.Fatal("incorrect body size accepted")
		}
	}
	j, created, err := w.stage(ctx, m, strings.NewReader("abc"), mockRPM)
	if err != nil || !created || j.State != "queued" {
		t.Fatal(j, created, err)
	}
	dup, created, err := w.stage(ctx, m, strings.NewReader("abc"), mockRPM)
	if err != nil || created || dup.SHA256 != j.SHA256 {
		t.Fatal(dup, created, err)
	}
	another := m
	another.Manifest.SHA256 = strings.Repeat("b", 64)
	if _, _, err = w.stage(ctx, another, strings.NewReader("abc"), mockRPM); err == nil {
		t.Fatal("concurrent update accepted")
	}
	if err = w.apply(ctx, &j, filepath.Join(w.dir, "candidate.rpm")); err != nil {
		t.Fatal(err)
	}
	want := []string{"preflight", "space", "stop", "backup", "install", "start"}
	if !reflect.DeepEqual(h.calls, want) || w.snapshot().State != "succeeded" || w.snapshot().CurrentVersion != newVersion {
		t.Fatal(h.calls, w.snapshot())
	}
	if _, _, err = w.stage(ctx, another, strings.NewReader("abc"), mockRPM); err == nil {
		t.Fatal("accepted a second launch during worker shutdown")
	}
	w.lock.Close()
	w2, e := acquireWorker(w.dir, h)
	if e != nil {
		t.Fatal(e)
	}
	defer w2.lock.Close()
	if w2.snapshot().Status != w.snapshot().Status {
		t.Fatalf("persisted status changed: %+v", w2.snapshot().Status)
	}
}
func TestWorkerFailureAndInterruptedRecovery(t *testing.T) {
	ctx := context.Background()
	for _, fail := range []string{"backup", "install", "start"} {
		t.Run(fail, func(t *testing.T) {
			w, h, m := workerFixture(t)
			j, newJob, err := w.stage(ctx, m, strings.NewReader("abc"), mockRPM)
			if err != nil || !newJob {
				t.Fatal(err)
			}
			h.fail = fail
			if err = w.apply(ctx, &j, "fixture.rpm"); err == nil || w.snapshot().State != "failed" {
				t.Fatal(w.snapshot(), err)
			}
			if fail == "backup" && (h.version != oldVersion || !h.active || strings.Contains(strings.Join(h.calls, ","), "install")) {
				t.Fatal(h.calls)
			}
			if fail == "install" && (h.version != oldVersion || !h.active || w.snapshot().Backup == "") {
				t.Fatal(h.calls)
			}
			if fail == "start" && (h.active || h.version != newVersion || w.snapshot().Backup == "") {
				t.Fatal(h.calls)
			}
		})
	}
	for _, state := range []string{"stopping", "backup", "installing", "starting"} {
		t.Run("recover-"+state, func(t *testing.T) {
			w, h, m := workerFixture(t)
			j, _, err := w.stage(ctx, m, strings.NewReader("abc"), mockRPM)
			if err != nil {
				t.Fatal(err)
			}
			if err = w.transition(&j, state, "fixture"); err != nil {
				t.Fatal(err)
			}
			h.active = false
			want := "interrupted"
			if state == "starting" {
				h.version = newVersion
				want = "succeeded"
			}
			h.calls = nil
			if err = w.recover(); err != nil || w.snapshot().State != want || !reflect.DeepEqual(h.calls, []string{"start"}) {
				t.Fatal(w.snapshot().State, h.calls, err)
			}
		})
	}
}
func TestWorkerValidatesOriginAndOrdering(t *testing.T) {
	if !strictlyNewer("0.1.0-9.el9.x86_64", "0.1.0-10.el9.x86_64") {
		t.Fatal("numeric release ordering")
	}
	for _, bad := range []string{oldVersion, "0.1.0-19.el10.x86_64", "0.1.0-19.el9.aarch64", "0.0.2-99.el9.x86_64", "0.9.9-1.el9.i386"} {
		if strictlyNewer(oldVersion, bad) {
			t.Fatal("bad target", bad)
		}
	}
	opts := []string{"/usr/sbin/sentinel-central", "serve", "--listen=0.0.0.0:19443", "--admin-listen", "127.0.0.1:19444", "--state-dir", centralState}
	addr, err := processConfig(opts)
	if err != nil || addr != "127.0.0.1:19444" {
		t.Fatal(addr, err)
	}
	for _, bad := range []string{"--state-dir=/", "--admin-listen=0.0.0.0:19", "--admin-listen=example.invalid:1"} {
		if _, e := processConfig(append(opts, bad)); e == nil {
			t.Fatal("accepted unsupported service args", bad)
		}
	}
	if _, e := processConfig([]string{"central", "serve", "--state-dir=/custom", "--panel-listen", "--state-dir=" + centralState}); e == nil {
		t.Fatal("mistook an unrelated flag value for the real state directory")
	}
	w, h, _ := workerFixture(t)
	r := httptest.NewRequest("POST", "http://localhost/apply", strings.NewReader("x"))
	r.Header.Set("Content-Type", "application/octet-stream")
	res := httptest.NewRecorder()
	w.handler(func(workerJob) { t.Fatal("invalid manifest started worker") }).ServeHTTP(res, r)
	if res.Code != 400 || len(h.calls) != 0 {
		t.Fatal(res.Code, h.calls)
	}
}
func TestStateBackupRestoresStoppedFiles(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "central")
	archive := filepath.Join(base, "backups")
	dest := filepath.Join(base, "restored")
	for _, d := range []string{state, archive, dest} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	expected := map[string]string{"state.json": "{}", "central.db": "database-fixture", "central.db-wal": "settled-WAL", "panel-accounts.db": "accounts", "ca-key.pem": "nonsecret unit-test payload"}
	for k, v := range expected {
		if e := os.WriteFile(filepath.Join(state, k), []byte(v), 0600); e != nil {
			t.Fatal(e)
		}
	}
	name, err := backupState(context.Background(), state, archive)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(archive, name))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal(fi, err)
	}
	if err = command(context.Background(), "/usr/bin/tar", "-xf", filepath.Join(archive, name), "-C", dest).Run(); err != nil {
		t.Fatal(err)
	}
	for k, v := range expected {
		got, err := os.ReadFile(filepath.Join(dest, "central", k))
		if err != nil || string(got) != v {
			t.Fatal(k, err)
		}
	}
	if err = os.Symlink("/not-read", filepath.Join(state, "external")); err != nil {
		t.Fatal(err)
	}
	if _, err = backupState(context.Background(), state, archive); err == nil {
		t.Fatal("archived nonlocal state")
	}
}

func TestBackupRestoresCommittedSQLiteWAL(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "original.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE checkpoint(seq INTEGER); INSERT INTO checkpoint VALUES(427)"); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	archives := filepath.Join(base, "archives")
	restored := filepath.Join(base, "restored")
	for _, dir := range []string{state, archives, restored} {
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Freeze the committed DB and WAL into an offline fixture while the original
	// connection keeps its WAL uncheckpointed. The restored DB must replay it.
	for _, suffix := range []string{"", "-wal"} {
		raw, e := os.ReadFile(source + suffix)
		if e != nil || len(raw) == 0 {
			t.Fatal(suffix, e)
		}
		if e = os.WriteFile(filepath.Join(state, "central.db"+suffix), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err = os.WriteFile(filepath.Join(state, "state.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := backupState(context.Background(), state, archives)
	if err != nil {
		t.Fatal(err)
	}
	if err = command(context.Background(), "/usr/bin/tar", "-xf", filepath.Join(archives, name), "-C", restored).Run(); err != nil {
		t.Fatal(err)
	}
	after, err := sql.Open("sqlite", filepath.Join(restored, "state", "central.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	var ack int
	if err = after.QueryRow("SELECT seq FROM checkpoint").Scan(&ack); err != nil || ack != 427 {
		t.Fatal(ack, err)
	}
}
