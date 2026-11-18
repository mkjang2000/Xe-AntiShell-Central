package selfupdate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	workerRoot   = "/var/lib/xe-antishell-central-updater"
	centralState = "/var/lib/xe-antishell-central"
	centralUnit  = "sentinel-central.service"
	packageName  = "xe-antishell-central"
)

type Status struct {
	State          string    `json:"state"`
	CurrentVersion string    `json:"current_version,omitempty"`
	Target         string    `json:"target,omitempty"`
	Detail         string    `json:"detail,omitempty"`
	Backup         string    `json:"backup,omitempty"`
	SHA256         string    `json:"sha256,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

type workerJob struct {
	Status
	Previous string         `json:"previous,omitempty"`
	Manifest SignedManifest `json:"manifest"`
}

type worker struct {
	dir           string
	host          workerHost
	mu            sync.RWMutex
	job           workerJob
	intake        chan struct{}
	lock          *os.File
	claimed       bool // set only under intake, or before serving a recovered queued job
	intakeFailure chan error
}

func acquireWorker(dir string, host workerHost) (*worker, error) {
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 || fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("updater directory must be private and owned by the updater")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("another central updater owns the active job")
	}
	w := &worker{dir: dir, host: host, intake: make(chan struct{}, 1), intakeFailure: make(chan error, 1), lock: lock}
	w.job.State = "idle"
	data, err := os.ReadFile(filepath.Join(dir, "job.json"))
	if err == nil {
		if err = json.Unmarshal(data, &w.job); err != nil || !knownState(w.job.State) {
			lock.Close()
			return nil, errors.New("invalid persisted central update status")
		}
	} else if !os.IsNotExist(err) {
		lock.Close()
		return nil, err
	}
	return w, nil
}

func knownState(s string) bool {
	return activeState(s) || s == "idle" || s == "failed" || s == "succeeded" || s == "interrupted"
}
func activeState(s string) bool {
	switch s {
	case "queued", "stopping", "backup", "installing", "starting":
		return true
	}
	return false
}
func (w *worker) snapshot() workerJob { w.mu.RLock(); defer w.mu.RUnlock(); return w.job }

func syncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (w *worker) save(j workerJob) error {
	j.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(w.dir, ".job-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	cerr := tmp.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), filepath.Join(w.dir, "job.json")); err != nil {
		return err
	}
	// The rename is visible even if the directory sync subsequently fails.
	w.mu.Lock()
	w.job = j
	w.mu.Unlock()
	return syncDir(w.dir)
}

func (w *worker) transition(j *workerJob, state, detail string) error {
	j.State = state
	j.Detail = detail
	return w.save(*j)
}
