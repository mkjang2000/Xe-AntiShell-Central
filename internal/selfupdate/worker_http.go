package selfupdate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func workerJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func workerProblem(w http.ResponseWriter, code int, message string) {
	workerJSON(w, code, map[string]string{"error": message})
}

func (w *worker) handler(start func(workerJob)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(out http.ResponseWriter, r *http.Request) {
		j := w.snapshot()
		if v, err := w.host.installed(r.Context()); err == nil {
			j.CurrentVersion = v
		} else if j.State == "idle" {
			j.Detail = err.Error()
		}
		workerJSON(out, 200, j.Status)
	})
	mux.HandleFunc("POST /apply", func(out http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			workerProblem(out, 415, "central update requires an RPM body")
			return
		}
		encoded := r.Header.Get("X-Xeas-Central-Manifest")
		if len(encoded) > base64.RawURLEncoding.EncodedLen(MaxManifestBytes) {
			workerProblem(out, 400, "manifest exceeds size limit")
			return
		}
		data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			workerProblem(out, 400, "invalid encoded central manifest")
			return
		}
		s, err := DecodeManifest(data)
		if err != nil {
			workerProblem(out, 400, "central publisher manifest verification failed")
			return
		}
		if r.ContentLength != s.Manifest.Size {
			workerProblem(out, 400, "RPM length does not match manifest")
			return
		}
		j, created, err := w.accept(r.Context(), s, http.MaxBytesReader(out, r.Body, MaxRPMBytes))
		if err != nil {
			var e intakeError
			if errors.As(err, &e) {
				workerProblem(out, e.code, e.message)
			} else {
				workerProblem(out, 500, "could not stage the central update")
			}
			return
		}
		// Send the job acknowledgement before an independent worker stops the console.
		workerJSON(out, http.StatusAccepted, j.Status)
		if f, ok := out.(http.Flusher); ok {
			f.Flush()
		}
		if created {
			start(j)
		}
	})
	return mux
}

// ServeWorker accepts exactly one systemd-owned Unix socket. The descriptor is
// kept by systemd across upgrades; a completed job exits to load the new binary.
func ServeWorker() error {
	if os.Geteuid() != 0 || os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return errors.New("central updater requires root and systemd socket activation")
	}
	f := os.NewFile(3, "central-updater-socket")
	if f == nil {
		return errors.New("missing activation socket")
	}
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return err
	}
	defer ln.Close()
	if ln.Addr().Network() != "unix" || ln.Addr().String() != updaterSocket {
		return errors.New("unexpected central updater socket")
	}
	w, err := acquireWorker(workerRoot, systemHost{})
	if err != nil {
		return err
	}
	defer w.lock.Close()
	clearPartial(w.dir)
	if err = w.recover(); err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 3 * time.Minute, WriteTimeout: 3 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	start := func(j workerJob) {
		go func() {
			err := w.run(j)
			// Only one accepted job runs per server lifetime. After any result
			// systemd holds the socket while readers reconnect to the new worker.
			done <- err
		}()
	}
	server.Handler = w.handler(start)
	serveDone := make(chan error, 1)
	if j := w.snapshot(); j.State == "queued" {
		w.claimed = true
		start(j)
	}
	go func() { serveDone <- server.Serve(ln) }()
	select {
	case err = <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err = <-done:
		if !activeState(w.snapshot().State) {
			err = nil
		}
	case err = <-w.intakeFailure:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if server.Shutdown(shutdown) != nil {
		_ = server.Close()
	}
	<-serveDone
	return err
}
