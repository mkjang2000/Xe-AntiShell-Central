package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type workerHost interface {
	installed(context.Context) (string, error)
	running(context.Context) error
	newer(context.Context, string, string) error
	stop(context.Context) error
	stopped(context.Context) bool
	backup(context.Context, string) (string, error)
	space(context.Context, string) error
	install(context.Context, string) error
	startAndCheck(context.Context, string) error
}
type systemHost struct{}

func command(ctx context.Context, path string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, path, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/root"}
	c.WaitDelay = 5 * time.Second
	return c
}
func cmdText(ctx context.Context, path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c := command(ctx, path, args...)
	var b boundedCommandOutput
	c.Stdout = &b
	if err := c.Run(); err != nil {
		return "", errors.New("local package or service query failed")
	}
	return strings.TrimSpace(b.body.String()), nil
}

type boundedCommandOutput struct{ body bytes.Buffer }

func (b *boundedCommandOutput) Write(p []byte) (int, error) {
	if b.body.Len()+len(p) > 64<<10 {
		return 0, errors.New("package query exceeded limit")
	}
	return b.body.Write(p)
}

var versionRE = regexp.MustCompile(`^([0-9]{1,10})\.([0-9]{1,10})\.([0-9]{1,10})-([1-9][0-9]{0,9})\.el([0-9]{1,2})\.(x86_64|aarch64)$`)

func (systemHost) installed(ctx context.Context) (string, error) {
	result, err := cmdText(ctx, "/usr/bin/rpm", "-q", "--queryformat", "%{EPOCHNUM}|%{VERSION}-%{RELEASE}.%{ARCH}\\n", packageName)
	v, ok := strings.CutPrefix(result, "0|")
	if err != nil || !ok || !versionRE.MatchString(v) {
		return "", errors.New("installed central RPM identity cannot be verified")
	}
	return v, nil
}
func versionFrom(j SignedManifest) string {
	return strings.TrimSuffix(strings.TrimPrefix(j.Manifest.ArtifactName, packageName+"-"), ".rpm")
}
func strictlyNewer(old, target string) bool {
	a, b := versionRE.FindStringSubmatch(old), versionRE.FindStringSubmatch(target)
	if a == nil || b == nil || a[5] != b[5] || a[6] != b[6] {
		return false
	}
	for i := 1; i <= 4; i++ {
		n, _ := strconv.ParseUint(a[i], 10, 64)
		m, _ := strconv.ParseUint(b[i], 10, 64)
		if n != m {
			return m > n
		}
	}
	return false
}
func (systemHost) newer(ctx context.Context, old, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := command(ctx, "/usr/bin/rpm", "-U", "--test", "--", path).Run(); err != nil {
		return errors.New("RPM upgrade preflight failed; check dependencies, disk capacity and installed version")
	}
	return nil
}
func (systemHost) stop(ctx context.Context) error {
	if command(ctx, "/usr/bin/systemctl", "stop", centralUnit).Run() != nil {
		return errors.New("could not stop the central service")
	}
	return nil
}
func (systemHost) stopped(ctx context.Context) bool {
	active, err := cmdText(ctx, "/usr/bin/systemctl", "show", "--property=ActiveState", "--value", centralUnit)
	return err == nil && active == "inactive"
}
func (systemHost) install(ctx context.Context, path string) error {
	if command(ctx, "/usr/bin/rpm", "-U", "--", path).Run() != nil {
		return errors.New("central RPM transaction failed")
	}
	return nil
}
func processConfig(args []string) (string, error) {
	if len(args) < 2 || args[1] != "serve" {
		return "", errors.New("central service launch command is unsupported")
	}
	// Parse complete options to avoid treating another option's value as the
	// state directory. Fail before shutdown on an unknown service layout.
	flags := flag.NewFlagSet("central-service-layout", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var statePath, addr, unused string
	var unusedBool bool
	flags.StringVar(&statePath, "state-dir", centralState, "")
	flags.StringVar(&addr, "admin-listen", "127.0.0.1:9444", "")
	for _, name := range []string{"listen", "enrollment-url", "panel-listen", "panel-tls-cert", "panel-tls-key", "panel-public-origin", "panel-trusted-proxies"} {
		flags.StringVar(&unused, name, "", "")
	}
	for _, name := range []string{"allow-non-loopback", "allow-non-loopback-panel"} {
		flags.BoolVar(&unusedBool, name, false, "")
	}
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
		return "", errors.New("unsupported central service launch options")
	}
	if statePath != centralState {
		return "", errors.New("automatic update requires the packaged central state directory")
	}
	host, port, err := net.SplitHostPort(addr)
	n, perr := strconv.Atoi(port)
	if err != nil || perr != nil || n < 1 || n > 65535 || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
		return "", errors.New("central admin listener must use a loopback address")
	}
	return addr, nil
}
func (systemHost) running(ctx context.Context) error {
	pid, err := cmdText(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", centralUnit)
	n, e := strconv.Atoi(pid)
	if err != nil || e != nil || n <= 1 {
		return errors.New("central service is not running")
	}
	proc := filepath.Join("/proc", strconv.Itoa(n))
	running, e1 := os.Stat(filepath.Join(proc, "exe"))
	installed, e2 := os.Stat("/usr/sbin/sentinel-central")
	if e1 != nil || e2 != nil || !os.SameFile(running, installed) {
		return errors.New("running central executable differs from the installed file")
	}
	raw, err := os.ReadFile(filepath.Join(proc, "cmdline"))
	if err != nil {
		return errors.New("cannot verify central service launch options")
	}
	addr, err := processConfig(strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00"))
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr+"/admin/agents", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("central admin listener is unavailable")
	}
	defer resp.Body.Close()
	var result struct {
		Error string `json:"error"`
	}
	if resp.StatusCode != 401 || json.NewDecoder(io.LimitReader(resp.Body, 2048)).Decode(&result) != nil || result.Error != "operator authentication required" {
		return errors.New("central admin listener did not return its expected readiness response")
	}
	return nil
}
func checkInstalledBinary(ctx context.Context) error {
	body, err := cmdText(ctx, "/usr/bin/rpm", "-q", "--queryformat", "%{FILEDIGESTALGO}\\n[%{FILENAMES}\\t%{FILEDIGESTS}\\n]", packageName)
	if err != nil {
		return err
	}
	algo, files, ok := strings.Cut(body, "\n")
	if !ok || algo != "8" {
		return errors.New("central RPM did not provide a SHA-256 binary digest")
	}
	digest := ""
	for _, row := range strings.Split(files, "\n") {
		name, value, _ := strings.Cut(row, "\t")
		if name == "/usr/sbin/sentinel-central" {
			digest = value
		}
	}
	f, err := os.Open("/usr/sbin/sentinel-central")
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 128<<20))
	if err != nil || n >= 128<<20 || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("installed binary does not match the central RPM digest")
	}
	return nil
}
func (h systemHost) startAndCheck(ctx context.Context, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	actual, err := h.installed(ctx)
	if err != nil || actual != version {
		return errors.New("installed central version changed unexpectedly")
	}
	if err = checkInstalledBinary(ctx); err != nil {
		return err
	}
	if command(ctx, "/usr/bin/systemctl", "daemon-reload").Run() != nil || command(ctx, "/usr/bin/systemctl", "start", centralUnit).Run() != nil {
		return errors.New("could not start the installed central service")
	}
	for {
		if err = h.running(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("central readiness check failed: %w", err)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
