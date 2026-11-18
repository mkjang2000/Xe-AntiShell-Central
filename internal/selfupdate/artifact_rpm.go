package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

var errRPM = errors.New("invalid central RPM size, digest or package header")

func openPackage(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxRPMBytes {
		f.Close()
		return nil, 0, errRPM
	}
	return f, info.Size(), nil
}

// inspectPackage handles an already-open descriptor in a trusted staging
// directory. It checks bytes before handing a publisher-approved RPM to rpm -qp.
func inspectPackage(ctx context.Context, f *os.File, m Manifest, checkDigest bool) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, m.Size+1))
	hash := hex.EncodeToString(h.Sum(nil))
	if err != nil || n != m.Size || (checkDigest && hash != m.SHA256) {
		return "", errRPM
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	const format = "%{NAME}\n%{EPOCHNUM}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n"
	cmd := exec.CommandContext(ctx, "/usr/bin/rpm", "-qp", "--queryformat", format, "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err = cmd.Start(); err != nil {
		return "", errRPM
	}
	b, err := io.ReadAll(io.LimitReader(out, 4097))
	if err != nil || len(b) > 4096 {
		cancel()
	}
	if waitErr := cmd.Wait(); waitErr != nil || err != nil || len(b) > 4096 {
		return "", errRPM
	}
	parts := releaseTag.FindStringSubmatch(m.Tag)
	want := "xe-antishell-central\n0\n" + parts[1] + "\n" + parts[2] + ".el" + m.OSMajor + "\nx86_64\n"
	if !bytes.Equal(b, []byte(want)) {
		return "", errRPM
	}
	return hash, nil
}

// VerifyRPM reauthenticates the signed envelope, artifact bytes, and exact
// NEVRA. The installer owns the private copy and keeps it immutable through apply.
func VerifyRPM(ctx context.Context, path string, s SignedManifest) error {
	if err := VerifyManifest(s); err != nil {
		return err
	}
	f, size, err := openPackage(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if size != s.Manifest.Size {
		return errRPM
	}
	_, err = inspectPackage(ctx, f, s.Manifest, true)
	return err
}

// PrepareManifest is for the publisher's trusted build output only.
func PrepareManifest(ctx context.Context, path, tag string) (Manifest, error) {
	name := filepath.Base(path)
	m := Manifest{SchemaVersion: "1", Tag: tag, ArtifactName: name}
	for _, major := range []string{"9", "10"} {
		if want, err := rpmName(tag, major); err == nil && name == want {
			m.OSMajor = major
			break
		}
	}
	if m.OSMajor == "" {
		return Manifest{}, errManifest
	}
	f, size, err := openPackage(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	m.Size = size
	m.SHA256, err = inspectPackage(ctx, f, m, false)
	if err != nil {
		return Manifest{}, err
	}
	return m, m.validate()
}
