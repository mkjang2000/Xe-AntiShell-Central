package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const fileIntegritySchema = `
CREATE TABLE IF NOT EXISTS integrity_package_files(release_id TEXT PRIMARY KEY REFERENCES update_releases(id), files_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS integrity_file_reports(agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,revision INTEGER NOT NULL,completed_at_ns INTEGER NOT NULL,received_at_ns INTEGER NOT NULL,report_json BLOB NOT NULL,PRIMARY KEY(agent_id,enrollment_id));`

// This is a query of the publisher-authenticated RPM file header. It executes
// no package code. Passing the verified descriptor keeps the path stable.
func rpmFileBaselines(ctx context.Context, file *os.File, manifest managed.ReleaseManifest) (map[string]string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, manifest.Size+1))
	if err != nil || n != manifest.Size || hex.EncodeToString(h.Sum(nil)) != manifest.SHA256 {
		return nil, ErrInvalid
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/rpm", "--query", "--package", "--queryformat", "%{FILEDIGESTALGO}\n[%{FILENAMES}\t%{FILEMODES}\t%{FILEDIGESTS}\n]", "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	const limit = 128 << 10
	raw, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if readErr != nil || len(raw) > limit {
		cancel()
	}
	if err = cmd.Wait(); err != nil || readErr != nil || len(raw) > limit {
		return nil, ErrInvalid
	}
	return parseRPMFileBaselines(string(raw))
}

func parseRPMFileBaselines(raw string) (map[string]string, error) {
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if lines[0] != "8" {
		return nil, ErrInvalid
	}
	targets := map[string]string{}
	for id, p := range contract.Targets() {
		if id != contract.ConfigID {
			targets[p] = id
		}
	}
	files := map[string]string{}
	for _, row := range lines[1:] {
		f := strings.Split(row, "\t")
		if len(f) != 3 {
			return nil, ErrInvalid
		}
		id, ok := targets[f[0]]
		if !ok {
			continue
		}
		mode, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil || mode&0170000 != 0100000 || files[id] != "" || !contract.ValidDigest(f[2]) {
			return nil, ErrInvalid
		}
		files[id] = f[2]
	}
	if len(files) != len(targets) {
		return nil, ErrInvalid
	}
	return files, nil
}

// Existing catalog entries are populated on first use, after validating their
// original publisher signature and rehashing the stored RPM. New imports can
// therefore coexist with catalogs created before file verification existed.
func (s *Server) packageBaselines(ctx context.Context, release ConsoleUpdateRelease) (map[string]string, error) {
	if release.ID != release.SHA256 || release.Validate() != nil || s.verifyUpdatePublisher(release.Publisher) != nil {
		return nil, ErrInvalid
	}
	var raw []byte
	err := s.store.db.QueryRowContext(ctx, "SELECT files_json FROM integrity_package_files WHERE release_id=?", release.ID).Scan(&raw)
	if err == nil {
		var files map[string]string
		if err = json.Unmarshal(raw, &files); err != nil {
			return nil, err
		}
		for id := range contract.Targets() {
			if id != contract.ConfigID && !contract.ValidDigest(files[id]) {
				return nil, ErrInvalid
			}
		}
		return files, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	select {
	case s.updateBlobs.downloads <- struct{}{}:
		defer func() { <-s.updateBlobs.downloads }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	f, err := s.updateBlobs.open(release.ID, release.Size)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	files, err := rpmFileBaselines(ctx, f, release.Publisher.Manifest)
	if err != nil {
		return nil, err
	}
	raw, err = json.Marshal(files)
	if err != nil {
		return nil, err
	}
	_, err = s.store.db.ExecContext(ctx, "INSERT INTO integrity_package_files(release_id,files_json) VALUES(?,?) ON CONFLICT(release_id) DO NOTHING", release.ID, raw)
	return files, err
}

// Legacy release import also accepts packages that predate file measurement.
// Only complete seven-file SHA-256 headers are eligible as integrity baselines.
func importFileBaselines(ctx context.Context, path string, manifest managed.ReleaseManifest) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	files, err := rpmFileBaselines(ctx, f, manifest)
	if err != nil {
		return nil
	}
	raw, err := json.Marshal(files)
	if err != nil {
		return nil
	}
	return raw
}

func storeImportedBaselines(ctx context.Context, tx *sql.Tx, releaseID string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO integrity_package_files(release_id,files_json) VALUES(?,?) ON CONFLICT(release_id) DO NOTHING", releaseID, raw)
	return err
}
