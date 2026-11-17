package central

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type updateZeroReader struct{}

func (updateZeroReader) Read(buffer []byte) (int, error) { clear(buffer); return len(buffer), nil }

func TestUpdateStorageRejectsOversizeAndCatalogQuota(t *testing.T) {
	f := updateFixture(t)
	large := f.signedUpdateBody(t, []byte("synthetic"), updatePackage(24))
	large.Manifest.Size = managed.MaxUpdateArtifactBytes
	large, _ = managed.SignReleaseManifest(large.Manifest, large.KeyID, f.updatePublisherPrivate)
	if _, _, err := f.server.publishUpdateRelease(context.Background(), io.LimitReader(updateZeroReader{}, managed.MaxUpdateArtifactBytes+1), "admin", large); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize RPM accepted")
	}
	if _, _, err := f.server.publishUpdateRelease(context.Background(), bytes.NewReader(nil), "admin", f.signedUpdateBody(t, []byte("synthetic"), updatePackage(24))); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty RPM accepted")
	}
	for n := 0; n < maxUpdateReleases; n++ {
		f.updateRelease(t, n+1)
	}
	body, _ := json.Marshal(updatePackage(100))
	if _, _, err := f.server.publishUpdateRelease(context.Background(), bytes.NewReader(body), "admin", f.signedUpdateBody(t, body, updatePackage(100))); !errors.Is(err, ErrConflict) {
		t.Fatal("catalog release cap exceeded")
	}
	entries, _ := os.ReadDir(filepath.Join(f.directory, "update-blobs/staging"))
	if len(entries) != 0 {
		t.Fatal("failed uploads retained staging files")
	}
}

func TestUpdateStorageDatabaseFailureAndCorruptionStayInvisible(t *testing.T) {
	f := updateFixture(t)
	if _, err := f.store.db.Exec(`CREATE TRIGGER reject_test_release BEFORE INSERT ON update_releases BEGIN SELECT RAISE(ABORT,'synthetic metadata failure'); END`); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(updatePackage(24))
	if _, _, err := f.server.publishUpdateRelease(context.Background(), bytes.NewReader(body), "admin", f.signedUpdateBody(t, body, updatePackage(24))); err == nil {
		t.Fatal("database failure accepted")
	}
	items, err := listUpdateReleases(context.Background(), f.store.db)
	if err != nil || len(items) != 0 {
		t.Fatal("failed release became visible")
	}
	if _, err = f.store.db.Exec("DROP TRIGGER reject_test_release"); err != nil {
		t.Fatal(err)
	}
	release := f.updateRelease(t, 24)
	path, _ := f.server.updateBlobs.path(release.ID)
	if err = os.WriteFile(path, bytes.Repeat([]byte("z"), int(release.Size)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.server.publishUpdateRelease(context.Background(), bytes.NewReader(body), "admin", f.signedUpdateBody(t, body, updatePackage(24))); !errors.Is(err, ErrConflict) {
		t.Fatal("corrupt duplicate blob reported valid")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.updateBlobs.open(release.ID, release.Size); err == nil {
		t.Fatal("artifact symlink followed")
	}
}

func TestUpdateAdditiveSchemaKeepsLegacyVersion(t *testing.T) {
	f := updateFixture(t)
	var legacy, feature int
	if err := f.store.db.QueryRow("PRAGMA user_version").Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if err := f.store.db.QueryRow("SELECT version FROM feature_schema WHERE name='agent_updates'").Scan(&feature); err != nil {
		t.Fatal(err)
	}
	if legacy != 2 || feature != 1 {
		t.Fatal("legacy central rollback schema changed")
	}
}
