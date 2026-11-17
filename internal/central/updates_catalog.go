package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const maxUpdateReleases = 32
const maxUpdateStorage int64 = 1 << 30

type updateReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadUpdateRelease(ctx context.Context, q updateReader, id string) (ConsoleUpdateRelease, error) {
	var release ConsoleUpdateRelease
	var body []byte
	err := q.QueryRowContext(ctx, "SELECT metadata_json,uploaded_by FROM update_releases WHERE id=? AND deleted=0", id).Scan(&body, &release.UploadedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return release, ErrNotFound
	}
	if err != nil {
		return release, err
	}
	err = json.Unmarshal(body, &release.UpdateRelease)
	if err == nil && (release.Validate() != nil || release.ID != id || release.SHA256 != id) {
		err = ErrConflict
	}
	return release, err
}

func listUpdateReleases(ctx context.Context, q updateReader) ([]ConsoleUpdateRelease, error) {
	rows, err := q.QueryContext(ctx, "SELECT metadata_json,uploaded_by FROM update_releases WHERE deleted=0 ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ConsoleUpdateRelease{}
	for rows.Next() {
		var item ConsoleUpdateRelease
		var body []byte
		if err = rows.Scan(&body, &item.UploadedBy); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(body, &item.UpdateRelease); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Server) publishUpdateRelease(ctx context.Context, body io.Reader, actor string, publisher managed.SignedReleaseManifest) (ConsoleUpdateRelease, bool, error) {
	if err := s.verifyUpdatePublisher(publisher); err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	path, digest, size, pack, major, err := s.updateBlobs.stage(ctx, body, publisher.Manifest)
	if err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	defer os.Remove(path)
	s.updateBlobs.mu.Lock()
	defer s.updateBlobs.mu.Unlock()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	defer tx.Rollback()
	if item, err := loadUpdateRelease(ctx, tx, digest); err == nil {
		if item.Package != pack || item.Size != size || item.OSMajor != major {
			return item, false, ErrConflict
		}
		if _, err = s.updateBlobs.publish(path, item.ID, item.Size); err != nil {
			return item, false, err
		}
		if err = s.verifyUpdatePublisher(item.Publisher); err != nil {
			return item, false, err
		}
		item.PublisherVerified = true
		return item, true, nil
	} else if !errors.Is(err, ErrNotFound) {
		return ConsoleUpdateRelease{}, false, err
	}
	items, err := listUpdateReleases(ctx, tx)
	if err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	total := size
	for _, item := range items {
		total += item.Size
		if item.Package == pack && item.OSMajor == major {
			return ConsoleUpdateRelease{}, false, ErrConflict
		}
	}
	if len(items) >= maxUpdateReleases || total > maxUpdateStorage {
		return ConsoleUpdateRelease{}, false, ErrConflict
	}
	if err = s.updateBlobs.admit(digest, size); err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	now := s.now().UTC()
	release := ConsoleUpdateRelease{UpdateRelease: managed.UpdateRelease{ID: digest, Package: pack, OSFamily: "rhel", OSMajor: major, SHA256: digest, Size: size, CreatedAt: now, Publisher: publisher}, UploadedBy: actor, PublisherVerified: true}
	if release.Validate() != nil {
		return release, false, ErrInvalid
	}
	metadata, _ := json.Marshal(release.UpdateRelease)
	created, err := s.updateBlobs.publish(path, digest, size)
	if err != nil {
		return release, false, err
	}
	committed := false
	commitAttempted := false
	defer func() {
		if created && !committed && !commitAttempted {
			target, _ := s.updateBlobs.path(digest)
			os.Remove(target)
		}
	}()
	_, err = tx.ExecContext(ctx, "INSERT INTO update_releases(id,metadata_json,uploaded_by,deleted) VALUES(?,?,?,0) ON CONFLICT(id) DO UPDATE SET metadata_json=excluded.metadata_json,uploaded_by=excluded.uploaded_by,deleted=0", digest, metadata, actor)
	if err == nil {
		err = appendAudit(ctx, tx, "", "update.release.uploaded", map[string]any{"release_id": digest, "actor": actor, "size": size}, now)
	}
	if err == nil {
		commitAttempted = true
		err = tx.Commit()
	}
	committed = err == nil
	return release, false, err
}

func (s *Server) deleteUpdateRelease(ctx context.Context, id, actor string) error {
	s.updateBlobs.mu.Lock()
	defer s.updateBlobs.mu.Unlock()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = loadUpdateRelease(ctx, tx, id); err != nil {
		return err
	}
	if err = expireUpdateJobs(ctx, tx, s.now().UTC()); err != nil {
		return err
	}
	var active int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM update_jobs j JOIN update_rollouts r ON r.id=j.rollout_id WHERE r.release_id=? AND j.state NOT IN ('succeeded','failed','expired','cancelled')`, id).Scan(&active)
	if err != nil {
		return err
	}
	if active > 0 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, "UPDATE update_releases SET deleted=1 WHERE id=?", id)
	if err == nil {
		err = appendAudit(ctx, tx, "", "update.release.deleted", map[string]string{"release_id": id, "actor": actor}, s.now().UTC())
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	path, _ := s.updateBlobs.path(id)
	if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		_, _ = s.store.db.ExecContext(ctx, "UPDATE update_releases SET deleted=0 WHERE id=?", id)
		return err
	}
	return nil
}

func timePointer(ns int64) *time.Time {
	if ns == 0 {
		return nil
	}
	value := time.Unix(0, ns).UTC()
	return &value
}
