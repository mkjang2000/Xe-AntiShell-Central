package central

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type StorageCapacity struct {
	SampledAt                time.Time `json:"sampled_at"`
	DBBytes                  int64     `json:"db_bytes"`
	WALBytes                 int64     `json:"wal_bytes"`
	FilesystemAvailableBytes uint64    `json:"filesystem_available_bytes"`
	UsedPageBytes            int64     `json:"used_page_bytes"`
	ReusablePageBytes        int64     `json:"reusable_page_bytes"`
	SchemaVersion            int       `json:"schema_version"`
	OldestExpiryOverdueSecs  int64     `json:"oldest_expiry_overdue_seconds"`
	LegacyAcknowledged       int64     `json:"legacy_acknowledged"`
	CompactAcknowledged      int64     `json:"compact_acknowledged"`
}

// SampleStorageCapacity reads one short SQLite snapshot. Cursor watermarks
// count acknowledged sequences without scanning receipts or counting events.
func SampleStorageCapacity(ctx context.Context, path string) (StorageCapacity, error) {
	var sample StorageCapacity
	path, err := filepath.Abs(path)
	if err != nil {
		return sample, err
	}
	dbFile, err := os.Lstat(path)
	if err != nil {
		return sample, err
	}
	if !dbFile.Mode().IsRegular() {
		return sample, errors.New("central database must be a regular file")
	}
	sample.DBBytes = dbFile.Size()
	ctx, cancel := context.WithTimeout(ctx, historyQueryTimeout)
	defer cancel()
	db, err := openHistoryReadPool(ctx, path)
	if err != nil {
		return sample, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return sample, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&sample.SchemaVersion); err != nil {
		return sample, err
	}
	var cursorQuery string
	switch sample.SchemaVersion {
	case 3:
		cursorQuery = "SELECT COALESCE(sum(acknowledged),0), 0 FROM delivery_cursors"
	case 4:
		cursorQuery = "SELECT COALESCE(sum(legacy_through),0), COALESCE(sum(acknowledged-legacy_through),0) FROM delivery_cursors"
	default:
		return sample, fmt.Errorf("unsupported central capacity schema version %d", sample.SchemaVersion)
	}
	if err := tx.QueryRowContext(ctx, cursorQuery).Scan(&sample.LegacyAcknowledged, &sample.CompactAcknowledged); err != nil {
		return sample, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT (page_count-freelist_count)*page_size, freelist_count*page_size
FROM pragma_page_size, pragma_page_count, pragma_freelist_count`).Scan(&sample.UsedPageBytes, &sample.ReusablePageBytes); err != nil {
		return sample, err
	}
	var oldest sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT (SELECT received_at_ns FROM history_expiry ORDER BY received_at_ns LIMIT 1)").Scan(&oldest); err != nil {
		return sample, err
	}
	if err := tx.Commit(); err != nil {
		return sample, err
	}
	var volume syscall.Statfs_t
	if err := syscall.Statfs(path, &volume); err != nil {
		return sample, err
	}
	sample.FilesystemAvailableBytes = volume.Bavail * uint64(volume.Bsize)
	wal, err := os.Stat(path + "-wal")
	if err == nil {
		sample.WALBytes = wal.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return sample, err
	}
	sample.SampledAt = time.Now().UTC()
	if oldest.Valid {
		overdue := sample.SampledAt.Sub(time.Unix(0, oldest.Int64).Add(ordinaryHistoryLifetime))
		if overdue > 0 {
			sample.OldestExpiryOverdueSecs = int64(overdue / time.Second)
		}
	}
	return sample, nil
}
