package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/central"
)

func TestCapacitySamplesLegacyAndCompactWithoutChangingStorage(t *testing.T) {
	for _, version := range []int{3, 4} {
		t.Run(fmt.Sprintf("schema-%d", version), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "central.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exec := func(statement string, args ...any) {
				t.Helper()
				if _, err := db.Exec(statement, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec("PRAGMA journal_mode=WAL")
			exec(fmt.Sprintf("PRAGMA user_version=%d", version))
			exec("CREATE TABLE history_expiry(received_at_ns INTEGER PRIMARY KEY)")
			if version == 3 {
				exec("CREATE TABLE delivery_cursors(acknowledged INTEGER)")
				exec("INSERT INTO delivery_cursors VALUES (7),(3)")
				exec("INSERT INTO history_expiry VALUES (?), (?)", time.Now().Add(-time.Hour-90*time.Second).UnixNano(), time.Now().UnixNano())
			} else {
				exec("CREATE TABLE delivery_cursors(acknowledged INTEGER,legacy_through INTEGER)")
				exec("INSERT INTO delivery_cursors VALUES (9,7),(3,0)")
				exec("INSERT INTO history_expiry VALUES (?)", time.Now().UnixNano())
			}
			beforeDB, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			beforeWAL, err := os.Stat(path + "-wal")
			if err != nil {
				t.Fatal(err)
			}
			since := time.Now()
			var out bytes.Buffer
			args := []string{"capacity", "--state-dir", dir}
			if err := run(args, &out, io.Discard); err != nil {
				t.Fatal(err)
			}
			var sample central.StorageCapacity
			if err := json.Unmarshal(out.Bytes(), &sample); err != nil {
				t.Fatal(err)
			}
			if sample.SchemaVersion != version || sample.DBBytes != beforeDB.Size() || sample.WALBytes != beforeWAL.Size() ||
				sample.FilesystemAvailableBytes == 0 || sample.UsedPageBytes == 0 || sample.ReusablePageBytes != 0 ||
				sample.SampledAt.Before(since) || sample.SampledAt.After(time.Now()) {
				t.Fatalf("invalid sample: %+v", sample)
			}
			if version == 3 && (sample.LegacyAcknowledged != 10 || sample.CompactAcknowledged != 0 ||
				sample.OldestExpiryOverdueSecs < 90 || sample.OldestExpiryOverdueSecs > int64(time.Since(since)/time.Second)+91) {
				t.Fatalf("wrong old schema counters: %+v", sample)
			}
			if version == 4 && (sample.LegacyAcknowledged != 7 || sample.CompactAcknowledged != 5 || sample.OldestExpiryOverdueSecs != 0) {
				t.Fatalf("wrong new schema counters: %+v", sample)
			}
			wal, err := os.Stat(path + "-wal")
			if err != nil || wal.Size() != beforeWAL.Size() {
				t.Fatalf("capacity wrote or checkpointed the database: %v", err)
			}
			// A read-only call on this fixture cannot rely on receipts, records
			// or any payload table. Check that it also left the schema intact.
			var schema, tables int
			if err := db.QueryRow("SELECT user_version,(SELECT count(*) FROM sqlite_schema WHERE type='table') FROM pragma_user_version").Scan(&schema, &tables); err != nil || schema != version || tables != 2 {
				t.Fatalf("changed database schema: %d, %d: %v", schema, tables, err)
			}
			out.Reset()
			if err := run(append(args, "--min-free-bytes", "18446744073709551615"), &out, io.Discard); err == nil || !json.Valid(out.Bytes()) {
				t.Fatalf("threshold breach did not return an error and a sample: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := central.SampleStorageCapacity(ctx, path); !errors.Is(err, context.Canceled) {
				t.Fatalf("ignored cancellation: %v", err)
			}
		})
	}
}

func TestCapacityFailsClosedForMissingOrUnsupportedStorage(t *testing.T) {
	dir := t.TempDir()
	args := []string{"capacity", "--state-dir", dir}
	var out bytes.Buffer
	if err := run(args, &out, io.Discard); err == nil || out.Len() != 0 {
		t.Fatalf("missing input: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("created missing database: %v", err)
	}
	path := filepath.Join(dir, "central.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, version := range []int{8, 3} {
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
			t.Fatal(err)
		}
		if err := run(args, &out, io.Discard); err == nil || out.Len() != 0 {
			t.Fatalf("invalid schema %d returned sample: %v", version, err)
		}
	}
	for _, extra := range [][]string{{"--min-free-bytes", "-1"}, {"extra"}} {
		if err := run(append(args, extra...), &out, io.Discard); err == nil || out.Len() != 0 {
			t.Fatalf("invalid arguments accepted: %v", extra)
		}
	}
}
