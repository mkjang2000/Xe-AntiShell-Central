package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestDeliveryReceiptEncoding(t *testing.T) {
	digest := sha256.Sum256([]byte(`{"ok":true}`))
	receipt := deliveryReceipt("audit", "x.y-123", digest)
	// Existing schema-4 receipts must still match across binary upgrades.
	if hex.EncodeToString(receipt[:]) != "08ad756d35bd26d718ae54b894591b03ffdf40d4bde8b80dc796e420bd94cddf" {
		t.Fatalf("changed receipt encoding: %x", receipt)
	}
}

func TestDeliveryReceiptMigrationMixedBatchAndRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(200000, 0)
	const agent = "receipt-agent"
	batch := managed.Batch{EnrollmentID: "legacy-enrollment-id", SpoolID: "shared-spool-id"}
	oldRecord := eventRecord(t, 1, "legacy-event")
	body, err := validateRecord(oldRecord)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	path := filepath.Join(t.TempDir(), "central.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema + historyRetentionSchema + "PRAGMA user_version=3"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO agents(agent_id,enrollment_id,cert_serial,enrolled_at_ns) VALUES(?,?,'serial',1)", agent, batch.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO delivery_cursors VALUES(?,?,?,1)", agent, batch.EnrollmentID, batch.SpoolID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO deliveries VALUES(?,?,?,1,?,?,?)", agent, batch.EnrollmentID, batch.SpoolID, oldRecord.Kind, oldRecord.ID, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if store != nil {
			store.Close()
		}
	}()

	newRecord := eventRecord(t, 2, "new-audit")
	newRecord.Kind = managed.RecordKindAudit
	ingest := func(want uint64, wantErr error, records ...managed.Record) {
		t.Helper()
		batch.Records = records
		ack, err := store.Ingest(ctx, agent, batch, now)
		if !errors.Is(err, wantErr) || ack.SpoolID != batch.SpoolID || ack.Acknowledged != want {
			t.Fatalf("ingest: ack=%+v err=%v, want %d/%v", ack, err, want, wantErr)
		}
	}
	value := func(query string) int64 {
		t.Helper()
		var n int64
		if err := store.db.QueryRow(query).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Leave a gap before the active stream's key before receiving any compact
	// receipt. An implicit rowid could be renumbered during the later VACUUM.
	if _, err := store.db.Exec("UPDATE delivery_cursors SET spool_key=100"); err != nil {
		t.Fatal(err)
	}
	// The old event body already expired or was cleared. Its original delivery
	// receipt alone must still permit an identical replay, without recreating it.
	changedLegacy := oldRecord
	changedLegacy.Kind = managed.RecordKindAudit
	ingest(1, ErrConflict, changedLegacy)
	ingest(2, nil, oldRecord, newRecord)
	if value("SELECT count(*) FROM deliveries") != 1 || value("SELECT count(*) FROM delivery_receipts") != 1 ||
		value("SELECT count(*) FROM records WHERE record_id='legacy-event'") != 0 ||
		value("SELECT legacy_through FROM delivery_cursors") != 1 {
		t.Fatal("mixed batch changed legacy accounting or restored expired evidence")
	}

	// All three mutations pass record validation. Each must independently
	// change the receipt, including the external audit ID.
	changedID, changedKind, changedBody := newRecord, newRecord, newRecord
	changedID.ID = "new-audit-with-different-id"
	changedKind.Kind = managed.RecordKindEvent
	changedBody.Payload = []byte(`{"different":true}`)
	for _, changed := range []managed.Record{changedID, changedKind, changedBody} {
		ingest(2, ErrConflict, oldRecord, changed)
	}
	ingest(2, ErrConflict, oldRecord, newRecord, eventRecord(t, 3, "rollback"), eventRecord(t, 5, "gap"))
	if value("SELECT acknowledged FROM delivery_cursors") != 2 || value("SELECT count(*) FROM delivery_receipts") != 1 ||
		value("SELECT count(*) FROM records") != 1 {
		t.Fatal("failed batch retained an uncommitted record, receipt, or ACK")
	}

	if _, err := store.db.Exec("VACUUM"); err != nil {
		t.Fatal(err)
	}
	if value("SELECT spool_key FROM delivery_cursors") != 100 {
		t.Fatal("vacuum renumbered a stream key")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ingest(3, nil, oldRecord, newRecord, eventRecord(t, 3, "rollback"))
	if value("SELECT count(*) FROM delivery_receipts") != 2 || value("SELECT legacy_through FROM delivery_cursors WHERE agent_id='receipt-agent'") != 1 {
		t.Fatal("reopen reset the migration boundary or lost receipts")
	}
}

func TestDeliveryReceiptScopeAndDatabaseError(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	enrollAndIngest := func(agent, recordID string) managed.Batch {
		t.Helper()
		enrolled, _, _ := f.enroll(t, agent)
		batch := managed.Batch{EnrollmentID: enrolled.EnrollmentID, SpoolID: "same-spool-on-each", Records: []managed.Record{eventRecord(t, 1, recordID)}}
		if ack, err := f.store.Ingest(ctx, agent, batch, time.Now()); err != nil || ack.Acknowledged != 1 {
			t.Fatalf("agent %s: %+v %v", agent, ack, err)
		}
		return batch
	}
	original := enrollAndIngest("receipt-a", "first")
	other := enrollAndIngest("receipt-b", "second")
	replacement := enrollAndIngest("receipt-a", "replacement")
	if _, err := f.store.Ingest(ctx, "receipt-a", original, time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old enrollment replay: %v", err)
	}
	if ack, err := f.store.Ingest(ctx, "receipt-b", other, time.Now()); err != nil || ack.Acknowledged != 1 {
		t.Fatalf("other agent replay: %+v %v", ack, err)
	}
	var streams int
	if err := f.store.db.QueryRow("SELECT count(DISTINCT spool_key) FROM delivery_receipts").Scan(&streams); err != nil || streams != 3 {
		t.Fatalf("distinct receipt streams: %d %v", streams, err)
	}
	if _, err := f.store.db.Exec("DROP TABLE delivery_receipts"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Ingest(ctx, "receipt-a", replacement, time.Now()); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("expected a storage failure on receipt lookup, got %v", err)
	}
}
