package central

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func compactBundleFixture(id string, findings string) managed.Record {
	return managed.Record{
		Sequence: 1, Kind: managed.RecordKindEventBundle, ID: id,
		Payload: json.RawMessage(fmt.Sprintf(`{
"event":{"event_id":%q,"event_type":"process.exec","source":"replay","event_time":"2026-11-18T00:00:00Z",
"sequence":9223372036854775808,"raw_json":{"unused":"private-content"},"ancestors":[{"exe":"private-ancestor"}],
"process":{"key":"stable-key","exe":"/usr/bin/true","argv":["private-argument"],"cwd":"/private-workdir"}},
"findings":%s}`, id, findings)),
	}
}

func TestMinimalHistoryPreservesAckAndImmutableHashAfterExpiry(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	now := time.Unix(15000, 0)
	event := compactBundleFixture("ordinary", "null")
	batch := managed.Batch{EnrollmentID: enrolled.EnrollmentID, SpoolID: "spool-first", Records: []managed.Record{event}}
	if ack, err := f.store.Ingest(ctx, "agent-a", batch, now); err != nil || ack.Acknowledged != 1 {
		t.Fatalf("ingest: %+v %v", ack, err)
	}
	var payload []byte
	if err := f.store.db.QueryRow("SELECT payload FROM records WHERE record_id='ordinary'").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-content", "private-ancestor", "private-argument", "/private-workdir", "raw_json", "\"ancestors\""} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("stored discarded data %q", forbidden)
		}
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil || len(envelope) != 2 || bytes.Contains(envelope["event"], []byte("\"findings\"")) {
		t.Fatal("projection changed bundle shape")
	}
	if !bytes.Contains(payload, []byte("9223372036854775808")) || !bytes.Contains(payload, []byte("stable-key")) {
		t.Fatal("lost process identity or large integer")
	}
	changed := event
	changed.Payload = bytes.ReplaceAll(event.Payload, []byte("private-ancestor"), []byte("different-ancestor"))
	conflict := batch
	conflict.Records = []managed.Record{changed}
	if _, err := f.store.Ingest(ctx, "agent-a", conflict, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed acknowledged sequence: %v", err)
	}
	conflict.SpoolID = "spool-second"
	if _, err := f.store.Ingest(ctx, "agent-a", conflict, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed held record under new sequence: %v", err)
	}
	if n, _, err := f.store.pruneObservationHistory(ctx, now.Add(time.Hour-time.Nanosecond), 8); err != nil || n != 0 {
		t.Fatalf("premature expiry: n=%d %v", n, err)
	}
	if n, _, err := f.store.pruneObservationHistory(ctx, now.Add(time.Hour), 8); err != nil || n != 1 {
		t.Fatalf("expiry: n=%d %v", n, err)
	}
	if _, err := f.store.Ingest(ctx, "agent-a", conflict, now.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed expired record under new sequence: %v", err)
	}
	for _, spool := range []string{"spool-first", "spool-second"} {
		batch.SpoolID = spool
		if ack, err := f.store.Ingest(ctx, "agent-a", batch, now.Add(time.Hour)); err != nil || ack.Acknowledged != 1 {
			t.Fatalf("identical replay %s: %+v %v", spool, ack, err)
		}
	}
	if rows, err := f.store.History(ctx, "agent-a", managed.RecordKindEventBundle, 50); err != nil || len(rows) != 0 {
		t.Fatalf("expired replay resurrected history: n=%d %v", len(rows), err)
	}
}

func TestHistoryBackfillAndExpiryPreserveDetectionEvidence(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	now := time.Unix(20000, 0)
	seed := func(kind, id string, payload []byte) {
		t.Helper()
		if _, err := f.store.db.Exec("INSERT INTO records(agent_id,kind,record_id,payload,received_at_ns) VALUES(?,?,?,?,?)", "old-agent", kind, id, payload, now.UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	event := compactBundleFixture("old-normal", "[]")
	body, err := validateRecord(event)
	if err != nil {
		t.Fatal(err)
	}
	seed(event.Kind, event.ID, body)
	seed("event", "old-evidence", []byte(`{"event_id":"old-evidence","event_type":"file.write"}`))
	seed("event_bundle", "old-bundle", []byte(`{"event":{"event_id":"old-bundle","event_type":"process.exec"},"findings":[{"finding_id":"rule-hit"}]}`))
	seed("finding", "old-finding", []byte(`{"finding_id":"old-finding","evidence_event_ids":["old-evidence"]}`))
	seed("audit", "old-audit", []byte(`{"action":"fixture"}`))
	if _, err := f.store.db.Exec("UPDATE history_retention_state SET legacy_max_rowid=(SELECT max(rowid) FROM records)"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		n, more, err := f.store.pruneObservationHistory(ctx, now.Add(time.Hour), 1)
		if err != nil || n != 0 || !more {
			t.Fatalf("legacy batch %d: n=%d more=%t %v", i, n, more, err)
		}
	}
	if n, _, err := f.store.pruneObservationHistory(ctx, now.Add(time.Hour), 8); err != nil || n != 2 {
		t.Fatalf("prune processed legacy: n=%d %v", n, err)
	}
	rows, err := f.store.History(ctx, "old-agent", "", 50)
	if err != nil || len(rows) != 4 {
		t.Fatalf("expired ordinary or lost evidence: n=%d %v", len(rows), err)
	}
	for _, row := range rows {
		if row.ID == "old-normal" {
			t.Fatal("retained legacy ordinary record")
		}
	}
	var remaining int
	if err := f.store.db.QueryRow("SELECT count(*) FROM history_expiry").Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("protected row would be scanned again: n=%d %v", remaining, err)
	}
}
