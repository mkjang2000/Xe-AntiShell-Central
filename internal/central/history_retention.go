package central

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

const ordinaryHistoryLifetime = time.Hour

const historyRetentionSchema = `
ALTER TABLE records ADD COLUMN original_hash BLOB;
CREATE TABLE history_expiry (
 received_at_ns INTEGER NOT NULL,
 agent_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 record_id TEXT NOT NULL,
 PRIMARY KEY(received_at_ns,agent_id,kind,record_id)
) WITHOUT ROWID;
CREATE TABLE history_expired_digests (
 agent_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 record_id TEXT NOT NULL,
 original_hash BLOB NOT NULL,
 PRIMARY KEY(agent_id,kind,record_id)
) WITHOUT ROWID;
CREATE TABLE history_finding_evidence (
 agent_id TEXT NOT NULL,
 event_id TEXT NOT NULL,
 PRIMARY KEY(agent_id,event_id)
) WITHOUT ROWID;
CREATE TABLE history_retention_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 last_rowid INTEGER NOT NULL,
 legacy_max_rowid INTEGER NOT NULL
);
INSERT INTO history_retention_state VALUES(1,0,COALESCE((SELECT max(rowid) FROM records),0));
`

// minimizeHistoryRecord runs after all validation and never changes the wire
// digest. RawMessage preserves integers and fields from newer agents.
func minimizeHistoryRecord(kind string, body []byte) (stored []byte, ordinary bool, err error) {
	if kind != managed.RecordKindEvent && kind != managed.RecordKindEventBundle {
		return body, false, nil
	}
	var wrapper, event map[string]json.RawMessage
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, false, err
	}
	ordinary = kind == managed.RecordKindEvent
	if kind == managed.RecordKindEventBundle {
		if err := json.Unmarshal(wrapper["event"], &event); err != nil {
			return nil, false, err
		}
		facts := bytes.TrimSpace(wrapper["findings"])
		ordinary = len(facts) == 0 || bytes.Equal(facts, []byte("null")) || bytes.Equal(facts, []byte("[]"))
	} else {
		event = wrapper
	}
	// Keep process identity fields and typed evidence. Their own validation
	// already ran against the complete input before omitting diagnostic data.
	delete(event, "raw_json")
	delete(event, "ancestors")
	if p := event["process"]; len(p) > 0 && !bytes.Equal(p, []byte("null")) {
		var process map[string]json.RawMessage
		if err := json.Unmarshal(p, &process); err != nil {
			return nil, false, err
		}
		delete(process, "argv")
		delete(process, "cwd")
		projected, err := json.Marshal(process)
		if err != nil {
			return nil, false, err
		}
		event["process"] = projected
	}
	if kind == managed.RecordKindEventBundle {
		projected, err := json.Marshal(event)
		if err != nil {
			return nil, false, err
		}
		wrapper["event"] = projected
	}
	stored, err = json.Marshal(wrapper)
	return stored, ordinary, err
}

func persistHistoryRecord(ctx context.Context, tx *sql.Tx, agentID string, record managed.Record, body []byte, digest [sha256.Size]byte, now time.Time) error {
	if record.Kind == managed.RecordKindEvent || record.Kind == managed.RecordKindEventBundle {
		var expired []byte
		err := tx.QueryRowContext(ctx, "SELECT original_hash FROM history_expired_digests WHERE agent_id=? AND kind=? AND record_id=?", agentID, record.Kind, record.ID).Scan(&expired)
		switch {
		case err == nil:
			if bytes.Equal(expired, digest[:]) {
				return nil
			}
			return ErrConflict
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
	}
	stored, ordinary, err := minimizeHistoryRecord(record.Kind, body)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO records
(agent_id,kind,record_id,payload,received_at_ns,original_hash,site_id) VALUES(?,?,?,?,?,?,COALESCE((SELECT site_id FROM agents WHERE agent_id=?),'default'))
ON CONFLICT DO NOTHING`, agentID, record.Kind, record.ID, stored, now.UnixNano(), digest[:], agentID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var hash, legacyBody []byte
		err := tx.QueryRowContext(ctx, `SELECT original_hash,
CASE WHEN original_hash IS NULL THEN payload END FROM records
WHERE agent_id=? AND kind=? AND record_id=?`, agentID, record.Kind, record.ID).Scan(&hash, &legacyBody)
		if err != nil {
			return err
		}
		if bytes.Equal(hash, digest[:]) || (len(hash) == 0 && bytes.Equal(legacyBody, body)) {
			return nil
		}
		return ErrConflict
	}
	if ordinary {
		_, err = tx.ExecContext(ctx, "INSERT INTO history_expiry VALUES(?,?,?,?)", now.UnixNano(), agentID, record.Kind, record.ID)
	}
	if record.Kind == managed.RecordKindFinding {
		var finding model.Finding
		if err := json.Unmarshal(body, &finding); err != nil {
			return err
		}
		for _, id := range finding.EvidenceEventIDs {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO history_finding_evidence VALUES(?,?)", agentID, id); err != nil {
				return err
			}
		}
	}
	return err
}

// A bounded rowid walk indexes old rows without scanning the entire DB during
// startup. Capture every existing standalone finding link before expiring any
// bundle; the link may refer to another row that appears earlier in the walk.
func backfillHistoryRetention(ctx context.Context, tx *sql.Tx, limit int) (bool, error) {
	var cursor, through int64
	if err := tx.QueryRowContext(ctx, "SELECT last_rowid,legacy_max_rowid FROM history_retention_state WHERE singleton=1").Scan(&cursor, &through); err != nil {
		return false, err
	}
	if cursor >= through {
		return false, nil
	}
	var last int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(rowid),?) FROM (
 SELECT rowid FROM records WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT ?
)`, through, cursor, through, limit).Scan(&last); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO history_expiry
 SELECT received_at_ns,agent_id,kind,record_id FROM records
 WHERE rowid>? AND rowid<=? AND original_hash IS NULL AND (
  kind='event' OR (kind='event_bundle' AND
  (json_type(payload,'$.findings') IS NULL OR json_type(payload,'$.findings')='null'
  OR (json_type(payload,'$.findings')='array' AND json_array_length(payload,'$.findings')=0))))`, cursor, last); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO history_finding_evidence
 SELECT r.agent_id,j.value FROM records r CROSS JOIN json_each(r.payload,'$.evidence_event_ids') j
 WHERE r.rowid>? AND r.rowid<=? AND r.original_hash IS NULL AND r.kind='finding' AND j.type='text'`, cursor, last); err != nil {
		return false, err
	}
	_, err := tx.ExecContext(ctx, "UPDATE history_retention_state SET last_rowid=? WHERE singleton=1", last)
	return true, err
}

type expiryRow struct {
	receivedAt int64
	agentID    string
	kind       string
	id         string
	protected  bool
	digest     []byte
	legacyBody []byte
}

func (s *Store) pruneObservationHistory(ctx context.Context, now time.Time, limit int) (processed int, backfilled bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	backfilled, err = backfillHistoryRetention(ctx, tx, limit)
	if err != nil {
		return 0, false, err
	}
	if backfilled {
		return 0, true, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.received_at_ns,e.agent_id,e.kind,e.record_id,
(f.event_id IS NOT NULL),r.original_hash,
CASE WHEN r.original_hash IS NULL AND f.event_id IS NULL THEN r.payload END
FROM history_expiry e
CROSS JOIN records r ON r.agent_id=e.agent_id AND r.kind=e.kind AND r.record_id=e.record_id
LEFT JOIN history_finding_evidence f ON f.agent_id=e.agent_id AND f.event_id=e.record_id
WHERE e.received_at_ns <= ?
ORDER BY e.received_at_ns,e.agent_id,e.kind,e.record_id LIMIT ?`, now.Add(-ordinaryHistoryLifetime).UnixNano(), limit)
	if err != nil {
		return 0, false, err
	}
	expired := make([]expiryRow, 0, limit)
	for rows.Next() {
		var entry expiryRow
		if err := rows.Scan(&entry.receivedAt, &entry.agentID, &entry.kind, &entry.id, &entry.protected, &entry.digest, &entry.legacyBody); err != nil {
			_ = rows.Close()
			return 0, false, err
		}
		expired = append(expired, entry)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, false, err
	}
	for _, e := range expired {
		if !e.protected {
			if len(e.digest) == 0 {
				digest := sha256.Sum256(e.legacyBody)
				e.digest = digest[:]
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO history_expired_digests VALUES(?,?,?,?)", e.agentID, e.kind, e.id, e.digest); err != nil {
				return 0, false, err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM records WHERE agent_id=? AND kind=? AND record_id=?", e.agentID, e.kind, e.id); err != nil {
				return 0, false, err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM history_expiry WHERE received_at_ns=? AND agent_id=? AND kind=? AND record_id=?", e.receivedAt, e.agentID, e.kind, e.id); err != nil {
			return 0, false, err
		}
	}
	return len(expired), false, tx.Commit()
}

const (
	observationReclaimInterval = time.Minute
	observationReclaimReserve  = 16 << 20
	observationReclaimMaxBytes = 256 << 10
)

func scheduleObservationReclaim(now, nextAttempt time.Time, backlog bool) (time.Time, bool) {
	if backlog || now.Before(nextAttempt) {
		return nextAttempt, false
	}
	return now.Add(observationReclaimInterval), true
}

// The byte budget bounds the pages returned by incremental vacuum. SQLite
// can also write WAL frames for moved records and their page references.
func (s *Store) reclaimObservationPages(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var mode int
	if err := tx.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&mode); err != nil || mode != 2 {
		return err
	}
	var pageSize, freePages int64
	if err := tx.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
		return err
	}
	// SQLite page sizes are powers of two from 512 to 65536. Both byte
	// thresholds are exact multiples for every supported page size.
	pages := min(freePages-observationReclaimReserve/pageSize, observationReclaimMaxBytes/pageSize)
	if pages <= 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA incremental_vacuum("+strconv.FormatInt(pages, 10)+")")
	if err != nil {
		return err
	}
	for rows.Next() {
		// SQLite performs one step per result; exhaust the bounded request.
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	return tx.Commit()
}

// MaintainObservationHistory runs only for the live service. At most one
// bounded retention batch holds the writer, with a yield between batches.
func (s *Store) MaintainObservationHistory(ctx context.Context, logger *slog.Logger) {
	const batch = 128
	const pause = 250 * time.Millisecond
	const idle = 5 * time.Second
	const budget = 400 * time.Millisecond
	delay := pause
	limit := batch
	nextReclaim := time.Now().Add(observationReclaimInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		bounded, cancel := context.WithTimeout(ctx, budget)
		processed, backfilled, err := s.pruneObservationHistory(bounded, time.Now(), limit)
		deadline := errors.Is(bounded.Err(), context.DeadlineExceeded)
		cancel()
		delay = idle
		if deadline {
			limit = max(8, limit/2)
		}
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("central observation retention deferred", "error", err)
			}
			continue
		}
		backlog := backfilled || processed == limit
		if backlog {
			delay = pause
		}
		var reclaim bool
		nextReclaim, reclaim = scheduleObservationReclaim(time.Now(), nextReclaim, backlog)
		if reclaim {
			reclaimCtx, cancelReclaim := context.WithTimeout(ctx, 100*time.Millisecond)
			err := s.reclaimObservationPages(reclaimCtx)
			cancelReclaim()
			if err != nil && ctx.Err() == nil {
				logger.Warn("central page reclamation deferred", "error", err)
			}
		}
	}
}
