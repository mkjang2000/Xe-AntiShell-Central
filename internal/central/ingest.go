package central

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func (s *Store) Ingest(ctx context.Context, agentID string, batch managed.Batch, now time.Time) (managed.Ack, error) {
	ack := managed.Ack{SpoolID: batch.SpoolID}
	if len(batch.EnrollmentID) < 16 || len(batch.SpoolID) < 8 || len(batch.SpoolID) > 128 || len(batch.Records) == 0 || len(batch.Records) > managed.MaxBatchRecords {
		return ack, fmt.Errorf("%w: invalid delivery batch", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ack, err
	}
	defer tx.Rollback()
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agents WHERE agent_id=? AND enrollment_id=? AND revoked=0", agentID, batch.EnrollmentID).Scan(&active); err != nil {
		return ack, err
	}
	if active != 1 {
		return ack, ErrUnauthorized
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO delivery_cursors(agent_id,enrollment_id,spool_id) VALUES(?,?,?) ON CONFLICT DO NOTHING", agentID, batch.EnrollmentID, batch.SpoolID); err != nil {
		return ack, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT acknowledged FROM delivery_cursors WHERE agent_id=? AND enrollment_id=? AND spool_id=?", agentID, batch.EnrollmentID, batch.SpoolID).Scan(&ack.Acknowledged); err != nil {
		return ack, err
	}
	var previous uint64
	for _, record := range batch.Records {
		if record.Sequence == 0 || record.Sequence > math.MaxInt64 || record.Sequence <= previous {
			return ack, fmt.Errorf("%w: delivery records must be strictly ordered", ErrInvalid)
		}
		previous = record.Sequence
		body, err := validateRecord(record)
		if err != nil {
			return ack, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		digest := sha256.Sum256(body)
		hash := hex.EncodeToString(digest[:])
		if record.Sequence <= ack.Acknowledged {
			var kind, id, oldHash string
			err = tx.QueryRowContext(ctx, "SELECT kind,record_id,payload_hash FROM deliveries WHERE agent_id=? AND enrollment_id=? AND spool_id=? AND sequence=?", agentID, batch.EnrollmentID, batch.SpoolID, record.Sequence).Scan(&kind, &id, &oldHash)
			if err != nil || kind != record.Kind || id != record.ID || oldHash != hash {
				return ack, ErrConflict
			}
			continue
		}
		if record.Sequence != ack.Acknowledged+1 {
			return ack, fmt.Errorf("%w: non-contiguous delivery sequence", ErrConflict)
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO records(agent_id,kind,record_id,payload,received_at_ns) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING", agentID, record.Kind, record.ID, body, now.UnixNano())
		if err != nil {
			return ack, err
		}
		inserted, _ := result.RowsAffected()
		if inserted == 0 {
			var oldBody []byte
			if err = tx.QueryRowContext(ctx, "SELECT payload FROM records WHERE agent_id=? AND kind=? AND record_id=?", agentID, record.Kind, record.ID).Scan(&oldBody); err != nil {
				return ack, err
			}
			if !bytes.Equal(oldBody, body) {
				return ack, ErrConflict
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO deliveries(agent_id,enrollment_id,spool_id,sequence,kind,record_id,payload_hash) VALUES(?,?,?,?,?,?,?)", agentID, batch.EnrollmentID, batch.SpoolID, record.Sequence, record.Kind, record.ID, hash); err != nil {
			return ack, err
		}
		ack.Acknowledged = record.Sequence
	}
	if _, err = tx.ExecContext(ctx, "UPDATE delivery_cursors SET acknowledged=? WHERE agent_id=? AND enrollment_id=? AND spool_id=?", ack.Acknowledged, agentID, batch.EnrollmentID, batch.SpoolID); err != nil {
		return ack, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE agents SET last_seen_at_ns=? WHERE agent_id=?", now.UnixNano(), agentID); err != nil {
		return ack, err
	}
	if err = tx.Commit(); err != nil {
		return managed.Ack{SpoolID: batch.SpoolID}, err
	}
	return ack, nil
}

func validateRecord(record managed.Record) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	if record.ID == "" || len(record.ID) > 160 || len(record.Payload) == 0 || len(record.Payload) > managed.MaxRecordBytes {
		return nil, errors.New("invalid record bounds")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(record.Payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid record JSON")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	switch record.Kind {
	case "event":
		var event model.Event
		if json.Unmarshal(body, &event) != nil || event.ID != record.ID || event.Type == "" || event.EventTime.IsZero() {
			return nil, errors.New("invalid event record")
		}
		if err := validatePrivilegeObservation(event); err != nil {
			return nil, err
		}
	case "finding":
		var finding model.Finding
		if json.Unmarshal(body, &finding) != nil || finding.ID != record.ID || finding.RuleID == "" || finding.CreatedAt.IsZero() {
			return nil, errors.New("invalid finding record")
		}
	case "event_bundle":
		var bundle struct {
			Event    model.Event     `json:"event"`
			Findings []model.Finding `json:"findings"`
		}
		if json.Unmarshal(body, &bundle) != nil || bundle.Event.ID != record.ID || bundle.Event.Type == "" || len(bundle.Findings) > 64 {
			return nil, errors.New("invalid event bundle")
		}
		if err := validatePrivilegeObservation(bundle.Event); err != nil {
			return nil, err
		}
		for _, finding := range bundle.Findings {
			if finding.ID == "" || finding.RuleID == "" || len(finding.EvidenceEventIDs) == 0 {
				return nil, errors.New("invalid bundle finding")
			}
			for _, eventID := range finding.EvidenceEventIDs {
				if eventID != bundle.Event.ID {
					return nil, errors.New("bundle finding references missing evidence")
				}
			}
		}
	case "audit":
		if _, ok := value.(map[string]any); !ok {
			return nil, errors.New("audit record must be an object")
		}
	default:
		return nil, errors.New("unsupported record kind")
	}
	return body, nil
}

func (s *Store) Heartbeat(ctx context.Context, agentID string, heartbeat managed.Heartbeat, now time.Time) error {
	body, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}
	if len(body) > managed.MaxHeartbeatBytes {
		return fmt.Errorf("%w: heartbeat too large", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE agents SET hostname=?,heartbeat_json=?,last_seen_at_ns=? WHERE agent_id=? AND enrollment_id=? AND revoked=0", heartbeat.Hostname, body, now.UnixNano(), agentID, heartbeat.EnrollmentID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrUnauthorized
	}
	if err = recordHeartbeatErrors(ctx, tx, agentID, heartbeat, now, false); err != nil {
		return err
	}
	return tx.Commit()
}

type HistoryRecord struct {
	AgentID    string          `json:"agent_id"`
	Kind       string          `json:"kind"`
	ID         string          `json:"id"`
	ReceivedAt time.Time       `json:"received_at"`
	Payload    json.RawMessage `json:"payload"`
}
type AuditEntry struct {
	ID        int64           `json:"id"`
	AgentID   string          `json:"agent_id"`
	Kind      string          `json:"kind"`
	CreatedAt time.Time       `json:"created_at"`
	Details   json.RawMessage `json:"details"`
}

func (s *Store) CurrentEnrollment(ctx context.Context, agentID string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT enrollment_id FROM agents WHERE agent_id=? AND revoked=0", agentID).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}
