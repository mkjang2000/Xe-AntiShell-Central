package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// Copy only the cursor for each stream. Receipts for pre-upgrade sequences
// stay in deliveries, so opening the upgraded database never walks that ledger.
const deliveryReceiptSchema = `
CREATE TABLE delivery_cursors_v4 (
 spool_key INTEGER PRIMARY KEY,
 agent_id TEXT NOT NULL,
 enrollment_id TEXT NOT NULL,
 spool_id TEXT NOT NULL,
 acknowledged INTEGER NOT NULL DEFAULT 0,
 legacy_through INTEGER NOT NULL DEFAULT 0 CHECK(legacy_through BETWEEN 0 AND acknowledged),
 UNIQUE(agent_id,enrollment_id,spool_id)
);
INSERT INTO delivery_cursors_v4(agent_id,enrollment_id,spool_id,acknowledged,legacy_through)
 SELECT agent_id,enrollment_id,spool_id,acknowledged,acknowledged FROM delivery_cursors;
DROP TABLE delivery_cursors;
ALTER TABLE delivery_cursors_v4 RENAME TO delivery_cursors;
CREATE TABLE delivery_receipts (
 spool_key INTEGER NOT NULL REFERENCES delivery_cursors(spool_key),
 sequence INTEGER NOT NULL,
 receipt BLOB NOT NULL CHECK(length(receipt)=32),
 PRIMARY KEY(spool_key,sequence)
) WITHOUT ROWID;
`

// Commit to the original wire identity as well as its canonical payload.
// An audit record can have the same payload under different IDs.
func deliveryReceipt(kind, id string, payloadDigest [sha256.Size]byte) [sha256.Size]byte {
	var buffer [256]byte // fits every validated kind and ID
	frame := append(buffer[:0], "xe-antishell/delivery-receipt/v1\x00"...)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(kind)))
	frame = append(frame, kind...)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(id)))
	frame = append(frame, id...)
	frame = append(frame, payloadDigest[:]...)
	return sha256.Sum256(frame)
}

func verifyDeliveryReceipt(ctx context.Context, tx *sql.Tx, spoolKey int64, legacyThrough uint64, agentID string, batch managed.Batch, record managed.Record, digest [sha256.Size]byte) error {
	var match int
	var err error
	if record.Sequence <= legacyThrough {
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM deliveries
WHERE agent_id=? AND enrollment_id=? AND spool_id=? AND sequence=?
AND kind=? AND record_id=? AND payload_hash=?`, agentID, batch.EnrollmentID, batch.SpoolID,
			record.Sequence, record.Kind, record.ID, hex.EncodeToString(digest[:])).Scan(&match)
	} else {
		receipt := deliveryReceipt(record.Kind, record.ID, digest)
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM delivery_receipts
WHERE spool_key=? AND sequence=? AND receipt=?`, spoolKey, record.Sequence, receipt[:]).Scan(&match)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	return err
}
