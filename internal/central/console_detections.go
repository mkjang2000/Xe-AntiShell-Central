package central

import (
	"context"
	"database/sql"
	"time"
)

const (
	consoleDetectionWindow = 24 * time.Hour
	// Bounds one state refresh's scan; the console polls every 15 seconds.
	consoleDetectionScanLimit = 100_000
)

// consoleDetection counts detected events: standalone findings and event
// bundles with at least one finding. A bundle counts once however many rules it
// matched, so payloads are never read; the history view lists each finding.
type consoleDetection struct {
	Count int64      `json:"detections_24h"`
	Last  *time.Time `json:"last_detection_at,omitempty"`
}

// Counts are lower bounds when Truncated is set.
type consoleDetectionWindowInfo struct {
	Since     time.Time `json:"since"`
	Truncated bool      `json:"truncated"`
}

// consoleRecentDetections counts by central receipt time, the same time the
// history filters use. Both branches read only the indexes detection history
// already maintains; limit caps the entries scanned across all agents.
func consoleRecentDetections(ctx context.Context, tx *sql.Tx, since time.Time, limit int) (map[string]consoleDetection, consoleDetectionWindowInfo, error) {
	info := consoleDetectionWindowInfo{Since: since}
	from := since.UnixNano()
	rows, err := tx.QueryContext(ctx, `SELECT agent_id,count(*),max(received_at_ns) FROM (
SELECT agent_id,received_at_ns FROM records INDEXED BY records_history_detection_bundle_idx WHERE kind='event_bundle' AND json_array_length(payload,'$.findings')>0 AND received_at_ns>=?
UNION ALL
SELECT agent_id,received_at_ns FROM records INDEXED BY records_history_kind_idx WHERE kind='finding' AND received_at_ns>=?
LIMIT ?) GROUP BY agent_id`, from, from, limit+1)
	if err != nil {
		return nil, info, err
	}
	defer rows.Close()
	counts := make(map[string]consoleDetection)
	var total int64
	for rows.Next() {
		var agent string
		var count, last int64
		if err := rows.Scan(&agent, &count, &last); err != nil {
			return nil, info, err
		}
		at := time.Unix(0, last).UTC()
		counts[agent] = consoleDetection{Count: count, Last: &at}
		total += count
	}
	if err := rows.Err(); err != nil {
		return nil, info, err
	}
	info.Truncated = total > int64(limit)
	return counts, info, nil
}
