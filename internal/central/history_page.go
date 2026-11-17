package central

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

const historyResponseBytes = 8 << 20

type historyPageItem struct {
	record HistoryRecord
	at     int64
	source string
	item   int64
}

func historyRowBytes(record HistoryRecord) int {
	// JSON escaping can expand metadata by up to six bytes per input byte.
	return historyJSONBytes(record.Payload) + 6*(len(record.AgentID)+len(record.Kind)+len(record.ID)) + 512
}

func historyJSONBytes(body []byte) int {
	return len(body) + 5*(bytes.Count(body, []byte("<"))+bytes.Count(body, []byte(">"))+bytes.Count(body, []byte("&"))) + 3*(bytes.Count(body, []byte("\xe2\x80\xa8"))+bytes.Count(body, []byte("\xe2\x80\xa9")))
}

// Sort only bounded metadata. After closing that result set, read immutable
// payloads by their primary key on the same read-only transaction/connection.
// This avoids both SQLite payload-sort amplification and nested pool acquisition.
func (s *Store) readHistoryPage(ctx context.Context, query string, args []any, limit, budget int, project bool) ([]historyPageItem, bool, error) {
	tx, err := s.historyDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	// modernc's query interrupt watcher covers the initial SQLite step. A
	// bounded one-row aggregate keeps sparse searches within that step instead
	// of leaving a later rows.Next scan outside the driver's watcher lifetime.
	metadataQuery := "SELECT json_group_array(json_object('agent',agent_id,'display',display_kind,'id',record_id,'at',received_at_ns,'source',source_kind,'item',item)) FROM (" + query + ")"
	var body []byte
	if err = tx.QueryRowContext(ctx, metadataQuery, args...).Scan(&body); err != nil {
		return nil, false, err
	}
	var values []struct {
		Agent   string `json:"agent"`
		Display string `json:"display"`
		ID      string `json:"id"`
		At      int64  `json:"at"`
		Source  string `json:"source"`
		Item    int64  `json:"item"`
	}
	if err = json.Unmarshal(body, &values); err != nil {
		return nil, false, err
	}
	metadata := make([]historyPageItem, 0, len(values))
	for _, value := range values {
		metadata = append(metadata, historyPageItem{record: HistoryRecord{AgentID: value.Agent, Kind: value.Display, ID: value.ID}, at: value.At, source: value.Source, item: value.Item})
	}
	statements := map[string]*sql.Stmt{}
	defer func() {
		for _, statement := range statements {
			_ = statement.Close()
		}
	}()
	items := []historyPageItem{}
	hasMore := false
	used := 0
	for _, row := range metadata {
		if len(items) == limit {
			hasMore = true
			break
		}
		expression := "payload"
		params := []any{row.record.AgentID, row.source, row.record.ID}
		if project && row.source == "event_bundle" {
			if row.record.Kind == "event" {
				expression = "json_extract(payload,'$.event')"
			} else if row.record.Kind == "finding" {
				expression = "json_extract(payload,'$.findings['||?||']')"
				params = append([]any{row.item}, params...)
			}
		}
		statement := statements[expression]
		if statement == nil {
			statement, err = tx.PrepareContext(ctx, "SELECT "+expression+" FROM records WHERE agent_id=? AND kind=? AND record_id=?")
			if err != nil {
				return nil, false, err
			}
			statements[expression] = statement
		}
		var payload []byte
		if err = statement.QueryRowContext(ctx, params...).Scan(&payload); err != nil {
			return nil, false, err
		}
		row.record.Payload = payload
		if !project {
			row.record.Kind = row.source
		}
		cost := historyRowBytes(row.record)
		// Valid records are at most 1 MiB. Always include the first one to preserve
		// forward progress even when a caller uses a smaller test budget.
		if len(items) > 0 && used+cost > budget {
			hasMore = true
			break
		}
		used += cost
		row.record.ReceivedAt = time.Unix(0, row.at).UTC()
		items = append(items, row)
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return items, hasMore, nil
}
