package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type auditPageItem struct {
	record AuditEntry
	at     int64
}

func (s *Store) readAuditPage(ctx context.Context, query string, args []any, limit, budget int) ([]auditPageItem, bool, error) {
	tx, err := s.historyDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	metadataQuery := "SELECT json_group_array(json_object('id',audit_id,'agent',agent_id,'kind',kind,'at',created_at_ns)) FROM (" + query + ")"
	var body []byte
	if err = tx.QueryRowContext(ctx, metadataQuery, args...).Scan(&body); err != nil {
		return nil, false, err
	}
	var values []struct {
		ID    int64  `json:"id"`
		Agent string `json:"agent"`
		Kind  string `json:"kind"`
		At    int64  `json:"at"`
	}
	if err = json.Unmarshal(body, &values); err != nil {
		return nil, false, err
	}
	statement, err := tx.PrepareContext(ctx, "SELECT details_json FROM audit WHERE audit_id=?")
	if err != nil {
		return nil, false, err
	}
	defer statement.Close()
	items := []auditPageItem{}
	hasMore := false
	used := 0
	for _, value := range values {
		if len(items) == limit {
			hasMore = true
			break
		}
		var details []byte
		if err = statement.QueryRowContext(ctx, value.ID).Scan(&details); err != nil {
			return nil, false, err
		}
		cost := historyJSONBytes(details) + 6*(len(value.Agent)+len(value.Kind)) + 512
		if len(items) > 0 && used+cost > budget {
			hasMore = true
			break
		}
		used += cost
		items = append(items, auditPageItem{record: AuditEntry{ID: value.ID, AgentID: value.Agent, Kind: value.Kind, CreatedAt: time.Unix(0, value.At).UTC(), Details: details}, at: value.At})
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return items, hasMore, nil
}
