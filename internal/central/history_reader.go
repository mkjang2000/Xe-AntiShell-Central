package central

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const historyQueryTimeout = 3 * time.Second

var errHistoryTimeout = errors.New("history query deadline exceeded")

// Small indexed keys keep history filters independent of the returned payload.
const historyReadSchema = `
CREATE INDEX IF NOT EXISTS records_history_event_type_idx ON records(json_extract(payload,'$.event_type'),received_at_ns DESC,agent_id DESC,record_id DESC) WHERE kind='event';
CREATE INDEX IF NOT EXISTS records_history_bundle_event_type_idx ON records(json_extract(payload,'$.event.event_type'),received_at_ns DESC,agent_id DESC,record_id DESC) WHERE kind='event_bundle';
CREATE INDEX IF NOT EXISTS records_history_event_agent_type_idx ON records(agent_id,json_extract(payload,'$.event_type'),received_at_ns DESC,record_id DESC) WHERE kind='event';
CREATE INDEX IF NOT EXISTS records_history_bundle_event_agent_type_idx ON records(agent_id,json_extract(payload,'$.event.event_type'),received_at_ns DESC,record_id DESC) WHERE kind='event_bundle';
`

func (s *Store) openHistoryReader(ctx context.Context, path string) error {
	db, err := openHistoryReadPool(ctx, path)
	if err == nil {
		s.historyDB = db
	}
	return err
}

func openHistoryReadPool(ctx context.Context, path string) (*sql.DB, error) {
	u := &url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(ON)")
	q.Add("_pragma", "busy_timeout(1000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func historyRequest(r *http.Request) (*http.Request, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), historyQueryTimeout)
	return r.WithContext(ctx), cancel
}
func (s *Server) historyError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	s.consoleError(w, operation, historyReadError(r.Context(), err))
}

func historyReadError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errHistoryTimeout
	}
	return err
}

func (s *Store) History(ctx context.Context, agentID, kind string, limit int) ([]HistoryRecord, error) {
	if limit < 1 || limit > 500 {
		return nil, fmt.Errorf("%w: history limit must be 1..500", ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, historyQueryTimeout)
	defer cancel()
	query := "SELECT agent_id,kind AS display_kind,record_id,received_at_ns,NULL AS payload,kind AS source_kind,0 AS item FROM records"
	conditions := []string{}
	args := []any{}
	if agentID != "" {
		conditions = append(conditions, "agent_id=?")
		args = append(args, agentID)
	}
	if kind != "" {
		conditions = append(conditions, "kind=?")
		args = append(args, kind)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY received_at_ns DESC,record_id ASC LIMIT ?"
	args = append(args, limit+1)
	page, _, err := s.readHistoryPage(ctx, query, args, limit, historyResponseBytes, false)
	if err != nil {
		return nil, historyReadError(ctx, err)
	}
	items := []HistoryRecord{}
	for _, row := range page {
		items = append(items, row.record)
	}
	return items, nil
}

func (s *Store) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit < 1 || limit > 500 {
		return nil, fmt.Errorf("%w: audit limit must be 1..500", ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, historyQueryTimeout)
	defer cancel()
	page, _, err := s.readAuditPage(ctx, "SELECT audit_id,agent_id,kind,created_at_ns FROM audit ORDER BY audit_id DESC LIMIT ?", []any{limit + 1}, limit, historyResponseBytes)
	if err != nil {
		return nil, historyReadError(ctx, err)
	}
	items := []AuditEntry{}
	for _, row := range page {
		items = append(items, row.record)
	}
	return items, nil
}
