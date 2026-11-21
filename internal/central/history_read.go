package central

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// The projected views expose one event or one finding per row. Delivery bundles
// remain immutable in records; legacy /api/history?kind= callers are unchanged.
func (s *Server) consoleHistoryView(w http.ResponseWriter, r *http.Request) {
	r, cancel := historyRequest(r)
	defer cancel()
	view := r.URL.Query().Get("view")
	if view != "events" && view != "detections" && view != "agent_audit" {
		s.historyError(w, r, "history view", fmt.Errorf("%w: 이력 구분을 확인하세요", ErrInvalid))
		return
	}
	filter, from, until, err := readHistoryFilter(r, view)
	limit, limitErr := historyLimit(r)
	if err == nil {
		err = limitErr
	}
	var cursor historyPageCursor
	if err == nil {
		cursor, err = readHistoryCursor(r, filter)
	}
	if err != nil {
		s.historyError(w, r, "history filter", err)
		return
	}
	query, args := buildHistoryQuery(filter, from, until, cursor, limit)
	page, hasMore, err := s.store.readHistoryPage(r.Context(), query, args, limit, historyResponseBytes, true)
	if err != nil {
		s.historyError(w, r, "history view read", err)
		return
	}
	items := []HistoryRecord{}
	var next historyPageCursor
	for _, row := range page {
		items = append(items, row.record)
		next = historyPageCursor{At: row.at, Agent: row.record.AgentID, Kind: row.source, ID: row.record.ID, Item: row.item, Filter: filter}
	}
	if hasMore {
		historyCursorHeader(w, next)
	}
	respond(w, http.StatusOK, items)
}

type AgentErrorRecord struct {
	ID         int64     `json:"id"`
	AgentID    string    `json:"agent_id"`
	Kind       string    `json:"kind"`
	Transition string    `json:"transition"`
	Category   string    `json:"category"`
	RecordedAt time.Time `json:"recorded_at"`
}

func (s *Server) consoleErrorHistory(w http.ResponseWriter, r *http.Request) {
	r, cancel := historyRequest(r)
	defer cancel()
	filter, from, until, err := readHistoryFilter(r, "errors")
	limit, limitErr := historyLimit(r)
	if err == nil {
		err = limitErr
	}
	if err == nil && filter.Type != "" && filter.Type != "agent" && filter.Type != "collector" && filter.Type != "policy" {
		err = fmt.Errorf("%w: 오류 유형을 확인하세요", ErrInvalid)
	}
	var cursor historyPageCursor
	if err == nil {
		cursor, err = readHistoryCursor(r, filter)
	}
	if err != nil {
		s.historyError(w, r, "error history filter", err)
		return
	}
	query := `SELECT id,agent_id,kind,transition,category,recorded_at_ns FROM console_agent_errors
WHERE (?='' OR site_id=?) AND (?='' OR agent_id=?) AND (?='' OR kind=?) AND (?=0 OR recorded_at_ns>=?) AND (?=0 OR recorded_at_ns<?)
AND (?='' OR instr(lower(kind||' '||transition||' '||category),lower(?))>0)
AND (?=0 OR (recorded_at_ns,id)<(?,?)) ORDER BY recorded_at_ns DESC,id DESC LIMIT ?`
	args := []any{filter.SiteID, filter.SiteID, filter.Agent, filter.Agent, filter.Type, filter.Type, from, from, until, until, filter.Search, filter.Search, cursor.At, cursor.At, cursor.Item, limit + 1}
	var body []byte
	err = s.store.historyDB.QueryRowContext(r.Context(), "SELECT json_group_array(json_object('id',id,'agent',agent_id,'kind',kind,'transition',transition,'category',category,'at',recorded_at_ns)) FROM ("+query+")", args...).Scan(&body)
	if err != nil {
		s.historyError(w, r, "error history query", err)
		return
	}
	var values []struct {
		ID         int64  `json:"id"`
		Agent      string `json:"agent"`
		Kind       string `json:"kind"`
		Transition string `json:"transition"`
		Category   string `json:"category"`
		At         int64  `json:"at"`
	}
	if err = json.Unmarshal(body, &values); err != nil {
		s.historyError(w, r, "error history decode", err)
		return
	}
	items := []AgentErrorRecord{}
	var next historyPageCursor
	hasMore := false
	used := 0
	for _, value := range values {
		cost := 512 + 6*(len(value.Agent)+len(value.Kind)+len(value.Transition)+len(value.Category))
		if len(items) == limit || len(items) > 0 && used+cost > historyResponseBytes {
			hasMore = true
			break
		}
		used += cost
		item := AgentErrorRecord{ID: value.ID, AgentID: value.Agent, Kind: value.Kind, Transition: value.Transition, Category: value.Category, RecordedAt: time.Unix(0, value.At).UTC()}
		items = append(items, item)
		next = historyPageCursor{At: value.At, ID: "errors", Item: value.ID, Filter: filter}
	}
	if hasMore {
		historyCursorHeader(w, next)
	}
	respond(w, http.StatusOK, items)
}

func (s *Server) consoleFilteredAudit(w http.ResponseWriter, r *http.Request) {
	r, cancel := historyRequest(r)
	defer cancel()
	filter, from, until, err := readHistoryFilter(r, "audit")
	limit, limitErr := historyLimit(r)
	if err == nil {
		err = limitErr
	}
	var cursor historyPageCursor
	if err == nil {
		cursor, err = readHistoryCursor(r, filter)
	}
	if err != nil {
		s.historyError(w, r, "audit filters", err)
		return
	}
	page, hasMore, err := s.store.readAuditPage(r.Context(), `SELECT audit_id,agent_id,kind,created_at_ns FROM audit
WHERE (?='' OR site_id=?) AND (?='' OR agent_id=?) AND (?='' OR kind=?) AND (?=0 OR created_at_ns>=?) AND (?=0 OR created_at_ns<?)
AND (?='' OR instr(lower(agent_id||' '||kind||' '||CAST(details_json AS TEXT)),lower(?))>0)
AND (?=0 OR (created_at_ns,audit_id)<(?,?)) ORDER BY created_at_ns DESC,audit_id DESC LIMIT ?`,
		[]any{filter.SiteID, filter.SiteID, filter.Agent, filter.Agent, filter.Type, filter.Type, from, from, until, until, filter.Search, filter.Search, cursor.At, cursor.At, cursor.Item, limit + 1}, limit, historyResponseBytes)
	if err != nil {
		s.historyError(w, r, "audit filtered read", err)
		return
	}
	items := []AuditEntry{}
	var next historyPageCursor
	for _, row := range page {
		items = append(items, row.record)
		next = historyPageCursor{At: row.at, ID: "audit", Item: row.record.ID, Filter: filter}
	}

	if hasMore {
		historyCursorHeader(w, next)
	}
	respond(w, http.StatusOK, items)
}
