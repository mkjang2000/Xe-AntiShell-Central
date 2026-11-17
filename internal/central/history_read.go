package central

import (
	"fmt"
	"net/http"
	"time"
)

const detectionHistoryProjection = `SELECT agent_id,kind AS source_kind,record_id,received_at_ns,payload,0 AS item,'finding' AS display_kind FROM records WHERE kind='finding'
UNION ALL SELECT r.agent_id,r.kind,r.record_id,r.received_at_ns,j.value,CAST(j.key AS INTEGER),'finding' FROM records r INDEXED BY records_history_detection_bundle_idx,json_each(r.payload,'$.findings') j
WHERE r.kind='event_bundle' AND json_array_length(r.payload,'$.findings')>0 AND json_type(r.payload,'$.findings')='array' AND j.type='object'`

const historyPageQuery = `WITH history AS (%s) SELECT agent_id,display_kind,record_id,received_at_ns,payload,source_kind,item FROM history
WHERE (?='' OR agent_id=?) AND (?=0 OR received_at_ns>=?) AND (?=0 OR received_at_ns<?)
AND (?='' OR json_extract(payload,?)=?) AND (?='' OR instr(lower(CAST(payload AS TEXT)),lower(?))>0)
AND (?=0 OR (received_at_ns,agent_id,source_kind,record_id,item)<(?,?,?,?,?))
ORDER BY received_at_ns DESC,agent_id DESC,source_kind DESC,record_id DESC,item DESC LIMIT ?`

// The projected views expose one event or one finding per row. Delivery bundles
// remain immutable in records; legacy /api/history?kind= callers are unchanged.
func (s *Server) consoleHistoryView(w http.ResponseWriter, r *http.Request) {
	view := r.URL.Query().Get("view")
	if view != "events" && view != "detections" && view != "agent_audit" {
		s.consoleError(w, "history view", fmt.Errorf("%w: 이력 구분을 확인하세요", ErrInvalid))
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
		s.consoleError(w, "history filter", err)
		return
	}
	projection := `SELECT agent_id,kind AS source_kind,record_id,received_at_ns,payload,0 AS item,'audit' AS display_kind FROM records WHERE kind='audit'`
	typePath := "$.action"
	if view == "events" {
		projection = `SELECT agent_id,kind AS source_kind,record_id,received_at_ns,payload,0 AS item,'event' AS display_kind FROM records WHERE kind='event'
UNION ALL SELECT agent_id,kind,record_id,received_at_ns,json_extract(payload,'$.event'),0,'event' FROM records WHERE kind='event_bundle'`
		typePath = "$.event_type"
	} else if view == "detections" {
		projection = detectionHistoryProjection
		typePath = "$.rule_id"
	}
	rows, err := s.store.db.QueryContext(r.Context(), fmt.Sprintf(historyPageQuery, projection),
		filter.Agent, filter.Agent, from, from, until, until, filter.Type, typePath, filter.Type, filter.Search, filter.Search, cursor.At, cursor.At, cursor.Agent, cursor.Kind, cursor.ID, cursor.Item, limit+1)
	if err != nil {
		s.consoleError(w, "history view query", err)
		return
	}
	items := []HistoryRecord{}
	var next historyPageCursor
	hasMore := false
	for rows.Next() {
		var item HistoryRecord
		var at, index int64
		var sourceKind string
		var payload []byte
		if err = rows.Scan(&item.AgentID, &item.Kind, &item.ID, &at, &payload, &sourceKind, &index); err != nil {
			break
		}
		item.Payload = payload
		if len(items) == limit {
			hasMore = true
			break
		}
		item.ReceivedAt = time.Unix(0, at).UTC()
		items = append(items, item)
		next = historyPageCursor{At: at, Agent: item.AgentID, Kind: sourceKind, ID: item.ID, Item: index, Filter: filter}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		s.consoleError(w, "history view rows", err)
		return
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
		s.consoleError(w, "error history filter", err)
		return
	}
	rows, err := s.store.db.QueryContext(r.Context(), `SELECT id,agent_id,kind,transition,category,recorded_at_ns FROM console_agent_errors
WHERE (?='' OR agent_id=?) AND (?='' OR kind=?) AND (?=0 OR recorded_at_ns>=?) AND (?=0 OR recorded_at_ns<?)
AND (?='' OR instr(lower(kind||' '||transition||' '||category),lower(?))>0)
AND (?=0 OR (recorded_at_ns,id)<(?,?)) ORDER BY recorded_at_ns DESC,id DESC LIMIT ?`,
		filter.Agent, filter.Agent, filter.Type, filter.Type, from, from, until, until, filter.Search, filter.Search, cursor.At, cursor.At, cursor.Item, limit+1)
	if err != nil {
		s.consoleError(w, "error history query", err)
		return
	}
	items := []AgentErrorRecord{}
	var next historyPageCursor
	hasMore := false
	for rows.Next() {
		var item AgentErrorRecord
		var at int64
		if err = rows.Scan(&item.ID, &item.AgentID, &item.Kind, &item.Transition, &item.Category, &at); err != nil {
			break
		}
		if len(items) == limit {
			hasMore = true
			break
		}
		item.RecordedAt = time.Unix(0, at).UTC()
		items = append(items, item)
		next = historyPageCursor{At: at, ID: "errors", Item: item.ID, Filter: filter}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		s.consoleError(w, "error history rows", err)
		return
	}
	if hasMore {
		historyCursorHeader(w, next)
	}
	respond(w, http.StatusOK, items)
}

func (s *Server) consoleFilteredAudit(w http.ResponseWriter, r *http.Request) {
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
		s.consoleError(w, "audit filters", err)
		return
	}
	rows, err := s.store.db.QueryContext(r.Context(), `SELECT audit_id,agent_id,kind,created_at_ns,details_json FROM audit
WHERE (?='' OR agent_id=?) AND (?='' OR kind=?) AND (?=0 OR created_at_ns>=?) AND (?=0 OR created_at_ns<?)
AND (?='' OR instr(lower(agent_id||' '||kind||' '||CAST(details_json AS TEXT)),lower(?))>0)
AND (?=0 OR (created_at_ns,audit_id)<(?,?)) ORDER BY created_at_ns DESC,audit_id DESC LIMIT ?`,
		filter.Agent, filter.Agent, filter.Type, filter.Type, from, from, until, until, filter.Search, filter.Search, cursor.At, cursor.At, cursor.Item, limit+1)
	if err != nil {
		s.consoleError(w, "audit filtered query", err)
		return
	}
	items := []AuditEntry{}
	var next historyPageCursor
	hasMore := false
	for rows.Next() {
		var item AuditEntry
		var at int64
		if err = rows.Scan(&item.ID, &item.AgentID, &item.Kind, &at, &item.Details); err != nil {
			break
		}
		if len(items) == limit {
			hasMore = true
			break
		}
		item.CreatedAt = time.Unix(0, at).UTC()
		items = append(items, item)
		next = historyPageCursor{At: at, ID: "audit", Item: item.ID, Filter: filter}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		s.consoleError(w, "audit filtered rows", err)
		return
	}
	if hasMore {
		historyCursorHeader(w, next)
	}
	respond(w, http.StatusOK, items)
}
