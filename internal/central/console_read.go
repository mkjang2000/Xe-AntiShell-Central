package central

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (s *Server) consoleAgentPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !identifierPattern.MatchString(id) {
		s.consoleError(w, "agent policy input", ErrInvalid)
		return
	}
	tx, err := s.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.consoleError(w, "agent policy transaction", err)
		return
	}
	defer tx.Rollback()
	var enrollment string
	if err = tx.QueryRowContext(r.Context(), "SELECT enrollment_id FROM agents WHERE agent_id=?", id).Scan(&enrollment); errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "agent policy target", err)
		return
	}
	var body []byte
	err = tx.QueryRowContext(r.Context(), "SELECT signed_json FROM policies WHERE agent_id=? AND enrollment_id=? ORDER BY revision DESC LIMIT 1", id, enrollment).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		respond(w, http.StatusOK, map[string]any{"policy": nil, "pending_features": []string{}})
		return
	}
	var signed managed.SignedPolicy
	if err == nil {
		err = json.Unmarshal(body, &signed)
	}
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "agent policy decode", err)
		return
	}
	response := map[string]any{"policy": signed.Policy, "pending_features": []string{}}
	err = tx.QueryRowContext(r.Context(), "SELECT settings_json FROM console_policy_settings WHERE agent_id=? AND enrollment_id=? AND revision=?", id, enrollment, signed.Policy.Revision).Scan(&body)
	if err == nil {
		var settings ConsoleSettings
		if err = json.Unmarshal(body, &settings); err == nil {
			response["desired_settings"], response["pending_features"] = settings, consolePending(settings)
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		s.consoleError(w, "agent desired settings", err)
		return
	}
	_ = tx.Rollback()
	respond(w, http.StatusOK, response)
}

type consoleHistoryCursor struct {
	At          int64  `json:"at"`
	AgentID     string `json:"agent_id"`
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	FilterAgent string `json:"filter_agent"`
	FilterKind  string `json:"filter_kind"`
}

func (s *Server) consoleHistory(w http.ResponseWriter, r *http.Request) {
	agentID, kind := r.URL.Query().Get("agent_id"), r.URL.Query().Get("kind")
	limit := queryLimit(r)
	if agentID != "" && !identifierPattern.MatchString(agentID) || kind != "" && kind != "event" && kind != "finding" && kind != "event_bundle" && kind != "audit" && kind != "detections" || limit < 1 || limit > 500 {
		s.consoleError(w, "history filter", fmt.Errorf("%w: 이력 조회 조건과 개수(1~500)를 확인하세요", ErrInvalid))
		return
	}
	before := r.URL.Query().Get("before")
	var cursor consoleHistoryCursor
	if before != "" {
		body, err := base64.RawURLEncoding.DecodeString(before)
		if len(before) > 2048 || err != nil || managed.DecodeStrict(body, 1536, &cursor) != nil || cursor.FilterAgent != agentID || cursor.FilterKind != kind || cursor.AgentID == "" || cursor.ID == "" {
			s.consoleError(w, "history cursor", fmt.Errorf("%w: 이력 페이지 정보가 잘못되었습니다", ErrInvalid))
			return
		}
	}
	rows, err := s.store.db.QueryContext(r.Context(), `SELECT agent_id,kind,record_id,received_at_ns,payload FROM records
WHERE (?='' OR agent_id=?) AND (?='' OR kind=? OR (?='detections' AND (kind='finding' OR (kind='event_bundle' AND json_array_length(payload,'$.findings')>0))))
AND (?='' OR (received_at_ns,agent_id,kind,record_id)<(?,?,?,?))
ORDER BY received_at_ns DESC,agent_id DESC,kind DESC,record_id DESC LIMIT ?`,
		agentID, agentID, kind, kind, kind, before, cursor.At, cursor.AgentID, cursor.Kind, cursor.ID, limit+1)
	if err != nil {
		s.consoleError(w, "history query", err)
		return
	}
	defer rows.Close()
	items := []HistoryRecord{}
	var next consoleHistoryCursor
	hasMore := false
	for rows.Next() {
		var item HistoryRecord
		var payload []byte
		var at int64
		if err = rows.Scan(&item.AgentID, &item.Kind, &item.ID, &at, &payload); err != nil {
			break
		}
		if len(items) == limit {
			hasMore = true
			break
		}
		item.ReceivedAt = time.Unix(0, at).UTC()
		item.Payload = payload
		items = append(items, item)
		next = consoleHistoryCursor{At: at, AgentID: item.AgentID, Kind: item.Kind, ID: item.ID, FilterAgent: agentID, FilterKind: kind}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		s.consoleError(w, "history rows", err)
		return
	}
	if hasMore {
		body, err := json.Marshal(next)
		if err != nil {
			s.consoleError(w, "history cursor encoding", err)
			return
		}
		w.Header().Set("X-Next-Cursor", base64.RawURLEncoding.EncodeToString(body))
	}
	respond(w, http.StatusOK, items)
}

func (s *Server) consoleAudit(w http.ResponseWriter, r *http.Request) {
	limit := queryLimit(r)
	before := r.URL.Query().Get("before")
	var cursor int64
	var err error
	if before != "" {
		cursor, err = strconv.ParseInt(before, 10, 64)
	}
	if err != nil || before != "" && cursor < 1 || limit < 1 || limit > 500 {
		s.consoleError(w, "audit cursor", fmt.Errorf("%w: 감사 이력 페이지 정보와 개수(1~500)를 확인하세요", ErrInvalid))
		return
	}
	rows, err := s.store.db.QueryContext(r.Context(), "SELECT audit_id,agent_id,kind,created_at_ns,details_json FROM audit WHERE (?='' OR audit_id<?) ORDER BY audit_id DESC LIMIT ?", before, cursor, limit+1)
	if err != nil {
		s.consoleError(w, "audit query", err)
		return
	}
	defer rows.Close()
	items := []AuditEntry{}
	hasMore := false
	for rows.Next() {
		var item AuditEntry
		var details []byte
		var at int64
		if err = rows.Scan(&item.ID, &item.AgentID, &item.Kind, &at, &details); err != nil {
			break
		}
		if len(items) == limit {
			hasMore = true
			break
		}
		item.CreatedAt = time.Unix(0, at).UTC()
		item.Details = details
		items = append(items, item)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		s.consoleError(w, "audit rows", err)
		return
	}
	if hasMore {
		w.Header().Set("X-Next-Cursor", strconv.FormatInt(items[len(items)-1].ID, 10))
	}
	respond(w, http.StatusOK, items)
}
