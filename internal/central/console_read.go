package central

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

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
	var heartbeat []byte
	var seen int64
	var revoked bool
	if err = tx.QueryRowContext(r.Context(), "SELECT enrollment_id,heartbeat_json,last_seen_at_ns,revoked FROM agents WHERE agent_id=?", id).Scan(&enrollment, &heartbeat, &seen, &revoked); errors.Is(err, sql.ErrNoRows) {
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
		respond(w, http.StatusOK, map[string]any{"policy": nil, "pending_features": []string{}, "applied_policy": nil, "application_status": applicationStatus{State: "none"}})
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
	applied, status, err := reportedApplicationPolicy(r.Context(), tx, signed, heartbeat, seen, revoked, s.now().UTC())
	if err != nil {
		s.consoleError(w, "agent applied policy", err)
		return
	}
	response := map[string]any{"policy": signed.Policy, "pending_features": []string{}, "applied_policy": applied, "application_status": status}
	var measured bool
	err = tx.QueryRowContext(r.Context(), `SELECT s.settings_json,EXISTS(SELECT 1 FROM integrity_file_reports f WHERE (f.agent_id,f.enrollment_id,f.revision)=(s.agent_id,s.enrollment_id,s.revision)) FROM console_policy_settings s WHERE s.agent_id=? AND s.enrollment_id=? AND s.revision=?`, id, enrollment, signed.Policy.Revision).Scan(&body, &measured)
	if err == nil {
		var settings ConsoleSettings
		if err = json.Unmarshal(body, &settings); err == nil {
			response["desired_settings"], response["pending_features"] = settings, consolePendingWithMeasurement(settings, measured)
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
	if r.URL.Query().Get("view") != "" {
		s.consoleHistoryView(w, r)
		return
	}
	r, cancel := historyRequest(r)
	defer cancel()
	agentID, kind := r.URL.Query().Get("agent_id"), r.URL.Query().Get("kind")
	limit := queryLimit(r)
	if agentID != "" && !identifierPattern.MatchString(agentID) || kind != "" && kind != "event" && kind != "finding" && kind != "event_bundle" && kind != "audit" && kind != "detections" || limit < 1 || limit > 500 {
		s.historyError(w, r, "history filter", fmt.Errorf("%w: 이력 조회 조건과 개수(1~500)를 확인하세요", ErrInvalid))
		return
	}
	before := r.URL.Query().Get("before")
	var cursor consoleHistoryCursor
	if before != "" {
		body, err := base64.RawURLEncoding.DecodeString(before)
		if len(before) > 2048 || err != nil || managed.DecodeStrict(body, 1536, &cursor) != nil || cursor.FilterAgent != agentID || cursor.FilterKind != kind || cursor.AgentID == "" || cursor.ID == "" {
			s.historyError(w, r, "history cursor", fmt.Errorf("%w: 이력 페이지 정보가 잘못되었습니다", ErrInvalid))
			return
		}
	}
	query, args := buildLegacyHistoryQuery(agentID, kind, cursor, limit)
	page, hasMore, err := s.store.readHistoryPage(r.Context(), query, args, limit, historyResponseBytes, false)
	if err != nil {
		s.historyError(w, r, "history read", err)
		return
	}
	items := []HistoryRecord{}
	var next consoleHistoryCursor
	for _, row := range page {
		items = append(items, row.record)
		next = consoleHistoryCursor{At: row.at, AgentID: row.record.AgentID, Kind: row.source, ID: row.record.ID, FilterAgent: agentID, FilterKind: kind}
	}
	if hasMore {
		body, err := json.Marshal(next)
		if err != nil {
			s.historyError(w, r, "history cursor encoding", err)
			return
		}
		w.Header().Set("X-Next-Cursor", base64.RawURLEncoding.EncodeToString(body))
	}
	respond(w, http.StatusOK, items)
}

func (s *Server) consoleAudit(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("view") == "audit" || query.Has("from") || query.Has("until") || query.Has("agent_id") || query.Has("type") || query.Has("q") {
		s.consoleFilteredAudit(w, r)
		return
	}
	r, cancel := historyRequest(r)
	defer cancel()
	limit := queryLimit(r)
	before := r.URL.Query().Get("before")
	var cursor int64
	var err error
	if before != "" {
		cursor, err = strconv.ParseInt(before, 10, 64)
	}
	if err != nil || before != "" && cursor < 1 || limit < 1 || limit > 500 {
		s.historyError(w, r, "audit cursor", fmt.Errorf("%w: 감사 이력 페이지 정보와 개수(1~500)를 확인하세요", ErrInvalid))
		return
	}
	statement := "SELECT audit_id,agent_id,kind,created_at_ns FROM audit"
	args := []any{}
	if before != "" {
		statement += " WHERE audit_id<?"
		args = append(args, cursor)
	}
	statement += " ORDER BY audit_id DESC LIMIT ?"
	args = append(args, limit+1)
	page, hasMore, err := s.store.readAuditPage(r.Context(), statement, args, limit, historyResponseBytes)
	if err != nil {
		s.historyError(w, r, "audit read", err)
		return
	}
	items := []AuditEntry{}
	for _, row := range page {
		items = append(items, row.record)
	}
	if hasMore {
		w.Header().Set("X-Next-Cursor", strconv.FormatInt(items[len(items)-1].ID, 10))
	}
	respond(w, http.StatusOK, items)
}
