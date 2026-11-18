package central

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// ConsoleHandler provides authenticated console business routes. It must only
// be mounted behind internal/console's session, same-origin and CSRF middleware;
// it intentionally accepts neither operator credentials nor browser sessions.
func (s *Server) ConsoleHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.consoleState)
	mux.HandleFunc("GET /api/agents/{id}/policy", s.consoleAgentPolicy)
	mux.HandleFunc("GET /api/history", s.consoleHistory)
	mux.HandleFunc("GET /api/finding-reviews", s.consoleFindingReviews)
	mux.HandleFunc("POST /api/finding-reviews", s.consoleFindingReviews)
	mux.HandleFunc("GET /api/errors", s.consoleErrorHistory)
	mux.HandleFunc("GET /api/audit", s.consoleAudit)
	mux.HandleFunc("POST /api/groups", s.consoleSaveGroup)
	mux.HandleFunc("DELETE /api/groups/{id}", s.consoleDeleteGroup)
	mux.HandleFunc("POST /api/templates", s.consoleSaveTemplate)
	mux.HandleFunc("DELETE /api/templates/{id}", s.consoleDeleteTemplate)
	mux.HandleFunc("POST /api/deploy/preview", s.consolePreview)
	mux.HandleFunc("POST /api/deploy", s.consoleDeploy)
	mux.HandleFunc("POST /api/enrollment", s.consoleEnrollment)
	// Reuse the existing enrollment-bound, policy-deny-aware signed grant flow.
	// Consumption and single-operation replay protection remain agent duties.
	mux.HandleFunc("POST /api/removal", s.consoleRemoval)
	mux.HandleFunc("POST /api/revoke", s.consoleRevoke)
	mux.HandleFunc("GET /api/updates/releases", s.consoleUpdateReleases)
	mux.HandleFunc("POST /api/updates/releases", s.consoleUpdateReleases)
	mux.HandleFunc("POST /api/updates/releases/{id}/delete", s.consoleDeleteUpdateRelease)
	mux.HandleFunc("GET /api/updates/agents", s.consoleUpdateAgents)
	mux.HandleFunc("POST /api/updates/preview", s.consoleUpdatePreview)
	mux.HandleFunc("POST /api/updates/rollouts", s.consoleCreateUpdate)
	mux.HandleFunc("GET /api/updates/rollouts", s.consoleUpdateRollouts)
	mux.HandleFunc("GET /api/updates/rollouts/{id}", s.consoleUpdateRollout)
	mux.HandleFunc("POST /api/updates/rollouts/{id}/cancel", s.consoleCancelUpdate)
	mux.HandleFunc("GET /api/updates/github/releases", s.consoleUpdateGitHubReleases)
	mux.HandleFunc("POST /api/updates/github/import", s.consoleImportUpdateGitHub)
	return secureHeaders(mux)
}

func consoleDecode(w http.ResponseWriter, r *http.Request, maximum int64, value any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		respond(w, http.StatusUnsupportedMediaType, map[string]string{"error": "application/json 형식으로 요청하세요"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximum)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		err = managed.DecodeStrict(body, int(maximum), value)
	}
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "JSON 형식이 잘못되었거나 요청 크기를 초과했습니다"})
		return false
	}
	return true
}

func (s *Server) consoleError(w http.ResponseWriter, operation string, err error) {
	status, message := http.StatusInternalServerError, "중앙 저장소 또는 서비스에 연결할 수 없습니다"
	switch {
	case errors.Is(err, errHistoryTimeout):
		status, message = http.StatusServiceUnavailable, "이력 조회 시간이 초과되었습니다. 기간·서버·유형을 좁혀 다시 조회하세요"
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, ErrInvalid):
		status, message = http.StatusBadRequest, "입력 값을 확인하세요"
		if suffix, ok := strings.CutPrefix(err.Error(), ErrInvalid.Error()+": "); ok {
			message = suffix
		}
	case errors.Is(err, ErrConflict):
		status, message = http.StatusConflict, "내용이 변경되었거나 미리보기가 만료되었습니다. 새로 조회한 뒤 다시 시도하세요"
	case errors.Is(err, ErrNotFound):
		status, message = http.StatusNotFound, "요청한 항목 또는 활성 에이전트를 찾을 수 없습니다"
	case errors.Is(err, ErrUnauthorized):
		status, message = http.StatusForbidden, "현재 등록 정보로 이 작업을 수행할 수 없습니다"
	default:
		// Database/crypto errors can contain request values. Keep logs free of
		// issued credentials, signed approvals and untrusted policy content.
		s.logger.Warn("console request failed", "operation", operation)
	}
	respond(w, status, map[string]string{"error": message})
}

func (s *Server) consoleState(w http.ResponseWriter, r *http.Request) {
	tx, err := s.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.consoleError(w, "state transaction", err)
		return
	}
	defer tx.Rollback()
	agents, err := listAgents(r.Context(), tx)
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "state agents", err)
		return
	}
	var totalAgents int
	if err = tx.QueryRowContext(r.Context(), "SELECT count(*) FROM agents").Scan(&totalAgents); err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "state fleet count", err)
		return
	}
	groups, templates := []ConsoleGroup{}, []ConsoleTemplate{}
	rows, err := tx.QueryContext(r.Context(), "SELECT id,name,description,version,agent_ids_json FROM console_groups ORDER BY id LIMIT 1000")
	if err == nil {
		for rows.Next() {
			var group ConsoleGroup
			var body []byte
			if err = rows.Scan(&group.ID, &group.Name, &group.Description, &group.Version, &body); err != nil {
				break
			}
			if err = json.Unmarshal(body, &group.AgentIDs); err != nil {
				break
			}
			groups = append(groups, group)
		}
		if err == nil {
			err = rows.Err()
		}
		_ = rows.Close()
	}
	if err == nil {
		rows, err = tx.QueryContext(r.Context(), "SELECT id,name,description,version,settings_json FROM console_templates ORDER BY id LIMIT 1000")
		if err == nil {
			for rows.Next() {
				var template ConsoleTemplate
				var body []byte
				if err = rows.Scan(&template.ID, &template.Name, &template.Description, &template.Version, &body); err != nil {
					break
				}
				if err = json.Unmarshal(body, &template.Settings); err != nil {
					break
				}
				templates = append(templates, template)
			}
			if err == nil {
				err = rows.Err()
			}
			_ = rows.Close()
		}
	}
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "state drafts", err)
		return
	}
	pending := make(map[string][]string)
	rows, err = tx.QueryContext(r.Context(), `SELECT a.agent_id,s.settings_json FROM agents a JOIN console_policy_settings s
ON a.agent_id=s.agent_id AND a.enrollment_id=s.enrollment_id AND a.desired_policy_revision=s.revision ORDER BY a.agent_id LIMIT 1000`)
	if err == nil {
		for rows.Next() {
			var id string
			var body []byte
			var settings ConsoleSettings
			if err = rows.Scan(&id, &body); err != nil {
				break
			}
			if err = json.Unmarshal(body, &settings); err != nil {
				break
			}
			pending[id] = consolePending(settings)
		}
		if err == nil {
			err = rows.Err()
		}
		_ = rows.Close()
	}
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "state pending features", err)
		return
	}
	type consoleAgent struct {
		Agent
		PendingFeatures []string `json:"pending_features"`
	}
	consoleAgents := make([]consoleAgent, 0, len(agents))
	for _, agent := range agents {
		features := pending[agent.ID]
		if features == nil {
			features = []string{}
		}
		consoleAgents = append(consoleAgents, consoleAgent{Agent: agent, PendingFeatures: features})
	}
	now := s.now().UTC()
	_ = tx.Rollback()
	respond(w, http.StatusOK, map[string]any{"server_time": now, "agents": consoleAgents, "total_agents": totalAgents, "agents_truncated": totalAgents > len(consoleAgents), "groups": groups, "templates": templates, "defaults": defaultConsoleSettings(now), "enrollment": map[string]any{"central_url": s.enrollmentURL, "ready": s.enrollmentURL != ""}})
}

func (s *Server) consoleSaveGroup(w http.ResponseWriter, r *http.Request) {
	var group ConsoleGroup
	if !consoleDecode(w, r, 256<<10, &group) {
		return
	}
	group, err := s.store.saveConsoleGroup(r.Context(), group, s.now().UTC())
	if err != nil {
		s.consoleError(w, "save group", err)
		return
	}
	respond(w, http.StatusOK, group)
}

func (s *Server) consoleSaveTemplate(w http.ResponseWriter, r *http.Request) {
	var template ConsoleTemplate
	if !consoleDecode(w, r, 1<<20, &template) {
		return
	}
	template, err := s.store.saveConsoleTemplate(r.Context(), template, s.now().UTC())
	if err != nil {
		s.consoleError(w, "save template", err)
		return
	}
	respond(w, http.StatusOK, template)
}

func (s *Server) consoleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	s.consoleDelete(w, r, true)
}

func (s *Server) consoleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	s.consoleDelete(w, r, false)
}

func (s *Server) consoleDelete(w http.ResponseWriter, r *http.Request, group bool) {
	version, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
	if err != nil {
		err = fmt.Errorf("%w: 현재 버전을 지정하세요", ErrInvalid)
	} else {
		err = s.store.deleteConsoleRecord(r.Context(), group, r.PathValue("id"), version, s.now().UTC())
	}
	if err != nil {
		s.consoleError(w, "delete draft", err)
		return
	}
	respond(w, http.StatusOK, map[string]string{"result": "deleted"})
}

func (s *Server) consoleRevoke(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AgentID string `json:"agent_id"`
		Confirm bool   `json:"confirm"`
	}
	if !consoleDecode(w, r, 1024, &request) {
		return
	}
	if !request.Confirm || !identifierPattern.MatchString(request.AgentID) {
		s.consoleError(w, "revoke confirmation", fmt.Errorf("%w: 에이전트 인증서 폐기 확인이 필요합니다", ErrInvalid))
		return
	}
	if err := s.store.Revoke(r.Context(), request.AgentID, s.now().UTC()); err != nil {
		s.consoleError(w, "revoke", err)
		return
	}
	respond(w, http.StatusOK, map[string]string{"result": "revoked"})
}
