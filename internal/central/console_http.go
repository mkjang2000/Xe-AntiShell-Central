package central

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// ConsoleHandler provides authenticated console business routes. It must only
// be mounted behind internal/console's session, same-origin and CSRF middleware;
// it intentionally accepts neither operator credentials nor browser sessions.
func (s *Server) ConsoleHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.consoleState)
	mux.HandleFunc("GET /api/sites", s.consoleSites)
	mux.HandleFunc("POST /api/sites", s.consoleSites)
	mux.HandleFunc("POST /api/sites/{id}/agents", s.consoleMoveSiteAgent)
	for _, pattern := range []string{"GET /api/policy-trials", "POST /api/policy-trials", "GET /api/policy-trials/{id}", "POST /api/policy-trials/{id}/{operation}"} {
		mux.HandleFunc(pattern, s.consolePolicyTrial)
	}
	mux.HandleFunc("GET /api/agents/{id}/integrity", s.consoleFileIntegrity)
	mux.HandleFunc("GET /api/agents/{id}/policy", s.consoleAgentPolicy)
	mux.HandleFunc("GET /api/agents/{id}/service-inventory", s.consoleAgentServiceInventory)
	mux.HandleFunc("GET /api/history", s.consoleHistory)
	mux.HandleFunc("GET /api/finding-reviews", s.consoleFindingReviews)
	mux.HandleFunc("POST /api/finding-reviews", s.consoleFindingReviews)
	mux.HandleFunc("GET /api/errors", s.consoleErrorHistory)
	mux.HandleFunc("GET /api/audit", s.consoleAudit)
	mux.HandleFunc("POST /api/groups", s.consoleSaveGroup)
	mux.HandleFunc("DELETE /api/groups/{id}", s.consoleDeleteGroup)
	mux.HandleFunc("GET /api/templates/{id}/usage", s.consoleTemplateUsage)
	mux.HandleFunc("POST /api/templates", s.consoleSaveTemplate)
	mux.HandleFunc("DELETE /api/templates/{id}", s.consoleDeleteTemplate)
	mux.HandleFunc("POST /api/deploy/preview", s.consolePreview)
	mux.HandleFunc("POST /api/deploy", s.consoleDeploy)
	mux.HandleFunc("GET /api/agent-configuration/{id}", s.consoleAgentConfiguration)
	mux.HandleFunc("POST /api/agent-configuration/preview", s.consoleAgentConfigurationPreview)
	mux.HandleFunc("POST /api/agent-configuration/apply", s.consoleAgentConfigurationApply)
	mux.HandleFunc("POST /api/enrollment", s.consoleEnrollment)
	// Reuse the existing enrollment-bound, policy-deny-aware signed grant flow.
	// Consumption and single-operation replay protection remain agent duties.
	mux.HandleFunc("POST /api/removal", s.consoleRemoval)
	mux.HandleFunc("POST /api/revoke", s.consoleRevoke)
	mux.HandleFunc("GET /api/agents/{id}/remote-removal", s.consoleRemoteRemoval)
	mux.HandleFunc("POST /api/agents/{id}/remote-removal", s.consoleRemoteRemoval)
	mux.HandleFunc("POST /api/agents/{id}/remote-removal/cancel", s.consoleRemoteRemovalCancel)
	mux.HandleFunc("POST /api/remote-removal/preview", s.consoleRemoteRemovalBatchPreview)
	mux.HandleFunc("POST /api/remote-removal/batches", s.consoleRemoteRemovalBatchApply)
	mux.HandleFunc("GET /api/remote-removal/batches/{id}", s.consoleRemoteRemovalBatchStatus)
	mux.HandleFunc("GET "+centralUpdateBase+"status", s.consoleSelfUpdate)
	mux.HandleFunc("GET "+centralUpdateBase+"releases", s.consoleSelfUpdate)
	mux.HandleFunc("POST "+centralUpdateBase+"github", s.consoleSelfUpdate)
	mux.HandleFunc("POST "+centralUpdateBase+"upload", s.consoleSelfUpdate)
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
	return secureHeaders(s.consoleSiteScope(mux))
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
	siteID := selectedSite(r.Context())
	readAgents := mayReadConsoleAgents(r)
	agents := []Agent{}
	var totalAgents int
	if readAgents {
		agents, err = listAgents(r.Context(), tx)
		if err != nil {
			_ = tx.Rollback()
			s.consoleError(w, "state agents", err)
			return
		}
		if err = tx.QueryRowContext(r.Context(), "SELECT count(*) FROM agents WHERE (?='' OR site_id=?)", siteID, siteID).Scan(&totalAgents); err != nil {
			_ = tx.Rollback()
			s.consoleError(w, "state fleet count", err)
			return
		}
	}
	groups, templates := []ConsoleGroup{}, []ConsoleTemplate{}
	var rows *sql.Rows
	if mayReadConsoleGroups(r) {
		rows, err = tx.QueryContext(r.Context(), "SELECT id,name,description,version,agent_ids_json,site_id FROM console_groups WHERE (?='' OR site_id=?) ORDER BY id LIMIT 1000", siteID, siteID)
	}
	if rows != nil && err == nil {
		for rows.Next() {
			var group ConsoleGroup
			var body []byte
			if err = rows.Scan(&group.ID, &group.Name, &group.Description, &group.Version, &body, &group.SiteID); err != nil {
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
	if err == nil && mayReadConsoleTemplates(r) {
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
	assignments := make(map[string]consoleAssignment)
	now := s.now().UTC()
	var responses map[string]consoleResponse
	var detections map[string]consoleDetection
	window := consoleDetectionWindowInfo{Since: now.Add(-consoleDetectionWindow)}
	if readAgents {
		latest := make(map[string][]byte, len(templates))
		for _, template := range templates {
			if latest[template.ID], err = json.Marshal(template.Settings); err != nil {
				break
			}
		}
		if err == nil {
			rows, err = tx.QueryContext(r.Context(), `SELECT a.agent_id,s.settings_json,EXISTS(SELECT 1 FROM integrity_file_reports f WHERE (f.agent_id,f.enrollment_id,f.revision)=(s.agent_id,s.enrollment_id,s.revision)),
COALESCE(json_extract(CAST(p.signed_json AS TEXT),'$.policy.policy_id'),'') FROM agents a JOIN console_policy_settings s
ON a.agent_id=s.agent_id AND a.enrollment_id=s.enrollment_id AND a.desired_policy_revision=s.revision
LEFT JOIN policies p ON (p.agent_id,p.enrollment_id,p.revision)=(s.agent_id,s.enrollment_id,s.revision) WHERE (?='' OR a.site_id=?) ORDER BY a.agent_id LIMIT 1000`, siteID, siteID)
		}
		if err == nil {
			for rows.Next() {
				var id, policyID string
				var body []byte
				var settings ConsoleSettings
				var measured bool
				if err = rows.Scan(&id, &body, &measured, &policyID); err != nil {
					break
				}
				if err = json.Unmarshal(body, &settings); err != nil {
					break
				}
				pending[id] = consolePendingWithMeasurement(settings, measured)
				var assignment consoleAssignment
				if assignment, err = assignedTemplate(policyID, settings, latest); err != nil {
					break
				}
				assignments[id] = assignment
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
		responses, err = consoleDesiredResponses(r.Context(), tx)
		if err != nil {
			_ = tx.Rollback()
			s.consoleError(w, "state response modes", err)
			return
		}
		detections, window, err = consoleRecentDetections(r.Context(), tx, now.Add(-consoleDetectionWindow), consoleDetectionScanLimit)
		if err != nil {
			_ = tx.Rollback()
			s.consoleError(w, "state detections", err)
			return
		}
	}
	type consoleAgent struct {
		Agent
		PendingFeatures []string `json:"pending_features"`
		consoleAssignment
		consoleResponse
		consoleDetection
	}
	consoleAgents := make([]consoleAgent, 0, len(agents))
	for _, agent := range agents {
		features := pending[agent.ID]
		if features == nil {
			features = []string{}
		}
		consoleAgents = append(consoleAgents, consoleAgent{Agent: agent, PendingFeatures: features, consoleAssignment: assignments[agent.ID], consoleResponse: responses[agent.ID], consoleDetection: detections[agent.ID]})
	}
	_ = tx.Rollback()
	respond(w, http.StatusOK, map[string]any{"server_time": now, "site_id": siteID, "rule_ids": managed.BuiltinRuleIDs(), "agents": consoleAgents, "total_agents": totalAgents, "agents_truncated": totalAgents > len(consoleAgents), "detections": window, "groups": groups, "templates": templates, "defaults": defaultConsoleSettings(now), "enrollment": map[string]any{"central_url": s.enrollmentURL, "ready": s.enrollmentURL != ""}})
}

func mayReadConsoleAgents(r *http.Request) bool {
	account, ok := console.AuthenticatedAccount(r.Context())
	return !ok || account.Can(console.PermissionAgentRead, selectedSite(r.Context()))
}

func mayReadConsoleGroups(r *http.Request) bool {
	account, ok := console.AuthenticatedAccount(r.Context())
	id := selectedSite(r.Context())
	return !ok || account.Can(console.PermissionGroupsRead, id) || account.Can(console.PermissionGroupsManage, id) ||
		account.Can(console.PermissionPoliciesDeploy, id) || account.Can(console.PermissionUpdatesDeploy, id) ||
		account.Can(console.PermissionAgentRemove, id)
}

func mayReadConsoleTemplates(r *http.Request) bool {
	account, ok := console.AuthenticatedAccount(r.Context())
	id := selectedSite(r.Context())
	return !ok || account.Can(console.PermissionPoliciesRead, id) || account.Can(console.PermissionPoliciesDeploy, id) || account.Can(console.PermissionPoliciesManage, console.GlobalScope)
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
