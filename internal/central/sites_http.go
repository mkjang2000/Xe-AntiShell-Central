package central

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
)

const siteHeader = "X-XEAS-Site"

var scopedPermissions = []console.Permission{
	console.PermissionAgentRead, console.PermissionAgentEnroll, console.PermissionAgentRevoke,
	console.PermissionAgentRemovalGrant, console.PermissionAgentRemove,
	console.PermissionAgentConfigurationRead, console.PermissionAgentConfigurationWrite,
	console.PermissionGroupsRead, console.PermissionGroupsManage, console.PermissionPoliciesRead, console.PermissionPoliciesDeploy,
	console.PermissionHistoryRead, console.PermissionFindingsReview, console.PermissionAuditRead,
	console.PermissionUpdatesRead, console.PermissionUpdatesDeploy,
}

func permitsSite(account console.Account, id string) bool {
	for _, permission := range scopedPermissions {
		if account.Can(permission, id) {
			return true
		}
	}
	return false
}

// Scope admission identifies the browser selection. The resource methods use
// this context to constrain their SQL. Moves acquire the exclusive lock, so a
// scoped request never checks one site's ownership and reads another site's row.
func (s *Server) consoleSiteScope(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, authenticated := console.AuthenticatedAccount(r.Context())
		if !authenticated {
			// The production wrapper always authenticates browser requests.
			mux.ServeHTTP(w, r)
			return
		}
		_, pattern := mux.Handler(r)
		if pattern == "" || pattern == "GET /api/sites" || pattern == "POST /api/sites" ||
			pattern == "POST /api/sites/{id}/agents" {
			mux.ServeHTTP(w, r)
			return
		}
		permission, ok := console.RoutePermission(r.Method, r.URL.Path)
		if !ok {
			s.consoleError(w, "site route permission", ErrUnauthorized)
			return
		}
		scopes := account.Scopes(permission)
		if pattern == "GET /api/state" {
			scopes = account.StateScopes()
		}
		canSelect := func(id string) bool {
			return slices.Contains(scopes, console.GlobalScope) || slices.Contains(scopes, id)
		}
		values := r.Header.Values(siteHeader)
		if len(values) > 1 {
			s.consoleError(w, "conflicting site selection", ErrInvalid)
			return
		}
		id := r.Header.Get(siteHeader)
		if id == "" {
			if canSelect(console.GlobalScope) {
				id = console.GlobalScope
			} else if len(scopes) != 0 {
				id = scopes[0]
			}
		}
		if !siteScopedPattern(pattern) {
			// Service-wide configuration/catalogs require the global grant.
			if !account.Can(permission, console.GlobalScope) {
				s.consoleError(w, "global route scope", ErrUnauthorized)
				return
			}
			mux.ServeHTTP(w, r)
			return
		}
		if id == "" || !canSelect(id) {
			s.consoleError(w, "selected site permission", ErrUnauthorized)
			return
		}
		if id == console.GlobalScope {
			mux.ServeHTTP(w, r)
			return
		}
		if !identifierPattern.MatchString(id) {
			s.consoleError(w, "invalid site selection", ErrInvalid)
			return
		}
		exists, err := s.store.SiteExists(r.Context(), id)
		if err != nil || !exists {
			if err == nil {
				err = ErrNotFound
			}
			s.consoleError(w, "selected site", err)
			return
		}
		s.siteMu.RLock()
		defer s.siteMu.RUnlock()
		ctx := context.WithValue(r.Context(), siteContextKey{}, id)
		if path := strings.Split(r.URL.Path, "/"); len(path) > 3 {
			var agentID string
			if path[2] == "agents" {
				agentID = path[3]
			} else if path[2] == "agent-configuration" && r.Method == http.MethodGet {
				agentID = path[3]
			}
			if agentID != "" {
				if err := requireAgentSite(ctx, s.store.db, agentID); err != nil {
					s.consoleError(w, "agent site", err)
					return
				}
			}
		}
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func siteScopedPattern(pattern string) bool {
	switch pattern {
	case "GET /api/state", "GET /api/history", "GET /api/errors", "GET /api/audit",
		"GET /api/finding-reviews", "POST /api/finding-reviews",
		"GET /api/agents/{id}/integrity", "GET /api/agents/{id}/policy", "GET /api/agents/{id}/service-inventory",
		"GET /api/agents/{id}/remote-removal", "POST /api/agents/{id}/remote-removal", "POST /api/agents/{id}/remote-removal/cancel",
		"POST /api/remote-removal/preview", "POST /api/remote-removal/batches", "GET /api/remote-removal/batches/{id}",
		"POST /api/groups", "DELETE /api/groups/{id}", "POST /api/deploy/preview", "POST /api/deploy",
		"GET /api/agent-configuration/{id}", "POST /api/agent-configuration/preview", "POST /api/agent-configuration/apply",
		"POST /api/enrollment", "POST /api/removal", "POST /api/revoke",
		"GET /api/updates/releases", "GET /api/updates/github/releases", "GET /api/updates/agents",
		"GET /api/updates/rollouts", "GET /api/updates/rollouts/{id}", "POST /api/updates/preview",
		"POST /api/updates/rollouts", "POST /api/updates/rollouts/{id}/cancel":
		return true
	}
	return false
}

func (s *Server) consoleSites(w http.ResponseWriter, r *http.Request) {
	account, ok := console.AuthenticatedAccount(r.Context())
	if !ok {
		s.consoleError(w, "sites account", ErrUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		items, err := s.store.listSites(r.Context())
		if err != nil {
			s.consoleError(w, "site list", err)
			return
		}
		global := permitsSite(account, console.GlobalScope) || account.Can(console.PermissionSitesManage, console.GlobalScope) ||
			account.Can(console.PermissionSiteAssignAgents, console.GlobalScope)
		if !global {
			filtered := items[:0]
			for _, item := range items {
				if permitsSite(account, item.ID) {
					filtered = append(filtered, item)
				}
			}
			items = filtered
		}
		respond(w, http.StatusOK, map[string]any{"sites": items, "global": global})
		return
	}
	if !account.Can(console.PermissionSitesManage, console.GlobalScope) {
		s.consoleError(w, "site management", ErrUnauthorized)
		return
	}
	var input site
	if !consoleDecode(w, r, 1024, &input) {
		return
	}
	item, err := s.store.saveSite(r.Context(), input, account.Username, s.now().UTC())
	if err != nil {
		s.consoleError(w, "site save", err)
		return
	}
	respond(w, http.StatusOK, item)
}

func (s *Server) consoleMoveSiteAgent(w http.ResponseWriter, r *http.Request) {
	account, ok := console.AuthenticatedAccount(r.Context())
	if !ok || !account.Can(console.PermissionSiteAssignAgents, console.GlobalScope) {
		s.consoleError(w, "site assignment", ErrUnauthorized)
		return
	}
	var input struct {
		AgentID      string `json:"agent_id"`
		EnrollmentID string `json:"enrollment_id"`
	}
	if !consoleDecode(w, r, 1024, &input) {
		return
	}
	s.siteMu.Lock()
	defer s.siteMu.Unlock()
	if err := s.store.moveAgentSite(r.Context(), input.AgentID, input.EnrollmentID, r.PathValue("id"), account.Username, s.now().UTC()); err != nil {
		s.consoleError(w, "site agent assignment", err)
		return
	}
	respond(w, http.StatusOK, map[string]string{"agent_id": input.AgentID, "site_id": r.PathValue("id")})
}
