package console

import (
	"net/http"
	"strings"
)

type permissionRoute struct {
	method     string
	pattern    []string
	permission Permission
}

func permissionPaths(method string, permission Permission, patterns ...string) []permissionRoute {
	routes := make([]permissionRoute, 0, len(patterns))
	for _, pattern := range patterns {
		routes = append(routes, permissionRoute{method, strings.Split(pattern, "/"), permission})
	}
	return routes
}

func permissionRoutes() []permissionRoute {
	var routes []permissionRoute
	add := func(method string, permission Permission, patterns ...string) {
		routes = append(routes, permissionPaths(method, permission, patterns...)...)
	}
	add(http.MethodGet, PermissionAgentRead, "/api/state", "/api/agents/{id}/integrity", "/api/agents/{id}/service-inventory")
	add(http.MethodPost, PermissionAgentEnroll, "/api/enrollment")
	add(http.MethodPost, PermissionAgentRevoke, "/api/revoke")
	add(http.MethodPost, PermissionAgentRemovalGrant, "/api/removal")
	add(http.MethodGet, PermissionAgentRemove, "/api/agents/{id}/remote-removal", "/api/remote-removal/batches/{id}")
	add(http.MethodPost, PermissionAgentRemove, "/api/agents/{id}/remote-removal", "/api/agents/{id}/remote-removal/cancel", "/api/remote-removal/preview", "/api/remote-removal/batches")
	add(http.MethodGet, PermissionAgentConfigurationRead, "/api/agent-configuration/{id}")
	add(http.MethodPost, PermissionAgentConfigurationWrite, "/api/agent-configuration/preview", "/api/agent-configuration/apply")
	add(http.MethodPost, PermissionGroupsManage, "/api/groups")
	add(http.MethodDelete, PermissionGroupsManage, "/api/groups/{id}")
	add(http.MethodGet, PermissionPoliciesRead, "/api/agents/{id}/policy", "/api/templates/{id}/usage", "/api/policy-trials", "/api/policy-trials/{id}")
	add(http.MethodPost, PermissionPoliciesManage, "/api/templates")
	add(http.MethodDelete, PermissionPoliciesManage, "/api/templates/{id}")
	add(http.MethodPost, PermissionPoliciesDeploy, "/api/deploy/preview", "/api/deploy")
	add(http.MethodPost, PermissionPoliciesTrial, "/api/policy-trials", "/api/policy-trials/{id}/report", "/api/policy-trials/{id}/preview", "/api/policy-trials/{id}/apply")
	add(http.MethodGet, PermissionHistoryRead, "/api/history", "/api/errors", "/api/finding-reviews")
	add(http.MethodPost, PermissionFindingsReview, "/api/finding-reviews")
	add(http.MethodGet, PermissionAuditRead, "/api/audit")
	add(http.MethodGet, PermissionUpdatesRead, "/api/updates/releases", "/api/updates/agents", "/api/updates/rollouts", "/api/updates/rollouts/{id}", "/api/updates/github/releases")
	add(http.MethodPost, PermissionUpdatesDeploy, "/api/updates/preview", "/api/updates/rollouts", "/api/updates/rollouts/{id}/cancel")
	add(http.MethodPost, PermissionUpdatesReleases, "/api/updates/releases", "/api/updates/releases/{id}/delete", "/api/updates/github/import")
	add(http.MethodGet, PermissionCentralUpdate, "/api/central-update/status", "/api/central-update/releases")
	add(http.MethodPost, PermissionCentralUpdate, "/api/central-update/github", "/api/central-update/upload")
	add(http.MethodPost, PermissionSitesManage, "/api/sites")
	add(http.MethodPost, PermissionSiteAssignAgents, "/api/sites/{id}/agents")
	return routes
}

var routesByPermission = permissionRoutes()

// RoutePermission returns the required capability for known business endpoints.
// Scope enforcement uses the site's authoritative resource ownership afterwards.
func RoutePermission(method, path string) (Permission, bool) {
	parts := strings.Split(path, "/")
	for _, route := range routesByPermission {
		if route.method != method || len(route.pattern) != len(parts) {
			continue
		}
		if route.matches(parts) {
			return route.permission, true
		}
	}
	return "", false
}

func (r permissionRoute) matches(parts []string) bool {
	for index, part := range r.pattern {
		if part == "{id}" {
			if !validRBACIdentifier(parts[index], 160) {
				return false
			}
		} else if part != parts[index] {
			return false
		}
	}
	return true
}
