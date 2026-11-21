package console

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

func TestRBACRoleChangesApplyToAnExistingSession(t *testing.T) {
	s, calls := testServer(t)
	defer s.Close()
	s.siteExists = func(_ context.Context, site string) (bool, error) { return site == "east", nil }
	admin := testSession(t, s)
	member, memberCookie := accountFixture(t, s, "member", RoleOperator)

	roleBody := map[string]any{
		"id": "decommission", "name": "Site recovery",
		"permissions": []Permission{PermissionAgentRemove, PermissionRolesManage},
	}
	if result := accountRequest(t, s, admin, "POST", "/api/rbac/roles", roleBody, false); result.Code != 403 {
		t.Fatalf("role creation skipped CSRF: %d", result.Code)
	}
	if result := accountRequest(t, s, admin, "POST", "/api/rbac/roles", roleBody, true); result.Code != 201 {
		t.Fatalf("role creation: %d %s", result.Code, result.Body)
	}
	grantURL := "/api/accounts/member/grants"
	grantBody := map[string]any{"version": member.Version, "grants": []RoleGrant{{RoleID: "decommission", SiteID: "unknown"}}}
	if result := accountRequest(t, s, admin, "POST", grantURL, grantBody, true); result.Code != 400 {
		t.Fatalf("unknown site accepted: %d", result.Code)
	}
	grantBody["grants"] = []RoleGrant{{RoleID: "decommission", SiteID: "east"}}
	if result := accountRequest(t, s, admin, "POST", grantURL, grantBody, true); result.Code != 200 {
		t.Fatalf("role grant: %d %s", result.Code, result.Body)
	}
	var role Role
	if err := s.accounts.db.QueryRow("SELECT role FROM accounts WHERE username='member'").Scan(&role); err != nil || role != storedScopedRole || role.valid() {
		t.Fatalf("legacy console would accept the stored scoped credentials: role %q error %v", role, err)
	}
	result := accountRequest(t, s, memberCookie, "GET", "/api/session/permissions", nil, false)
	var session struct {
		Permissions map[Permission][]string `json:"permissions"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &session); err != nil || result.Code != 200 {
		t.Fatalf("session permission reload: %d %v", result.Code, err)
	}
	got := session.Permissions[PermissionAgentRemove]
	if len(got) != 1 || got[0] != "east" || len(session.Permissions) != 1 {
		t.Fatalf("scope escaped or inherited: %#v", session.Permissions)
	}
	s.api = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !HasPermission(r.Context(), PermissionAgentRemove, "east") ||
			HasPermission(r.Context(), PermissionAgentRemove, "west") ||
			HasPermission(r.Context(), PermissionAgentRemove, GlobalScope) ||
			HasAnyPermission(r.Context(), PermissionRolesManage) {
			t.Error("effective authority at the business API differs from the assignment")
		}
		*calls++
	})
	url := "/api/agents/site-agent/remote-removal"
	if result := accountRequest(t, s, memberCookie, "GET", url, nil, false); result.Code != 200 {
		t.Fatalf("assigned action denied: %d", result.Code)
	}
	if result := accountRequest(t, s, memberCookie, "POST", "/api/revoke", nil, true); result.Code != 403 {
		t.Fatalf("legacy operator permission still applied: %d", result.Code)
	}
	if result := accountRequest(t, s, admin, "POST", "/api/accounts/member", map[string]any{"role": "admin", "version": 2}, true); result.Code != 403 {
		t.Fatalf("legacy role endpoint overwrote custom grants: %d", result.Code)
	}
	roleBody["permissions"], roleBody["version"] = []Permission{}, 1
	if result := accountRequest(t, s, admin, "POST", "/api/rbac/roles/decommission", roleBody, true); result.Code != 200 {
		t.Fatalf("role update: %d %s", result.Code, result.Body)
	}
	if result := accountRequest(t, s, memberCookie, "GET", url, nil, false); result.Code != 403 || *calls != 1 {
		t.Fatalf("revoked right survived in old session: %d, calls %d", result.Code, *calls)
	}
}

func TestRBACDelegationAndRecoveryAdmin(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	admin := testSession(t, s)
	delegate, delegateCookie := accountFixture(t, s, "delegate", RoleViewer)
	member, _ := accountFixture(t, s, "member", RoleViewer)
	permissionGroup := map[string]any{"id": "limited", "name": "Accounts and roles", "permissions": []Permission{PermissionAccountsManage, PermissionRolesManage, PermissionAgentRead}}
	if result := accountRequest(t, s, admin, "POST", "/api/rbac/roles", permissionGroup, true); result.Code != 201 {
		t.Fatalf("limited role: %d", result.Code)
	}
	if result := accountRequest(t, s, admin, "POST", "/api/accounts/delegate/grants", map[string]any{"version": delegate.Version, "grants": []RoleGrant{{"limited", GlobalScope}}}, true); result.Code != 200 {
		t.Fatalf("limited delegate: %d %s", result.Code, result.Body)
	}
	for _, attempt := range []struct {
		path string
		body any
	}{
		{"/api/accounts", map[string]any{"username": "extra", "role": "admin", "password": "account-password-fixture1!"}},
		{"/api/rbac/roles", map[string]any{"id": "grant", "name": "Remove", "permissions": []Permission{PermissionAgentRemove}}},
		{"/api/accounts/member/grants", map[string]any{"version": member.Version, "grants": []RoleGrant{{"admin", GlobalScope}}}},
		{"/api/accounts/admin/password", map[string]any{"version": 1, "password": "account-password-fixture1!"}},
	} {
		if result := accountRequest(t, s, delegateCookie, "POST", attempt.path, attempt.body, true); result.Code != 403 {
			t.Fatalf("restricted delegate action %s: %d %s", attempt.path, result.Code, result.Body)
		}
	}
	removeAdmin := map[string]any{"version": 1, "grants": []RoleGrant{}}
	if result := accountRequest(t, s, admin, "POST", "/api/accounts/admin/grants", removeAdmin, true); result.Code != 409 {
		t.Fatalf("removed last unrestricted administrator: %d", result.Code)
	}
	if result := accountRequest(t, s, admin, "DELETE", "/api/rbac/roles/admin?version=1", nil, true); result.Code != 403 {
		t.Fatalf("builtin recovery role altered: %d", result.Code)
	}
	if result := accountRequest(t, s, admin, "DELETE", "/api/rbac/roles/limited?version=1", nil, true); result.Code != 409 {
		t.Fatalf("role with live grants deleted: %d", result.Code)
	}
}

func TestRBACRecoveryAdminRemainsAccessibleAfterDowngrade(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	admin := testSession(t, s)
	standby, standbyCookie := accountFixture(t, s, "standby", RoleViewer)
	body := map[string]any{"version": standby.Version, "grants": []RoleGrant{{"admin", GlobalScope}}}
	if result := accountRequest(t, s, admin, "POST", "/api/accounts/standby/grants", body, true); result.Code != 200 {
		t.Fatalf("assign recovery admin: %d %s", result.Code, result.Body)
	}
	var role Role
	if err := s.accounts.db.QueryRow("SELECT role FROM accounts WHERE username='standby'").Scan(&role); err != nil || role != RoleAdmin {
		t.Fatalf("rollback recovery unavailable: role %q error %v", role, err)
	}
	if result := accountRequest(t, s, standbyCookie, "POST", "/api/accounts/admin/grants", map[string]any{"version": 1, "grants": []RoleGrant{}}, true); result.Code != 200 {
		t.Fatalf("scoping the prior admin with recovery retained: %d %s", result.Code, result.Body)
	}
	if result := accountRequest(t, s, admin, "GET", "/api/accounts", nil, false); result.Code != 403 {
		t.Fatalf("prior admin retained authority in the current binary: %d", result.Code)
	}
}

func TestRBACStateRouteCombinesIndependentSitePermissions(t *testing.T) {
	account := Account{access: map[Permission][]string{
		PermissionGroupsRead:  {"east", "north"},
		PermissionAgentRemove: {"east", "west"},
	}}
	if !slices.Equal(account.StateScopes(), []string{"east", "north", "west"}) ||
		!allowsAccountAPI(account, http.MethodGet, "/api/state") ||
		allowsAccountAPI(account, http.MethodGet, "/api/agents/agent-a/integrity") {
		t.Fatalf("inconsistent composite state permission: %v", account.StateScopes())
	}
	account.access[PermissionPoliciesManage] = []string{GlobalScope}
	if !slices.Equal(account.StateScopes(), []string{GlobalScope}) {
		t.Fatalf("missing global state projection: %v", account.StateScopes())
	}
}
