package console

import (
	"context"
	"slices"
	"strings"
)

type Permission string

const (
	GlobalScope = "*"

	PermissionAgentRead               Permission = "agents.read"
	PermissionAgentEnroll             Permission = "agents.enroll"
	PermissionAgentRevoke             Permission = "agents.revoke"
	PermissionAgentRemovalGrant       Permission = "agents.removal_grant"
	PermissionAgentRemove             Permission = "agents.remove"
	PermissionAgentConfigurationRead  Permission = "agent_configuration.read"
	PermissionAgentConfigurationWrite Permission = "agent_configuration.write"
	PermissionGroupsRead              Permission = "groups.read"
	PermissionGroupsManage            Permission = "groups.manage"
	PermissionPoliciesRead            Permission = "policies.read"
	PermissionPoliciesManage          Permission = "policies.manage"
	PermissionPoliciesDeploy          Permission = "policies.deploy"
	PermissionPoliciesTrial           Permission = "policies.trial"
	PermissionHistoryRead             Permission = "history.read"
	PermissionFindingsReview          Permission = "findings.review"
	PermissionAuditRead               Permission = "audit.read"
	PermissionUpdatesRead             Permission = "updates.read"
	PermissionUpdatesDeploy           Permission = "updates.deploy"
	PermissionUpdatesReleases         Permission = "updates.releases"
	PermissionCentralUpdate           Permission = "central.update"
	PermissionSitesManage             Permission = "sites.manage"
	PermissionSiteAssignAgents        Permission = "sites.assign_agents"
	PermissionAccountsManage          Permission = "accounts.manage"
	PermissionRolesManage             Permission = "roles.manage"
)

type PermissionDefinition struct {
	ID    Permission `json:"id"`
	Label string     `json:"label"`
	Scope string     `json:"scope"`
}

type RoleDefinition struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Version     int64        `json:"version"`
	Builtin     bool         `json:"builtin"`
}

type RoleGrant struct {
	RoleID string `json:"role_id"`
	SiteID string `json:"site_id"`
}

var permissionCatalog = []PermissionDefinition{
	{PermissionAgentRead, "에이전트·서비스 조회", "site"},
	{PermissionAgentEnroll, "에이전트 등록", "site"},
	{PermissionAgentRevoke, "에이전트 인증서 폐기", "site"},
	{PermissionAgentRemovalGrant, "호스트 수동 제거 승인", "site"},
	{PermissionAgentRemove, "에이전트 원격 제거", "site"},
	{PermissionAgentConfigurationRead, "에이전트 운영 설정 조회", "site"},
	{PermissionAgentConfigurationWrite, "에이전트 운영 설정 배포", "site"},
	{PermissionGroupsRead, "서버 그룹 조회", "site"},
	{PermissionGroupsManage, "서버 그룹 관리", "site"},
	{PermissionPoliciesRead, "보안 정책 조회", "site"},
	{PermissionPoliciesManage, "공용 보안 정책 편집", "global"},
	{PermissionPoliciesDeploy, "보안 정책 배포", "site"},
	{PermissionPoliciesTrial, "공용 정책 시험 요청·승격", "global"},
	{PermissionHistoryRead, "탐지·실행·오류 이력 조회", "site"},
	{PermissionFindingsReview, "탐지 판정 기록", "site"},
	{PermissionAuditRead, "감사 이력 조회", "site"},
	{PermissionUpdatesRead, "에이전트 업데이트 조회", "site"},
	{PermissionUpdatesDeploy, "에이전트 업데이트 배포", "site"},
	{PermissionUpdatesReleases, "공용 에이전트 릴리스 관리", "global"},
	{PermissionCentralUpdate, "센트럴 업데이트", "global"},
	{PermissionSitesManage, "사이트 생성·이름 편집", "global"},
	{PermissionSiteAssignAgents, "에이전트 소속 사이트 변경", "global"},
	{PermissionAccountsManage, "계정 관리", "global"},
	{PermissionRolesManage, "권한 역할·할당 관리", "global"},
}

func permissionIndex() map[Permission]PermissionDefinition {
	index := make(map[Permission]PermissionDefinition, len(permissionCatalog))
	for _, permission := range permissionCatalog {
		index[permission.ID] = permission
	}
	return index
}

var knownPermissions = permissionIndex()

func presetRoleDefinitions() []RoleDefinition {
	admin := make([]Permission, 0, len(permissionCatalog))
	for _, entry := range permissionCatalog {
		admin = append(admin, entry.ID)
	}
	viewer := []Permission{PermissionAgentRead, PermissionAgentConfigurationRead, PermissionGroupsRead, PermissionPoliciesRead, PermissionHistoryRead, PermissionAuditRead, PermissionUpdatesRead}
	operator := append(slices.Clone(viewer), PermissionAgentEnroll, PermissionAgentRevoke, PermissionAgentRemovalGrant, PermissionAgentConfigurationWrite, PermissionGroupsManage, PermissionPoliciesManage, PermissionPoliciesDeploy, PermissionPoliciesTrial, PermissionFindingsReview, PermissionUpdatesDeploy)
	return []RoleDefinition{
		{ID: string(RoleAdmin), Name: "관리자", Permissions: admin, Version: 1, Builtin: true},
		{ID: string(RoleOperator), Name: "운영자", Permissions: operator, Version: 1, Builtin: true},
		{ID: string(RoleViewer), Name: "조회자", Permissions: viewer, Version: 1, Builtin: true},
	}
}

var builtinRoleDefinitions = presetRoleDefinitions()

func builtinRoles() []RoleDefinition { return slices.Clone(builtinRoleDefinitions) }

func builtinRole(id string) (RoleDefinition, bool) {
	for _, role := range builtinRoleDefinitions {
		if role.ID == id {
			return role, true
		}
	}
	return RoleDefinition{}, false
}

func (a Account) Scopes(permission Permission) []string {
	if _, ok := knownPermissions[permission]; !ok {
		return nil
	}
	if a.access != nil {
		return slices.Clone(a.access[permission])
	}
	if role, ok := builtinRole(string(a.Role)); ok && slices.Contains(role.Permissions, permission) {
		return []string{GlobalScope}
	}
	return nil
}

func (a Account) Has(permission Permission) bool { return len(a.Scopes(permission)) != 0 }

func (a Account) Can(permission Permission, siteID string) bool {
	if siteID == "" {
		siteID = GlobalScope
	}
	for _, scope := range a.Scopes(permission) {
		if scope == GlobalScope || scope == siteID {
			return true
		}
	}
	return false
}

// SiteIDs enumerates distinct effective site assignments. Any global grant
// advertises the wildcard once so site listing can return the complete catalog.
func (a Account) SiteIDs() []string {
	sites := []string{}
	for _, permission := range permissionCatalog {
		for _, scope := range a.Scopes(permission.ID) {
			if scope == GlobalScope {
				return []string{GlobalScope}
			}
			if !slices.Contains(sites, scope) {
				sites = append(sites, scope)
			}
		}
	}
	slices.Sort(sites)
	return sites
}

// StateScopes enumerates the site scopes in which at least one projection of
// the composite state is useful. Each projection applies its own permission.
func (a Account) StateScopes() []string {
	sites := []string{}
	for _, permission := range [...]Permission{
		PermissionAgentRead, PermissionAgentRemove, PermissionGroupsRead, PermissionGroupsManage,
		PermissionPoliciesRead, PermissionPoliciesManage, PermissionPoliciesDeploy, PermissionUpdatesDeploy,
	} {
		for _, scope := range a.Scopes(permission) {
			if scope == GlobalScope {
				return []string{GlobalScope}
			}
			if !slices.Contains(sites, scope) {
				sites = append(sites, scope)
			}
		}
	}
	slices.Sort(sites)
	return sites
}

func HasPermission(ctx context.Context, permission Permission, siteID string) bool {
	account, ok := AuthenticatedAccount(ctx)
	return ok && account.Can(permission, siteID)
}

func HasAnyPermission(ctx context.Context, permission Permission) bool {
	account, ok := AuthenticatedAccount(ctx)
	return ok && account.Has(permission)
}

func (a Account) permissionScopes() map[Permission][]string {
	result := make(map[Permission][]string)
	for _, entry := range permissionCatalog {
		if scopes := a.Scopes(entry.ID); len(scopes) > 0 {
			result[entry.ID] = scopes
		}
	}
	return result
}

func effectiveScopes(grants []RoleGrant, roles map[string]RoleDefinition) (map[Permission][]string, error) {
	result := map[Permission][]string{}
	for _, grant := range grants {
		role, ok := roles[grant.RoleID]
		if !ok {
			return nil, errInvalidGrant
		}
		for _, permission := range role.Permissions {
			definition, ok := knownPermissions[permission]
			if !ok {
				return nil, errInvalidGrant
			}
			if grant.SiteID != GlobalScope && definition.Scope == "global" {
				continue
			}
			scopes := result[permission]
			if grant.SiteID == GlobalScope {
				result[permission] = []string{GlobalScope}
				continue
			}
			if !slices.Contains(scopes, GlobalScope) && !slices.Contains(scopes, grant.SiteID) {
				result[permission] = append(scopes, grant.SiteID)
			}
		}
	}
	for _, scopes := range result {
		slices.Sort(scopes)
	}
	return result, nil
}

func (a Account) recoveryAdmin() bool {
	return slices.Contains(a.roleGrants(), RoleGrant{RoleID: string(RoleAdmin), SiteID: GlobalScope})
}

func (a Account) roleGrants() []RoleGrant {
	if a.ExplicitGrants || !a.Role.valid() {
		return a.Grants
	}
	return []RoleGrant{{RoleID: string(a.Role), SiteID: GlobalScope}}
}

func canDelegate(actor, target Account) bool {
	if target.recoveryAdmin() && !actor.recoveryAdmin() {
		return false
	}
	for permission, scopes := range target.permissionScopes() {
		for _, site := range scopes {
			if !actor.Can(permission, site) {
				return false
			}
		}
	}
	return true
}

func accountStoredRole(account Account) Role {
	if !account.ExplicitGrants {
		return account.Role
	}
	if account.recoveryAdmin() {
		return RoleAdmin
	}
	return storedScopedRole
}

func accountDisplayRole(account Account) Role {
	if !account.ExplicitGrants {
		return account.Role
	}
	if account.recoveryAdmin() {
		return RoleAdmin
	}
	return RoleViewer
}

func validRBACIdentifier(id string, maximum int) bool {
	if id == "" || len(id) > maximum {
		return false
	}
	if !strings.ContainsAny(id[:1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
		return false
	}
	for _, char := range id {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-", char) {
			return false
		}
	}
	return true
}
