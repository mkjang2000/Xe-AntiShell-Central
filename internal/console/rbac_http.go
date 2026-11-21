package console

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
)

func (s *server) serveRBAC(w http.ResponseWriter, r *http.Request, actor Account) {
	endpoint := r.URL.Path
	if endpoint == "/api/rbac" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		if !actor.Can(PermissionRolesManage, GlobalScope) && !actor.Can(PermissionAccountsManage, GlobalScope) {
			denyAccountAccess(w)
			return
		}
		tx, err := s.accounts.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
		if err != nil {
			s.accountError(w, err)
			return
		}
		defer tx.Rollback()
		roles, err := listRoles(r.Context(), tx)
		if err != nil {
			s.accountError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Permissions []PermissionDefinition `json:"permissions"`
			Roles       []RoleDefinition       `json:"roles"`
		}{permissionCatalog, roles})
		return
	}
	if !actor.Can(PermissionRolesManage, GlobalScope) {
		denyAccountAccess(w)
		return
	}
	if endpoint == "/api/rbac/roles" || strings.HasPrefix(endpoint, "/api/rbac/roles/") {
		s.serveRoleMutation(w, r, actor)
		return
	}
	username, ok := accountGrantTarget(endpoint)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var request struct {
		Version int64       `json:"version"`
		Grants  []RoleGrant `json:"grants"`
	}
	if !decodeAccountRequest(w, r, &request) {
		return
	}
	if err := s.validateRequestedSites(r, request.Grants); err != nil {
		s.accountError(w, err)
		return
	}
	account, err := s.accounts.changeGrants(r.Context(), actor, username, request.Version, request.Grants, s.now())
	if err != nil {
		s.accountError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, account)
}

func accountGrantTarget(endpoint string) (string, bool) {
	suffix, found := strings.CutPrefix(endpoint, "/api/accounts/")
	if !found {
		return "", false
	}
	username, suffix, found := strings.Cut(suffix, "/")
	return username, found && suffix == "grants" && validateUsername(username) == nil
}

func (s *server) validateRequestedSites(r *http.Request, grants []RoleGrant) error {
	if err := validateGrantList(grants); err != nil {
		return err
	}
	checked := map[string]bool{GlobalScope: true}
	for _, grant := range grants {
		if checked[grant.SiteID] {
			continue
		}
		if s.siteExists == nil {
			return errInvalidGrant
		}
		exists, err := s.siteExists(r.Context(), grant.SiteID)
		if err != nil {
			return err
		}
		if !exists {
			return errInvalidGrant
		}
		checked[grant.SiteID] = true
	}
	return nil
}

func (s *server) serveRoleMutation(w http.ResponseWriter, r *http.Request, actor Account) {
	const base = "/api/rbac/roles"
	id := strings.TrimPrefix(r.URL.Path, base+"/")
	creating := r.URL.Path == base
	if !creating && !validRBACIdentifier(id, 64) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var role struct {
			ID          string       `json:"id"`
			Name        string       `json:"name"`
			Permissions []Permission `json:"permissions"`
			Version     int64        `json:"version"`
		}
		if !decodeAccountRequest(w, r, &role) {
			return
		}
		operation, status := "updated", http.StatusOK
		if creating {
			id, operation, status = role.ID, "created", http.StatusCreated
			if role.Version != 0 {
				s.accountError(w, errAccountInvalid)
				return
			}
		} else if role.ID != "" && role.ID != id || role.Version < 1 {
			s.accountError(w, errAccountInvalid)
			return
		}
		saved, err := s.accounts.mutateRole(r.Context(), actor, RoleDefinition{ID: id, Name: role.Name, Permissions: role.Permissions, Version: role.Version}, operation, s.now())
		if err != nil {
			s.accountError(w, err)
			return
		}
		writeJSON(w, status, saved)
	case http.MethodDelete:
		if creating {
			methodNotAllowed(w, "POST")
			return
		}
		version, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
		if err != nil || version < 1 {
			s.accountError(w, errAccountInvalid)
			return
		}
		if _, err := s.accounts.mutateRole(r.Context(), actor, RoleDefinition{ID: id, Version: version}, "deleted", s.now()); err != nil {
			s.accountError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, "POST, DELETE")
	}
}
