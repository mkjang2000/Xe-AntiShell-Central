package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (s *accountStore) changeGrants(ctx context.Context, actor Account, username string, expected int64, grants []RoleGrant, now time.Time) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	actor, err = currentAuthorizer(ctx, tx, actor, PermissionRolesManage)
	if err != nil {
		return Account{}, err
	}
	target, err := readAccount(ctx, tx, username)
	if err != nil {
		return Account{}, err
	}
	if expected != target.Version {
		return Account{}, errAccountConflict
	}
	replacement, err := accountWithGrants(ctx, tx, target.Account, grants)
	if err != nil {
		return Account{}, err
	}
	if !canDelegate(actor, target.Account) || !canDelegate(actor, replacement) {
		return Account{}, errRBACForbidden
	}
	if err := setRoleGrants(ctx, tx, username, grants); err != nil {
		return Account{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE accounts SET role=?,version=version+1,updated_ns=? WHERE username=?", accountStoredRole(replacement), now.UnixNano(), username); err != nil {
		return Account{}, err
	}
	if err := assertRecoveryAdmin(ctx, tx); err != nil {
		return Account{}, err
	}
	summary := make([]string, 0, len(grants))
	for _, grant := range grants {
		summary = append(summary, grant.RoleID+"@"+grant.SiteID)
	}
	if err := writeAccountMutation(ctx, tx, actor.Username, username, "grants_changed", strings.Join(summary, ","), expected+1, now); err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, err
	}
	record, err := s.get(ctx, username)
	return record.Account, err
}

func validateRole(role RoleDefinition) bool {
	if !validRBACIdentifier(role.ID, 64) || strings.TrimSpace(role.Name) == "" || len(role.Name) > 144 || role.Permissions == nil || len(role.Permissions) > len(permissionCatalog) {
		return false
	}
	seen := make(map[Permission]bool, len(role.Permissions))
	for _, permission := range role.Permissions {
		if _, ok := knownPermissions[permission]; !ok || seen[permission] {
			return false
		}
		seen[permission] = true
	}
	return true
}

func canEditRole(actor Account, role RoleDefinition) bool {
	for _, permission := range role.Permissions {
		if !actor.Can(permission, GlobalScope) {
			return false
		}
	}
	return true
}

func (s *accountStore) mutateRole(ctx context.Context, actor Account, role RoleDefinition, operation string, now time.Time) (RoleDefinition, error) {
	if !validRBACIdentifier(role.ID, 64) || operation != "deleted" && !validateRole(role) {
		return RoleDefinition{}, errAccountInvalid
	}
	if _, builtin := builtinRole(role.ID); builtin {
		return RoleDefinition{}, errRBACForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RoleDefinition{}, err
	}
	defer tx.Rollback()
	actor, err = currentAuthorizer(ctx, tx, actor, PermissionRolesManage)
	if err != nil {
		return RoleDefinition{}, err
	}
	if !canEditRole(actor, role) {
		return RoleDefinition{}, errRBACForbidden
	}
	if err := writeRole(ctx, tx, actor, &role, operation); err != nil {
		return RoleDefinition{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO account_audit(actor,target,operation,role,created_ns) VALUES(?,?,?,?,?)", actor.Username, "role:"+role.ID, "rbac_role_"+operation, role.ID, now.UnixNano()); err != nil {
		return RoleDefinition{}, err
	}
	return role, tx.Commit()
}

func writeRole(ctx context.Context, tx *sql.Tx, actor Account, role *RoleDefinition, operation string) error {
	previous, err := readRole(ctx, tx, role.ID)
	if operation == "created" {
		if err == nil {
			return errAccountConflict
		}
		if !errors.Is(err, errAccountMissing) {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM rbac_roles").Scan(&count); err != nil {
			return err
		}
		if count >= 128 {
			return errAccountConflict
		}
		if err := tx.QueryRowContext(ctx, "SELECT last_version FROM rbac_role_versions WHERE id=?", role.ID).Scan(&previous.Version); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	} else {
		if err != nil {
			return err
		}
		if previous.Version != role.Version {
			return errAccountConflict
		}
		if !canEditRole(actor, previous) {
			return errRBACForbidden
		}
	}
	if operation == "deleted" {
		var assigned bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM rbac_grants WHERE role_id=?)", role.ID).Scan(&assigned); err != nil {
			return err
		}
		if assigned {
			return errRBACRoleAssigned
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM rbac_roles WHERE id=?", role.ID)
		return err
	}
	role.Name = strings.TrimSpace(role.Name)
	raw, err := json.Marshal(role.Permissions)
	if err != nil {
		return err
	}
	role.Version = previous.Version + 1
	if _, err = tx.ExecContext(ctx, `INSERT INTO rbac_roles VALUES(?,?,?,?)
 ON CONFLICT(id) DO UPDATE SET name=excluded.name,permissions=excluded.permissions,version=excluded.version`, role.ID, role.Name, raw, role.Version); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO rbac_role_versions VALUES(?,?) ON CONFLICT(id) DO UPDATE SET last_version=excluded.last_version", role.ID, role.Version)
	return err
}
