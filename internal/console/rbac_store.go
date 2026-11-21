package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

const rbacSchema = `
CREATE TABLE IF NOT EXISTS rbac_roles(id TEXT PRIMARY KEY,name TEXT NOT NULL,permissions BLOB NOT NULL,version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rbac_role_versions(id TEXT PRIMARY KEY,last_version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rbac_explicit_accounts(username TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS rbac_grants(username TEXT NOT NULL,role_id TEXT NOT NULL,site_id TEXT NOT NULL,PRIMARY KEY(username,role_id,site_id));
CREATE INDEX IF NOT EXISTS rbac_grants_role ON rbac_grants(role_id);
`

var (
	errInvalidGrant     = fmt.Errorf("%w: invalid role grant", errAccountInvalid)
	errRBACForbidden    = errors.New("role permissions exceed the account's delegation scope")
	errRBACRoleAssigned = errors.New("role is still assigned")
)

func listRoles(ctx context.Context, tx *sql.Tx) ([]RoleDefinition, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id,name,permissions,version FROM rbac_roles ORDER BY name,id LIMIT 128")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := builtinRoles()
	for rows.Next() {
		role, err := scanCustomRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func readRole(ctx context.Context, tx *sql.Tx, id string) (RoleDefinition, error) {
	if role, ok := builtinRole(id); ok {
		return role, nil
	}
	role, err := scanCustomRole(tx.QueryRowContext(ctx, "SELECT id,name,permissions,version FROM rbac_roles WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return role, errAccountMissing
	}
	return role, err
}

func scanCustomRole(row interface{ Scan(...any) error }) (RoleDefinition, error) {
	var role RoleDefinition
	var raw []byte
	err := row.Scan(&role.ID, &role.Name, &raw, &role.Version)
	if err != nil {
		return role, err
	}
	if err = json.Unmarshal(raw, &role.Permissions); err != nil {
		return role, err
	}
	return role, nil
}

func readRoleGrants(ctx context.Context, tx *sql.Tx, account *Account) error {
	err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM rbac_explicit_accounts WHERE username=?)", account.Username).Scan(&account.ExplicitGrants)
	if err != nil {
		return err
	}
	if !account.ExplicitGrants {
		account.Grants = account.roleGrants()
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT role_id,site_id FROM rbac_grants WHERE username=? ORDER BY role_id,site_id", account.Username)
	if err != nil {
		return err
	}
	defer rows.Close()
	account.Grants = []RoleGrant{}
	for rows.Next() {
		var grant RoleGrant
		if err := rows.Scan(&grant.RoleID, &grant.SiteID); err != nil {
			return err
		}
		account.Grants = append(account.Grants, grant)
	}
	return rows.Err()
}

func readAccess(ctx context.Context, tx *sql.Tx, account *Account) error {
	if err := readRoleGrants(ctx, tx, account); err != nil {
		return err
	}
	if !account.ExplicitGrants {
		return nil
	}
	access, err := accessForGrants(ctx, tx, account.Grants)
	if err != nil {
		return err
	}
	account.access = access
	return nil
}

func accessForGrants(ctx context.Context, tx *sql.Tx, grants []RoleGrant) (map[Permission][]string, error) {
	roles := make(map[string]RoleDefinition, len(grants))
	for _, grant := range grants {
		if _, ok := roles[grant.RoleID]; ok {
			continue
		}
		role, err := readRole(ctx, tx, grant.RoleID)
		if errors.Is(err, errAccountMissing) {
			return nil, errInvalidGrant
		}
		if err != nil {
			return nil, err
		}
		roles[grant.RoleID] = role
	}
	return effectiveScopes(grants, roles)
}

func setRoleGrants(ctx context.Context, tx *sql.Tx, username string, grants []RoleGrant) error {
	if slices.Contains(grants, RoleGrant{RoleID: string(RoleAdmin), SiteID: GlobalScope}) {
		return clearRoleGrants(ctx, tx, username)
	}
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO rbac_explicit_accounts VALUES(?)", username); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM rbac_grants WHERE username=?", username); err != nil {
		return err
	}
	for _, grant := range grants {
		if _, err := tx.ExecContext(ctx, "INSERT INTO rbac_grants VALUES(?,?,?)", username, grant.RoleID, grant.SiteID); err != nil {
			return err
		}
	}
	return nil
}

func clearRoleGrants(ctx context.Context, tx *sql.Tx, username string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM rbac_grants WHERE username=?", username); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM rbac_explicit_accounts WHERE username=?", username)
	return err
}

// Store scoped accounts under a role value older consoles refuse to authenticate.
// A full recovery administrator remains a legacy admin without a supplemental
// grant, so legitimate legacy role changes cannot revive earlier authority.
func normalizeStoredRoles(tx *sql.Tx) error {
	_, err := tx.Exec(`UPDATE accounts AS a SET role=CASE
 WHEN EXISTS(SELECT 1 FROM rbac_grants g WHERE g.username=a.username AND g.role_id='admin' AND g.site_id='*') THEN 'admin'
 ELSE 'rbac' END WHERE a.username IN (SELECT username FROM rbac_explicit_accounts);
DELETE FROM rbac_grants WHERE username IN (SELECT username FROM accounts WHERE role='admin');
DELETE FROM rbac_explicit_accounts WHERE username IN (SELECT username FROM accounts WHERE role='admin');`)
	return err
}

func assertRecoveryAdmin(ctx context.Context, tx *sql.Tx) error {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM accounts a WHERE
 (a.role='admin' AND NOT EXISTS(SELECT 1 FROM rbac_explicit_accounts x WHERE x.username=a.username))
 OR EXISTS(SELECT 1 FROM rbac_explicit_accounts x JOIN rbac_grants g ON g.username=x.username
   WHERE x.username=a.username AND g.role_id='admin' AND g.site_id='*')`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errLastAdmin
	}
	return nil
}

func currentAuthorizer(ctx context.Context, tx *sql.Tx, authenticated Account, permission Permission) (Account, error) {
	record, err := readAccount(ctx, tx, authenticated.Username)
	if err != nil {
		return Account{}, err
	}
	if record.Version != authenticated.Version || !record.Can(permission, GlobalScope) {
		return Account{}, errRBACForbidden
	}
	return record.Account, nil
}

func validateGrantList(grants []RoleGrant) error {
	if grants == nil || len(grants) > 64 {
		return errInvalidGrant
	}
	seen := make(map[RoleGrant]struct{}, len(grants))
	for _, grant := range grants {
		if !validRBACIdentifier(grant.RoleID, 64) || grant.SiteID != GlobalScope && !validRBACIdentifier(grant.SiteID, 128) {
			return errInvalidGrant
		}
		if _, duplicate := seen[grant]; duplicate {
			return errInvalidGrant
		}
		seen[grant] = struct{}{}
	}
	return nil
}

func accountWithGrants(ctx context.Context, tx *sql.Tx, account Account, grants []RoleGrant) (Account, error) {
	if err := validateGrantList(grants); err != nil {
		return Account{}, err
	}
	access, err := accessForGrants(ctx, tx, grants)
	if err != nil {
		return Account{}, err
	}
	account.ExplicitGrants, account.Grants, account.access = true, slices.Clone(grants), access
	return account, nil
}
