package console

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Role string

const (
	RoleAdmin        Role = "admin"
	RoleOperator     Role = "operator"
	RoleViewer       Role = "viewer"
	storedScopedRole Role = "rbac"
)

func (role Role) valid() bool { return role == RoleAdmin || role == RoleOperator || role == RoleViewer }

var (
	// ErrAccountNotFound lets a queued workflow distinguish a deleted actor from a transient failure.
	ErrAccountNotFound = errors.New("account not found")
	errAccountMissing  = ErrAccountNotFound
	errAccountConflict = errors.New("account changed or already exists")
	errLastAdmin       = errors.New("last administrator must remain")
	errAccountInvalid  = errors.New("invalid account input")
)

type Account struct {
	Username       string      `json:"username"`
	Role           Role        `json:"role"`
	Version        int64       `json:"version"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	Grants         []RoleGrant `json:"grants"`
	ExplicitGrants bool        `json:"explicit_grants"`
	access         map[Permission][]string
}

type accountRecord struct {
	Account
	credentials Credentials
}

type accountStore struct {
	db *sql.DB
	mu sync.Mutex
}

func openAccountStore(filename string, seed Credentials) (*accountStore, error) {
	dsn := ":memory:"
	if filename != "" {
		if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
			return nil, errors.New("account database path must be a clean absolute path")
		}
		info, err := os.Lstat(filename)
		if errors.Is(err, os.ErrNotExist) {
			file, createErr := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if createErr != nil {
				return nil, createErr
			}
			if err = file.Close(); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("account database must be a private regular file")
		}
		u := &url.URL{Scheme: "file", Path: filename}
		query := u.Query()
		for _, pragma := range []string{"journal_mode(WAL)", "synchronous(FULL)", "busy_timeout(5000)"} {
			query.Add("_pragma", pragma)
		}
		u.RawQuery = query.Encode()
		dsn = u.String()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &accountStore{db: db}
	if err := store.initialize(seed); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *accountStore) initialize(seed Credentials) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS account_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accounts(username TEXT PRIMARY KEY,role TEXT NOT NULL,version INTEGER NOT NULL,created_ns INTEGER NOT NULL,updated_ns INTEGER NOT NULL,credentials BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS account_versions(username TEXT PRIMARY KEY,last_version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS account_audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,target TEXT NOT NULL,operation TEXT NOT NULL,role TEXT NOT NULL,created_ns INTEGER NOT NULL);` + rbacSchema)
	if err != nil {
		return err
	}
	var initialized int
	if err = tx.QueryRow("SELECT count(*) FROM account_metadata WHERE key='initialized'").Scan(&initialized); err != nil {
		return err
	}
	if initialized == 0 {
		encoded, err := json.Marshal(seed)
		if err != nil {
			return err
		}
		now := time.Now().UTC().UnixNano()
		if _, err = tx.Exec("INSERT INTO accounts VALUES(?,?,1,?,?,?)", seed.Username, RoleAdmin, now, now, encoded); err != nil {
			return err
		}
		if _, err = tx.Exec("INSERT INTO account_metadata VALUES('initialized','1')"); err != nil {
			return err
		}
	}
	if err := normalizeStoredRoles(tx); err != nil {
		return err
	}
	if err := assertRecoveryAdmin(context.Background(), tx); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO account_versions SELECT username,version FROM accounts WHERE 1 ON CONFLICT(username) DO UPDATE SET last_version=MAX(last_version,excluded.last_version)"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *accountStore) get(ctx context.Context, username string) (accountRecord, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return accountRecord{}, err
	}
	defer tx.Rollback()
	return readAccount(ctx, tx, username)
}

func (s *accountStore) loadAuthorization(ctx context.Context, username string) (Account, error) {
	record, err := s.get(ctx, username)
	return record.Account, err
}

func readAccount(ctx context.Context, tx *sql.Tx, username string) (accountRecord, error) {
	var record accountRecord
	var created, updated int64
	var encoded []byte
	err := tx.QueryRowContext(ctx, "SELECT username,role,version,created_ns,updated_ns,credentials FROM accounts WHERE username=?", username).
		Scan(&record.Username, &record.Role, &record.Version, &created, &updated, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return record, errAccountMissing
	}
	if err != nil {
		return record, err
	}
	if err = json.Unmarshal(encoded, &record.credentials); err != nil {
		return record, err
	}
	if (!record.Role.valid() && record.Role != storedScopedRole) || record.Version < 1 || record.credentials.Username != record.Username || record.credentials.Validate() != nil {
		return record, errAccountInvalid
	}
	record.CreatedAt, record.UpdatedAt = time.Unix(0, created).UTC(), time.Unix(0, updated).UTC()
	if err := readAccess(ctx, tx, &record.Account); err != nil {
		return accountRecord{}, err
	}
	if record.Role == storedScopedRole && !record.ExplicitGrants {
		return accountRecord{}, errAccountInvalid
	}
	record.Role = accountDisplayRole(record.Account)
	return record, nil
}

func (s *accountStore) list(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.username,a.role,a.version,a.created_ns,a.updated_ns,
 EXISTS(SELECT 1 FROM rbac_explicit_accounts x WHERE x.username=a.username),
 (SELECT json_group_array(json_object('role_id',role_id,'site_id',site_id))
   FROM (SELECT role_id,site_id FROM rbac_grants WHERE username=a.username ORDER BY role_id,site_id))
 FROM accounts a ORDER BY a.username LIMIT 256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := []Account{}
	for rows.Next() {
		var account Account
		var created, updated int64
		var grants []byte
		if err := rows.Scan(&account.Username, &account.Role, &account.Version, &created, &updated, &account.ExplicitGrants, &grants); err != nil {
			return nil, err
		}
		account.CreatedAt, account.UpdatedAt = time.Unix(0, created).UTC(), time.Unix(0, updated).UTC()
		if account.ExplicitGrants {
			if err := json.Unmarshal(grants, &account.Grants); err != nil {
				return nil, err
			}
			account.Role = accountDisplayRole(account)
		} else {
			account.Grants = account.roleGrants()
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

// mutate serializes changes and protects the final administrator in the same
// transaction as the credential/role update and its secret-free audit record.
func (s *accountStore) mutate(ctx context.Context, actor, operation string, next accountRecord, expected int64, now time.Time) (Account, error) {
	return s.mutateAccount(ctx, actor, operation, next, expected, now, nil)
}

func (s *accountStore) mutateAuthorized(ctx context.Context, actor Account, operation string, next accountRecord, expected int64, now time.Time) (Account, error) {
	return s.mutateAccount(ctx, actor.Username, operation, next, expected, now, &actor)
}

func (s *accountStore) mutateAccount(ctx context.Context, actor, operation string, next accountRecord, expected int64, now time.Time, authorization *Account) (Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, err
	}
	defer tx.Rollback()
	if authorization != nil {
		if err := authorizeAccountMutation(ctx, tx, *authorization, next.Account, operation); err != nil {
			return Account{}, err
		}
	}
	var version int64
	err = tx.QueryRowContext(ctx, "SELECT version FROM accounts WHERE username=?", next.Username).Scan(&version)
	if operation == "created" {
		if err == nil {
			return Account{}, errAccountConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Account{}, err
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM accounts").Scan(&count); err != nil {
			return Account{}, err
		}
		if count >= 256 {
			return Account{}, errAccountConflict
		}
		err = tx.QueryRowContext(ctx, "SELECT last_version FROM account_versions WHERE username=?", next.Username).Scan(&version)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Account{}, err
		}
	} else {
		if errors.Is(err, sql.ErrNoRows) {
			return Account{}, errAccountMissing
		}
		if err != nil {
			return Account{}, err
		}
		if expected < 1 || version != expected {
			return Account{}, errAccountConflict
		}
	}
	if operation == "deleted" {
		if err = clearRoleGrants(ctx, tx, next.Username); err != nil {
			return Account{}, err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM accounts WHERE username=?", next.Username)
	} else {
		if !next.Role.valid() || next.credentials.Validate() != nil || next.credentials.Username != next.Username {
			return Account{}, errAccountInvalid
		}
		encoded, encodeErr := json.Marshal(next.credentials)
		if encodeErr != nil {
			return Account{}, encodeErr
		}
		if operation == "created" {
			_, err = tx.ExecContext(ctx, "INSERT INTO accounts VALUES(?,?,?,?,?,?)", next.Username, accountStoredRole(next.Account), version+1, now.UnixNano(), now.UnixNano(), encoded)
			if err == nil && next.ExplicitGrants {
				err = setRoleGrants(ctx, tx, next.Username, next.Grants)
			}
		} else {
			_, err = tx.ExecContext(ctx, "UPDATE accounts SET role=?,version=version+1,updated_ns=?,credentials=? WHERE username=?", accountStoredRole(next.Account), now.UnixNano(), encoded, next.Username)
		}
	}
	if err != nil {
		return Account{}, err
	}
	if err := assertRecoveryAdmin(ctx, tx); err != nil {
		return Account{}, err
	}
	if err := writeAccountMutation(ctx, tx, actor, next.Username, operation, string(next.Role), version+1, now); err != nil {
		return Account{}, err
	}
	if err = tx.Commit(); err != nil {
		return Account{}, err
	}
	if operation == "deleted" {
		return Account{Username: next.Username}, nil
	}
	record, err := s.get(ctx, next.Username)
	return record.Account, err
}

func writeAccountMutation(ctx context.Context, tx *sql.Tx, actor, username, operation, description string, version int64, now time.Time) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO account_versions VALUES(?,?) ON CONFLICT(username) DO UPDATE SET last_version=excluded.last_version", username, version); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO account_audit(actor,target,operation,role,created_ns) VALUES(?,?,?,?,?)", actor, username, operation, description, now.UnixNano())
	return err
}

func authorizeAccountMutation(ctx context.Context, tx *sql.Tx, authenticated Account, target Account, operation string) error {
	permission := PermissionAccountsManage
	if operation == "password_changed" && authenticated.Username == target.Username {
		account, err := readAccount(ctx, tx, authenticated.Username)
		if err != nil {
			return err
		}
		if account.Version != authenticated.Version {
			return errAccountConflict
		}
		return nil
	}
	actor, err := currentAuthorizer(ctx, tx, authenticated, permission)
	if err != nil {
		return err
	}
	if operation == "created" {
		if target.ExplicitGrants {
			if !actor.Can(PermissionRolesManage, GlobalScope) {
				return errRBACForbidden
			}
			target, err = accountWithGrants(ctx, tx, target, target.Grants)
			if err != nil {
				return err
			}
		}
		if !canDelegate(actor, target) {
			return errRBACForbidden
		}
		return nil
	}
	current, err := readAccount(ctx, tx, target.Username)
	if err != nil {
		return err
	}
	if !canDelegate(actor, current.Account) {
		return errRBACForbidden
	}
	if operation == "role_changed" {
		if current.ExplicitGrants || !actor.Can(PermissionRolesManage, GlobalScope) {
			return errRBACForbidden
		}
		if !canDelegate(actor, target) {
			return errRBACForbidden
		}
	}
	return nil
}
