package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrUnauthorized   = errors.New("central authorization rejected")
	ErrInvalid        = errors.New("central invalid input")
	ErrConflict       = errors.New("central immutable record conflict")
	ErrNotFound       = errors.New("central record not found")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type Store struct {
	db        *sql.DB
	historyDB *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("central database path must be absolute")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("central database must be a regular file")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		_ = file.Close()
	} else {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: path}
	q := u.Query()
	for _, pragma := range []string{"journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)", "busy_timeout(5000)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		_ = db.Close()
		return nil, err
	}
	if version > 4 {
		_ = db.Close()
		return nil, errors.New("central database schema is newer than this binary")
	}
	if err = store.initializeSchema(ctx, version); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = store.openHistoryReader(ctx, path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) initializeSchema(ctx context.Context, version int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, schema); err != nil {
		return err
	}
	// Initial development builds did not retain enrollment acknowledgements.
	// Upgrade those version-0 databases without discarding enrolled identities.
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(enrollment_tokens)")
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var index, required, primary int
		var name, kind string
		var defaultValue any
		if err = rows.Scan(&index, &name, &kind, &required, &defaultValue, &primary); err != nil {
			_ = rows.Close()
			return err
		}
		columns[name] = true
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	for _, name := range []string{"csr_hash", "enrollment_id", "certificate_pem"} {
		if !columns[name] {
			if _, err = tx.ExecContext(ctx, "ALTER TABLE enrollment_tokens ADD COLUMN "+name+" TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, consoleSchema+reviewSchema+historySchema); err != nil {
		return err
	}
	if err = initializeSites(ctx, tx); err != nil {
		return err
	}
	if err = initializeErrorHistory(ctx, tx); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, historyReadSchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, trialSchema+trialTicketSchema); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, updateSchema+fileIntegritySchema+agentConfigurationSchema+remoteRemovalSchema); err != nil {
		return err
	}
	if err = initializeSiteRolloutScope(ctx, tx); err != nil {
		return err
	}
	var updateVersion int
	if err = tx.QueryRowContext(ctx, "SELECT version FROM feature_schema WHERE name='agent_updates'").Scan(&updateVersion); err != nil {
		return err
	}
	if updateVersion != 1 {
		return errors.New("central update schema is newer than this binary")
	}
	if version < 3 {
		if _, err = tx.ExecContext(ctx, historyRetentionSchema); err != nil {
			return err
		}
	}
	if version < 4 {
		if _, err = tx.ExecContext(ctx, deliveryReceiptSchema); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version=4"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	var readerErr error
	if s.historyDB != nil {
		readerErr = s.historyDB.Close()
	}
	_, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return errors.Join(readerErr, err, s.db.Close())
}

type Agent struct {
	ID                    string          `json:"agent_id"`
	EnrollmentID          string          `json:"enrollment_id"`
	SiteID                string          `json:"site_id"`
	Hostname              string          `json:"hostname"`
	EnrolledAt            time.Time       `json:"enrolled_at"`
	LastSeenAt            *time.Time      `json:"last_seen_at,omitempty"`
	Revoked               bool            `json:"revoked"`
	Heartbeat             json.RawMessage `json:"heartbeat,omitempty"`
	DesiredPolicyRevision uint64          `json:"desired_policy_revision"`
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, agentID string, lifetime time.Duration, outputPath string) error {
	if !identifierPattern.MatchString(agentID) || lifetime <= 0 || lifetime > 24*time.Hour {
		return errors.New("invalid enrollment agent or lifetime")
	}
	if !filepath.IsAbs(outputPath) {
		return errors.New("token output must be absolute")
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(token))
	if err = writePrivateExclusive(outputPath, []byte(token+"\n")); err != nil {
		return err
	}
	if _, err = s.db.ExecContext(ctx, "INSERT INTO enrollment_tokens(token_hash,agent_id,expires_at_ns,site_id) VALUES(?,?,?,COALESCE((SELECT site_id FROM agents WHERE agent_id=?),'default'))", hex.EncodeToString(hash[:]), agentID, time.Now().UTC().Add(lifetime).UnixNano(), agentID); err != nil {
		_ = os.Remove(outputPath)
		return err
	}
	return nil
}

func (s *Store) Enroll(ctx context.Context, token, agentID, csr string, material *Material, now time.Time) (enrollmentID, certificate string, err error) {
	if len(token) < 32 || len(token) > 256 || !identifierPattern.MatchString(agentID) || len(csr) > 16<<10 {
		return "", "", ErrUnauthorized
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	hash := sha256.Sum256([]byte(token))
	var tokenAgent, tokenSite string
	var expiry int64
	var used int
	var oldCSRHash, oldEnrollment, oldCertificate string
	err = tx.QueryRowContext(ctx, "SELECT agent_id,site_id,expires_at_ns,used,csr_hash,enrollment_id,certificate_pem FROM enrollment_tokens WHERE token_hash=?", hex.EncodeToString(hash[:])).Scan(&tokenAgent, &tokenSite, &expiry, &used, &oldCSRHash, &oldEnrollment, &oldCertificate)
	if err != nil || tokenAgent != agentID || now.UnixNano() >= expiry {
		return "", "", ErrUnauthorized
	}
	csrHash := sha256.Sum256([]byte(csr))
	if used != 0 {
		if oldCSRHash != hex.EncodeToString(csrHash[:]) || oldEnrollment == "" || oldCertificate == "" {
			return "", "", ErrUnauthorized
		}
		var active int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agents WHERE agent_id=? AND enrollment_id=? AND site_id=? AND revoked=0", agentID, oldEnrollment, tokenSite).Scan(&active); err != nil || active != 1 {
			return "", "", ErrUnauthorized
		}
		// An acknowledgement can be lost after the token is consumed. Only
		// this exact CSR/target can retrieve the original enrollment again.
		return oldEnrollment, oldCertificate, nil
	}
	enrollmentID, err = randomToken()
	if err != nil {
		return "", "", err
	}
	cert, serialValue, err := material.IssueClient(csr, agentID, enrollmentID, now)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid enrollment request", ErrInvalid)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE enrollment_tokens SET used=1,csr_hash=?,enrollment_id=?,certificate_pem=? WHERE token_hash=? AND used=0", hex.EncodeToString(csrHash[:]), enrollmentID, string(cert), hex.EncodeToString(hash[:])); err != nil {
		return "", "", err
	}
	updated, err := tx.ExecContext(ctx, `INSERT INTO agents(agent_id,enrollment_id,cert_serial,enrolled_at_ns,site_id) VALUES(?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET enrollment_id=excluded.enrollment_id,cert_serial=excluded.cert_serial,enrolled_at_ns=excluded.enrolled_at_ns,revoked=0,last_seen_at_ns=0,heartbeat_json=NULL,desired_policy_revision=0 WHERE agents.site_id=excluded.site_id`, agentID, enrollmentID, serialValue, now.UnixNano(), tokenSite)
	if err != nil {
		return "", "", err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return "", "", err
	}
	if count != 1 {
		return "", "", ErrUnauthorized
	}
	if err = appendAudit(ctx, tx, agentID, "agent.enrolled", map[string]string{"enrollment_id": enrollmentID}, now); err != nil {
		return "", "", err
	}
	if err = tx.Commit(); err != nil {
		return "", "", err
	}
	return enrollmentID, string(cert), nil
}

func (s *Store) Authenticate(ctx context.Context, agentID, enrollmentID, serialValue string) error {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM agents WHERE agent_id=? AND enrollment_id=? AND cert_serial=? AND revoked=0", agentID, enrollmentID, serialValue).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrUnauthorized
	}
	return nil
}

func (s *Store) Agents(ctx context.Context) ([]Agent, error) {
	return listAgents(ctx, s.db)
}

func listAgents(ctx context.Context, query interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]Agent, error) {
	statement := "SELECT agent_id,enrollment_id,site_id,hostname,enrolled_at_ns,last_seen_at_ns,revoked,heartbeat_json,desired_policy_revision FROM agents"
	var args []any
	if site := selectedSite(ctx); site != "" {
		statement += " WHERE site_id=?"
		args = append(args, site)
	}
	rows, err := query.QueryContext(ctx, statement+" ORDER BY agent_id LIMIT 1000", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Agent, 0)
	for rows.Next() {
		var agent Agent
		var heartbeat []byte
		var enrolled, last int64
		var revoked int
		if err = rows.Scan(&agent.ID, &agent.EnrollmentID, &agent.SiteID, &agent.Hostname, &enrolled, &last, &revoked, &heartbeat, &agent.DesiredPolicyRevision); err != nil {
			return nil, err
		}
		agent.EnrolledAt = time.Unix(0, enrolled).UTC()
		if last != 0 {
			at := time.Unix(0, last).UTC()
			agent.LastSeenAt = &at
		}
		agent.Revoked = revoked != 0
		agent.Heartbeat = heartbeat
		result = append(result, agent)
	}
	return result, rows.Err()
}

func (s *Store) Revoke(ctx context.Context, agentID string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE agents SET revoked=1 WHERE agent_id=? AND (?='' OR site_id=?)", agentID, selectedSite(ctx), selectedSite(ctx))
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNotFound
	}
	if err = appendAudit(ctx, tx, agentID, "agent.revoked", nil, now); err != nil {
		return err
	}
	return tx.Commit()
}

func appendAudit(ctx context.Context, tx *sql.Tx, agentID, kind string, details any, now time.Time) error {
	siteID := selectedSite(ctx)
	if agentID != "" && siteID == "" {
		registeredSite, err := agentSite(ctx, tx, agentID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		siteID = registeredSite
	}
	return appendSiteAudit(ctx, tx, siteID, agentID, kind, details, now)
}

func appendSiteAudit(ctx context.Context, tx *sql.Tx, siteID, agentID, kind string, details any, now time.Time) error {
	body, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit(agent_id,kind,created_at_ns,details_json,site_id) VALUES(?,?,?,?,NULLIF(?,''))", agentID, kind, now.UnixNano(), body, siteID)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS enrollment_tokens(token_hash TEXT PRIMARY KEY,agent_id TEXT NOT NULL,expires_at_ns INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0,csr_hash TEXT NOT NULL DEFAULT '',enrollment_id TEXT NOT NULL DEFAULT '',certificate_pem TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS agents(agent_id TEXT PRIMARY KEY,enrollment_id TEXT NOT NULL,cert_serial TEXT NOT NULL,hostname TEXT NOT NULL DEFAULT '',enrolled_at_ns INTEGER NOT NULL,last_seen_at_ns INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0,heartbeat_json BLOB,desired_policy_revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS delivery_cursors(agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,spool_id TEXT NOT NULL,acknowledged INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(agent_id,enrollment_id,spool_id));
CREATE TABLE IF NOT EXISTS records(agent_id TEXT NOT NULL,kind TEXT NOT NULL,record_id TEXT NOT NULL,payload BLOB NOT NULL,received_at_ns INTEGER NOT NULL,PRIMARY KEY(agent_id,kind,record_id));
CREATE TABLE IF NOT EXISTS deliveries(agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,spool_id TEXT NOT NULL,sequence INTEGER NOT NULL,kind TEXT NOT NULL,record_id TEXT NOT NULL,payload_hash TEXT NOT NULL,PRIMARY KEY(agent_id,enrollment_id,spool_id,sequence));
CREATE TABLE IF NOT EXISTS policies(agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,revision INTEGER NOT NULL,signed_json BLOB NOT NULL,PRIMARY KEY(agent_id,enrollment_id,revision));
CREATE TABLE IF NOT EXISTS audit(audit_id INTEGER PRIMARY KEY AUTOINCREMENT,agent_id TEXT NOT NULL,kind TEXT NOT NULL,created_at_ns INTEGER NOT NULL,details_json BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS records_received_idx ON records(agent_id,received_at_ns DESC);
CREATE INDEX IF NOT EXISTS audit_received_idx ON audit(created_at_ns DESC);
`
