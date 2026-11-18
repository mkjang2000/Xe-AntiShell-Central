package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const consoleSchema = `
CREATE TABLE IF NOT EXISTS console_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,version INTEGER NOT NULL,generation TEXT NOT NULL,agent_ids_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS console_templates(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,version INTEGER NOT NULL,generation TEXT NOT NULL,settings_json BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS console_policy_settings(agent_id TEXT NOT NULL,enrollment_id TEXT NOT NULL,revision INTEGER NOT NULL,settings_json BLOB NOT NULL,PRIMARY KEY(agent_id,enrollment_id,revision));
CREATE TABLE IF NOT EXISTS console_record_versions(kind TEXT NOT NULL,id TEXT NOT NULL,last_version INTEGER NOT NULL,PRIMARY KEY(kind,id));
INSERT INTO console_record_versions(kind,id,last_version) SELECT 'console_groups',id,version FROM console_groups WHERE 1 ON CONFLICT(kind,id) DO UPDATE SET last_version=MAX(last_version,excluded.last_version);
INSERT INTO console_record_versions(kind,id,last_version) SELECT 'console_templates',id,version FROM console_templates WHERE 1 ON CONFLICT(kind,id) DO UPDATE SET last_version=MAX(last_version,excluded.last_version);
CREATE INDEX IF NOT EXISTS records_console_page_idx ON records(received_at_ns DESC,agent_id DESC,kind DESC,record_id DESC);
`

const consoleMaxTargets = 1000

type ConsoleGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     int64    `json:"version"`
	AgentIDs    []string `json:"agent_ids"`
	generation  string
}

type ConsoleIntegrity struct {
	PackageFiles bool     `json:"package_files,omitempty"`
	ConfigSHA256 string   `json:"config_sha256,omitempty"`
	Enabled      bool     `json:"enabled"`
	Mode         string   `json:"mode"`
	RequireTPM   bool     `json:"require_tpm"`
	Paths        []string `json:"paths"`
}

// ConsoleSettings retains desired configuration independently of the agent wire
// contract. In particular integrity must never be added to a managed-v1 policy.
type ConsoleSettings struct {
	Detection     managed.DetectionPolicy  `json:"detection"`
	Response      managed.ResponsePolicy   `json:"response"`
	UninstallMode string                   `json:"uninstall_mode"`
	Monitoring    managed.MonitoringPolicy `json:"monitoring"`
	Integrity     ConsoleIntegrity         `json:"integrity"`
	ValidityHours int                      `json:"validity_hours"`
}

type ConsoleTemplate struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Version     int64           `json:"version"`
	Settings    ConsoleSettings `json:"settings"`
	generation  string
}

func defaultConsoleSettings(now time.Time) ConsoleSettings {
	p := managed.DefaultPolicy("console-default", "console-default", 1, now)
	return ConsoleSettings{Detection: p.Detection, Response: p.Response, UninstallMode: p.UninstallMode,
		Monitoring: p.Monitoring, Integrity: ConsoleIntegrity{Mode: "observe", Paths: []string{}}, ValidityHours: 24}
}

func (settings ConsoleSettings) wirePolicy(id, agentID, enrollmentID string, revision uint64, now time.Time) managed.Policy {
	return managed.Policy{SchemaVersion: managed.SchemaVersion, ID: id, Revision: revision,
		AgentID: agentID, EnrollmentID: enrollmentID, IssuedAt: now, ExpiresAt: now.Add(time.Duration(settings.ValidityHours) * time.Hour),
		Detection: settings.Detection, Response: settings.Response, UninstallMode: settings.UninstallMode, Monitoring: settings.Monitoring}
}

func (settings ConsoleSettings) validate() error {
	if settings.ValidityHours < 1 || settings.ValidityHours > 8760 {
		return fmt.Errorf("%w: 정책 유효 시간은 1~8760시간이어야 합니다", ErrInvalid)
	}
	if settings.Integrity.Mode != "observe" && settings.Integrity.Mode != "enforce" {
		return fmt.Errorf("%w: 무결성 모드는 observe 또는 enforce여야 합니다", ErrInvalid)
	}
	if settings.Integrity.ConfigSHA256 != "" && (!settings.Integrity.PackageFiles || !contract.ValidDigest(settings.Integrity.ConfigSHA256)) {
		return fmt.Errorf("%w: 파일 무결성 설정에는 승인된 YAML의 소문자 SHA-256이 필요합니다", ErrInvalid)
	}
	if len(settings.Integrity.Paths) > 256 {
		return fmt.Errorf("%w: 무결성 경로는 256개 이하여야 합니다", ErrInvalid)
	}
	seen := make(map[string]bool)
	for _, path := range settings.Integrity.Paths {
		if len(path) > 4096 || !validText(path, false) || !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return fmt.Errorf("%w: 무결성 경로는 중복 없는 정규화된 절대 경로여야 합니다", ErrInvalid)
		}
		seen[path] = true
	}
	policy := settings.wirePolicy("validation", "validation", "validation", 1, time.Unix(1, 0).UTC())
	if policy.Validate() != nil {
		return fmt.Errorf("%w: 탐지·대응·삭제 또는 모니터링 설정을 확인하세요", ErrInvalid)
	}
	body, err := json.Marshal(policy)
	if err != nil || len(body) > managed.MaxPolicyBytes-1024 {
		return fmt.Errorf("%w: 정책 설정이 너무 큽니다", ErrInvalid)
	}
	if body, err = json.Marshal(settings); err != nil || len(body) > 128<<10 {
		return fmt.Errorf("%w: 무결성을 포함한 전체 설정은 128KiB 이하여야 합니다", ErrInvalid)
	}
	return nil
}

func validText(value string, multiline bool) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) && !(multiline && (char == '\n' || char == '\t')) {
			return false
		}
	}
	return true
}

func validateConsoleMetadata(id, name, description string, version int64) error {
	if !identifierPattern.MatchString(id) || name == "" || len(name) > 256 || len(description) > 4096 || !validText(name, false) || !validText(description, true) || version < 0 || version >= math.MaxInt64 {
		return fmt.Errorf("%w: ID, 이름, 설명 또는 버전을 확인하세요", ErrInvalid)
	}
	return nil
}

func normalizedIDs(ids []string, maximum int) ([]string, error) {
	if len(ids) > maximum {
		return nil, fmt.Errorf("%w: 선택한 대상이 너무 많습니다", ErrInvalid)
	}
	result := append([]string{}, ids...)
	sort.Strings(result)
	for index, id := range result {
		if !identifierPattern.MatchString(id) || index > 0 && result[index-1] == id {
			return nil, fmt.Errorf("%w: 대상 ID가 잘못되었거나 중복되었습니다", ErrInvalid)
		}
	}
	return result, nil
}

func loadConsoleGroup(ctx context.Context, tx *sql.Tx, id string) (ConsoleGroup, error) {
	var group ConsoleGroup
	var body []byte
	err := tx.QueryRowContext(ctx, "SELECT id,name,description,version,generation,agent_ids_json FROM console_groups WHERE id=?", id).Scan(&group.ID, &group.Name, &group.Description, &group.Version, &group.generation, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return group, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(body, &group.AgentIDs)
	}
	return group, err
}

func loadConsoleTemplate(ctx context.Context, tx *sql.Tx, id string) (ConsoleTemplate, error) {
	var template ConsoleTemplate
	var body []byte
	err := tx.QueryRowContext(ctx, "SELECT id,name,description,version,generation,settings_json FROM console_templates WHERE id=?", id).Scan(&template.ID, &template.Name, &template.Description, &template.Version, &template.generation, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return template, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(body, &template.Settings)
	}
	return template, err
}

func (s *Store) saveConsoleGroup(ctx context.Context, group ConsoleGroup, now time.Time) (ConsoleGroup, error) {
	if err := validateConsoleMetadata(group.ID, group.Name, group.Description, group.Version); err != nil {
		return group, err
	}
	ids, err := normalizedIDs(group.AgentIDs, consoleMaxTargets)
	if err != nil {
		return group, err
	}
	group.AgentIDs = ids
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return group, err
	}
	defer tx.Rollback()
	for _, id := range ids {
		var active int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM agents WHERE agent_id=? AND revoked=0", id).Scan(&active); err != nil {
			return group, err
		}
		if active != 1 {
			return group, fmt.Errorf("%w: 등록된 활성 에이전트만 그룹에 추가할 수 있습니다", ErrInvalid)
		}
	}
	body, err := json.Marshal(ids)
	if err != nil {
		return group, err
	}
	if group.Version, err = saveConsoleRecord(ctx, tx, "console_groups", group.ID, group.Name, group.Description, group.Version, "agent_ids_json", body); err != nil {
		return group, err
	}
	if err = appendAudit(ctx, tx, "", "console.group.saved", map[string]any{"group_id": group.ID, "version": group.Version, "agent_count": len(ids)}, now); err != nil {
		return group, err
	}
	return group, tx.Commit()
}

func (s *Store) saveConsoleTemplate(ctx context.Context, template ConsoleTemplate, now time.Time) (ConsoleTemplate, error) {
	if err := validateConsoleMetadata(template.ID, template.Name, template.Description, template.Version); err != nil {
		return template, err
	}
	if err := template.Settings.validate(); err != nil {
		return template, err
	}
	body, err := json.Marshal(template.Settings)
	if err != nil {
		return template, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return template, err
	}
	defer tx.Rollback()
	if template.Version, err = saveConsoleRecord(ctx, tx, "console_templates", template.ID, template.Name, template.Description, template.Version, "settings_json", body); err != nil {
		return template, err
	}
	if err = appendAudit(ctx, tx, "", "console.template.saved", map[string]any{"template_id": template.ID, "version": template.Version}, now); err != nil {
		return template, err
	}
	return template, tx.Commit()
}

// table and column are fixed internal identifiers, never request input.
func saveConsoleRecord(ctx context.Context, tx *sql.Tx, table, id, name, description string, version int64, column string, body []byte) (int64, error) {
	var current int64
	err := tx.QueryRowContext(ctx, "SELECT version FROM "+table+" WHERE id=?", id).Scan(&current)
	creating := errors.Is(err, sql.ErrNoRows)
	if creating {
		if version != 0 {
			return 0, ErrConflict
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			return 0, err
		}
		if count >= 1000 {
			return 0, fmt.Errorf("%w: 항목은 최대 1000개까지 저장할 수 있습니다", ErrInvalid)
		}
	} else if err != nil {
		return 0, err
	} else if version != current {
		return 0, ErrConflict
	}
	var previous int64
	err = tx.QueryRowContext(ctx, "SELECT last_version FROM console_record_versions WHERE kind=? AND id=?", table, id).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if current > previous {
		previous = current
	}
	if previous >= math.MaxInt64 {
		return 0, fmt.Errorf("%w: 항목 버전이 최대값에 도달했습니다", ErrInvalid)
	}
	next := previous + 1
	if creating {
		generation, randomErr := randomToken()
		if randomErr != nil {
			return 0, randomErr
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO "+table+"(id,name,description,version,generation,"+column+") VALUES(?,?,?,?,?,?)", id, name, description, next, generation, body)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE "+table+" SET name=?,description=?,version=?,"+column+"=? WHERE id=? AND version=?", name, description, next, body, id, version)
	}
	if err != nil {
		return 0, err
	}
	// This ledger survives deletion so stale editors cannot match a recreated
	// record's version. It commits atomically with the record and audit entry.
	_, err = tx.ExecContext(ctx, "INSERT INTO console_record_versions(kind,id,last_version) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET last_version=excluded.last_version", table, id, next)
	return next, err
}

func (s *Store) deleteConsoleRecord(ctx context.Context, group bool, id string, version int64, now time.Time) error {
	if !identifierPattern.MatchString(id) || version < 1 {
		return fmt.Errorf("%w: 삭제할 ID와 현재 버전을 지정하세요", ErrInvalid)
	}
	table, kind := "console_templates", "console.template.deleted"
	if group {
		table, kind = "console_groups", "console.group.deleted"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, "SELECT version FROM "+table+" WHERE id=?", id).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if current != version {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE id=? AND version=?", id, version); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, "", kind, map[string]any{"id": id, "version": version}, now); err != nil {
		return err
	}
	return tx.Commit()
}
