package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Source record and array offset are immutable. A standalone finding and a bundle
// can have identical IDs, and multiple findings in one bundle share its record ID.
type findingLocation struct {
	Source string `json:"source"`
	Item   int    `json:"item"` // One-based so omission cannot select the first finding.
}

type reviewTarget struct {
	Agent  string `json:"agent_id"`
	Record string `json:"record_id"`
	findingLocation
}

func (t reviewTarget) validate() error {
	if !identifierPattern.MatchString(t.Agent) || t.Record == "" || len(t.Record) > 160 ||
		!(t.Source == "finding" && t.Item == 1 || t.Source == "event_bundle" && t.Item >= 1 && t.Item <= 64) {
		return ErrInvalid
	}
	return nil
}

const reviewSchema = `CREATE TABLE IF NOT EXISTS finding_reviews (
 agent_id TEXT NOT NULL, source TEXT NOT NULL, record_id TEXT NOT NULL, item INTEGER NOT NULL,
 version INTEGER NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL,
 created_at_ns INTEGER NOT NULL, request_id TEXT NOT NULL,
 PRIMARY KEY(agent_id,source,record_id,item,version), UNIQUE(actor,request_id),
 FOREIGN KEY(agent_id,source,record_id) REFERENCES records(agent_id,kind,record_id)
) WITHOUT ROWID;`

type reviewInput struct {
	Target   reviewTarget `json:"target"`
	Expected *int64       `json:"expected_version"`
	Request  string       `json:"request_id"`
	Verdict  string       `json:"verdict"`
	Reason   string       `json:"reason"`
}

type findingReview struct {
	Version int64     `json:"version"`
	Verdict string    `json:"verdict"`
	Reason  string    `json:"reason"`
	Actor   string    `json:"actor"`
	At      time.Time `json:"created_at"`
}

type reviewPage struct {
	Finding json.RawMessage `json:"finding"`
	Latest  int64           `json:"latest_version"`
	Items   []findingReview `json:"items"`
	Next    int64           `json:"next_before,omitempty"`
}

func readFinding(ctx context.Context, tx *sql.Tx, t reviewTarget) (json.RawMessage, error) {
	var body []byte
	expr := "payload"
	args := []any{}
	if t.Source == "event_bundle" {
		expr = "json_extract(payload,'$.findings['||?||']')"
		args = append(args, t.Item-1)
	}
	args = append(args, t.Agent, t.Source, t.Record, selectedSite(ctx), selectedSite(ctx))
	if err := tx.QueryRowContext(ctx, "SELECT "+expr+" FROM records WHERE agent_id=? AND kind=? AND record_id=? AND (?='' OR site_id=?)", args...).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var check struct {
		ID string `json:"finding_id"`
	}
	if json.Unmarshal(body, &check) != nil || check.ID == "" {
		return nil, ErrNotFound
	}
	return body, nil
}

const reviewWhere = `agent_id=? AND source=? AND record_id=? AND item=?`

func latestReview(ctx context.Context, tx *sql.Tx, t reviewTarget) (int64, error) {
	var v int64
	err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM finding_reviews WHERE "+reviewWhere, t.Agent, t.Source, t.Record, t.Item).Scan(&v)
	return v, err
}

func (s *Store) listReviews(ctx context.Context, t reviewTarget, before int64, limit int) (reviewPage, error) {
	var page reviewPage
	tx, err := s.historyDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	page.Finding, err = readFinding(ctx, tx, t)
	if err != nil {
		return page, err
	}
	page.Latest, err = latestReview(ctx, tx, t)
	if err != nil {
		return page, err
	}
	if before == 0 {
		before = math.MaxInt64
	}
	rows, err := tx.QueryContext(ctx, "SELECT version, verdict, reason, actor, created_at_ns FROM finding_reviews WHERE "+reviewWhere+" AND version < ? ORDER BY version DESC LIMIT ?", t.Agent, t.Source, t.Record, t.Item, before, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	page.Items = []findingReview{}
	for rows.Next() {
		if len(page.Items) == limit {
			page.Next = page.Items[limit-1].Version
			break
		}
		var r findingReview
		var ns int64
		if err := rows.Scan(&r.Version, &r.Verdict, &r.Reason, &r.Actor, &ns); err != nil {
			return page, err
		}
		r.At = time.Unix(0, ns).UTC()
		page.Items = append(page.Items, r)
	}
	return page, rows.Err()
}

func (s *Store) appendReview(ctx context.Context, input reviewInput, actor string, now time.Time) (findingReview, bool, error) {
	var r findingReview
	t := input.Target
	if t.validate() != nil || input.Expected == nil || *input.Expected < 0 || *input.Expected >= math.MaxInt64-1 || !identifierPattern.MatchString(input.Request) || input.Reason == "" || len(input.Reason) > 2048 || !validText(input.Reason, true) {
		return r, false, ErrInvalid
	}
	switch input.Verdict {
	case "normal", "suspicious", "deferred":
	default:
		return r, false, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, false, err
	}
	defer tx.Rollback()
	if _, err = readFinding(ctx, tx, t); err != nil {
		return r, false, err
	}
	var previous reviewTarget
	var ns int64
	err = tx.QueryRowContext(ctx, "SELECT agent_id,source,record_id,item,version,verdict,reason,actor,created_at_ns FROM finding_reviews WHERE actor=? AND request_id=?", actor, input.Request).Scan(&previous.Agent, &previous.Source, &previous.Record, &previous.Item, &r.Version, &r.Verdict, &r.Reason, &r.Actor, &ns)
	if err == nil {
		if t != previous || r.Version != *input.Expected+1 || r.Verdict != input.Verdict || r.Reason != input.Reason {
			return r, false, ErrConflict
		}
		r.At = time.Unix(0, ns).UTC()
		return r, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return r, false, err
	}
	latest, err := latestReview(ctx, tx, t)
	if err != nil {
		return r, false, err
	}
	if latest != *input.Expected {
		return r, false, ErrConflict
	}
	r = findingReview{latest + 1, input.Verdict, input.Reason, actor, now.UTC()}
	_, err = tx.ExecContext(ctx, "INSERT INTO finding_reviews(agent_id,source,record_id,item,version,verdict,reason,actor,created_at_ns,request_id) VALUES(?,?,?,?,?,?,?,?,?,?)", t.Agent, t.Source, t.Record, t.Item, r.Version, r.Verdict, r.Reason, r.Actor, r.At.UnixNano(), input.Request)
	if err != nil {
		return r, false, err
	}
	var siteID string
	if err = tx.QueryRowContext(ctx, "SELECT site_id FROM records WHERE agent_id=? AND kind=? AND record_id=?", t.Agent, t.Source, t.Record).Scan(&siteID); err != nil {
		return r, false, err
	}
	if err = appendSiteAudit(ctx, tx, siteID, t.Agent, "finding.reviewed", map[string]any{"actor": actor, "source": t.Source, "record_id": t.Record, "item": t.Item, "version": r.Version, "verdict": r.Verdict}, now); err != nil {
		return r, false, err
	}
	return r, true, tx.Commit()
}

// Only evidence explicitly referenced by the selected finding can be opened.
func (s *Store) reviewEvidence(ctx context.Context, t reviewTarget, id string) (json.RawMessage, error) {
	tx, err := s.historyDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	body, err := readFinding(ctx, tx, t)
	if err != nil {
		return nil, err
	}
	var f struct {
		Evidence []string `json:"evidence_event_ids"`
	}
	if err = json.Unmarshal(body, &f); err != nil {
		return nil, err
	}
	for _, ref := range f.Evidence {
		if ref == id {
			var evidence []byte
			// Prefer the original bundle event for a bundle finding. Standalone records
			// can refer to either representation of an event from the same agent.
			preferred := "event"
			if t.Source == "event_bundle" {
				preferred = "event_bundle"
			}
			err = tx.QueryRowContext(ctx, `SELECT CASE kind WHEN 'event' THEN payload ELSE json_extract(payload,'$.event') END FROM records WHERE agent_id=? AND record_id=? AND kind IN ('event','event_bundle') AND (?='' OR site_id=?) ORDER BY (kind=?) DESC LIMIT 1`, t.Agent, id, selectedSite(ctx), selectedSite(ctx), preferred).Scan(&evidence)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return evidence, err
		}
	}
	return nil, fmt.Errorf("%w: 선택한 경보의 근거를 확인하세요", ErrInvalid)
}
