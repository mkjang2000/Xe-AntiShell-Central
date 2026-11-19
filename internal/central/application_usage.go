package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type templateUse struct {
	AgentID         string               `json:"agent_id"`
	EnrollmentID    string               `json:"enrollment_id"`
	DesiredRevision uint64               `json:"desired_revision"`
	HostPolicy      bool                 `json:"host_policy"`
	Bindings        []ApplicationBinding `json:"bindings"`
	Status          applicationStatus    `json:"application_status"`
}

type templateUsagePage struct {
	Items     []templateUse `json:"items"`
	NextAfter string        `json:"next_after,omitempty"`
}

func (s *Server) consoleTemplateUsage(w http.ResponseWriter, r *http.Request) {
	id, after := r.PathValue("id"), r.URL.Query().Get("after")
	limit := 100
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
	}
	if !identifierPattern.MatchString(id) || after != "" && !identifierPattern.MatchString(after) || err != nil || limit < 1 || limit > 100 {
		s.consoleError(w, "template usage input", ErrInvalid)
		return
	}
	tx, err := s.store.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		s.consoleError(w, "template usage transaction", err)
		return
	}
	defer tx.Rollback()
	page, err := templateUsage(r.Context(), tx, id, after, limit, s.now().UTC())
	if err != nil {
		s.consoleError(w, "template usage", err)
		return
	}
	_ = tx.Rollback()
	respond(w, http.StatusOK, page)
}

// Page the fleet first to keep sparse matches bounded. Only console assignments
// carry source template provenance. A direct policy using the same ID is not a
// template deployment. The client already has group membership in its fleet view.
func templateUsage(ctx context.Context, tx *sql.Tx, id, after string, limit int, now time.Time) (templateUsagePage, error) {
	out := templateUsagePage{Items: []templateUse{}}
	rows, err := tx.QueryContext(ctx, `SELECT a.agent_id,a.enrollment_id,a.last_seen_at_ns,
		CASE WHEN s.agent_id IS NOT NULL THEN p.signed_json END,
		CASE WHEN s.agent_id IS NOT NULL THEN json_object(
			'agent_id', json_extract(a.heartbeat_json,'$.agent_id'), 'enrollment_id', json_extract(a.heartbeat_json,'$.enrollment_id'),
			'sent_at', json_extract(a.heartbeat_json,'$.sent_at'), 'policy_status', json_extract(a.heartbeat_json,'$.policy_status')) END
		FROM agents a
		LEFT JOIN console_policy_settings s ON (s.agent_id,s.enrollment_id,s.revision)=(a.agent_id,a.enrollment_id,a.desired_policy_revision)
		LEFT JOIN policies p ON (p.agent_id,p.enrollment_id,p.revision)=(s.agent_id,s.enrollment_id,s.revision)
		WHERE a.revoked=0 AND a.agent_id>? ORDER BY a.agent_id LIMIT ?`, after, limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	type evidence struct {
		signed managed.SignedPolicy
		hb     []byte
		seen   int64
	}
	var matches []evidence
	scanned, last := 0, ""
	for rows.Next() {
		if scanned == limit {
			out.NextAfter = last
			break
		}
		var item templateUse
		var e evidence
		var raw []byte
		if err = rows.Scan(&item.AgentID, &item.EnrollmentID, &e.seen, &raw, &e.hb); err != nil {
			return out, err
		}
		scanned++
		last = item.AgentID
		if len(raw) == 0 {
			continue
		}
		if err = json.Unmarshal(raw, &e.signed); err != nil {
			return out, err
		}
		policy := e.signed.Policy
		item.HostPolicy = policy.ID == id
		item.DesiredRevision = policy.Revision
		item.Bindings = []ApplicationBinding{}
		for _, app := range policy.Applications {
			if app.PolicyID == id {
				item.Bindings = append(item.Bindings, ApplicationBinding{app.Service, app.PolicyID, app.PolicyVersion})
			}
		}
		if !item.HostPolicy && len(item.Bindings) == 0 {
			continue
		}
		out.Items = append(out.Items, item)
		matches = append(matches, e)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if err = rows.Close(); err != nil {
		return out, err
	}
	for i, e := range matches {
		_, out.Items[i].Status, err = reportedApplicationPolicy(ctx, tx, e.signed, e.hb, e.seen, false, now)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
