package central

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (s *Server) consolePolicyTrial(w http.ResponseWriter, r *http.Request) {
	account, ok := console.AuthenticatedAccount(r.Context())
	write := r.Method == http.MethodPost
	if !ok || !(account.Role == console.RoleAdmin || account.Role == console.RoleOperator || !write && account.Role == console.RoleViewer) {
		s.consoleError(w, "policy trial authorization", ErrUnauthorized)
		return
	}
	// Receive the bounded request before taking the single SQLite writer.
	if write {
		limit := int64(1 << 20)
		if r.PathValue("id") != "" {
			limit = 64 << 10
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			s.consoleError(w, "policy trial body", ErrInvalid)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}
	if !write {
		var cancel func()
		r, cancel = historyRequest(r)
		defer cancel()
	}
	db := s.store.historyDB
	if write {
		db = s.store.db
	}
	tx, err := db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: !write})
	if err != nil {
		s.consoleError(w, "policy trial transaction", err)
		return
	}
	defer tx.Rollback()
	now := s.now().UTC()
	id := r.PathValue("id")
	var result any
	if id == "" {
		result, err = s.trialCollection(w, r, tx, write, account.Username, now)
	} else if !identifierPattern.MatchString(id) {
		err = ErrInvalid
	} else {
		var t policyTrial
		t, err = loadTrial(r.Context(), tx, id)
		if err == nil {
			if write {
				result, err = s.trialMutation(w, r, tx, t, account.Username, now)
			} else {
				result, err = readTrial(r, tx, t, now)
			}
		}
	}
	if errors.Is(err, errTrialHandled) {
		return
	}
	if err == nil && write {
		err = tx.Commit()
	}
	if err != nil {
		s.consoleError(w, "policy impact trial", err)
		return
	}
	respond(w, http.StatusOK, result)
}

var errTrialHandled = errors.New("policy trial response already written")

func (s *Server) trialCollection(w http.ResponseWriter, r *http.Request, tx *sql.Tx, create bool, actor string, now time.Time) (any, error) {
	if !create {
		rows, err := tx.QueryContext(r.Context(), "SELECT id,canary,phase FROM policy_trials ORDER BY rowid DESC LIMIT 100")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		trials := []policyTrial{}
		for rows.Next() {
			var t policyTrial
			if err := rows.Scan(&t.ID, &t.Canary, &t.Phase); err != nil {
				return nil, err
			}
			trials = append(trials, t)
		}
		return trials, rows.Err()
	}
	var req struct {
		Preview string `json:"preview_token"`
		Canary  string `json:"canary"`
	}
	if !consoleDecode(w, r, 1<<20, &req) {
		return nil, errTrialHandled
	}
	before, err := s.decodeConsolePreview(req.Preview, now)
	if err != nil {
		return nil, err
	}
	return s.createTrial(r.Context(), tx, before, req.Canary, actor, now)
}
func readTrial(r *http.Request, tx *sql.Tx, t policyTrial, now time.Time) (any, error) {
	agent := r.URL.Query().Get("agent_id")
	if agent != "" {
		a, err := t.target(agent)
		if err != nil {
			return nil, err
		}
		switch r.URL.Query().Get("view") {
		case "input":
			return t.input(r.Context(), tx, a)
		case "report":
			var b []byte
			err = tx.QueryRowContext(r.Context(), "SELECT report FROM policy_trial_reports WHERE trial=? AND agent_id=?", t.ID, agent).Scan(&b)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return json.RawMessage(b), err
		default:
			return nil, ErrInvalid
		}
	}
	statuses := make([]trialStatus, 0, len(t.Snapshot.Targets))
	for _, a := range t.Snapshot.Targets {
		one, err := t.status(r.Context(), tx, a, now)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, one)
	}
	return map[string]any{"trial": t, "targets": statuses, "evaluated_at": t.Snapshot.IssuedAt, "template_id": t.Template.ID, "template_version": t.Template.Version}, nil
}
func (s *Server) trialMutation(w http.ResponseWriter, r *http.Request, tx *sql.Tx, t policyTrial, actor string, now time.Time) (any, error) {
	switch r.PathValue("operation") {
	case "report":
		var req struct {
			Agent  string                     `json:"agent_id"`
			Report managed.PolicyImpactReport `json:"report"`
		}
		if !consoleDecode(w, r, 64<<10, &req) {
			return nil, errTrialHandled
		}
		a, err := t.target(req.Agent)
		if err != nil {
			return nil, err
		}
		return t, t.review(r.Context(), tx, a, req.Report, actor, now)
	case "preview", "apply":
		var req trialAction
		if !consoleDecode(w, r, 8192, &req) {
			return nil, errTrialHandled
		}
		return s.trialAction(r.Context(), tx, t, req, actor, r.PathValue("operation") == "apply", now)
	default:
		return nil, ErrNotFound
	}
}
