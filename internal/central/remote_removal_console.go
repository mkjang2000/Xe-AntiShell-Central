package central

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
)

type remoteRemovalConsoleRequest struct {
	EnrollmentID string `json:"enrollment_id"`
	Confirmation string `json:"confirmation"`
}

func (r *remoteRemovalConsoleRequest) UnmarshalJSON(body []byte) error {
	type request remoteRemovalConsoleRequest
	return decodeAgentConfigurationConsoleObject(body, (*request)(r), "enrollment_id", "confirmation")
}

type remoteRemovalConsoleCancellation struct {
	EnrollmentID string `json:"enrollment_id"`
	OrderID      string `json:"order_id"`
}

func (r *remoteRemovalConsoleCancellation) UnmarshalJSON(body []byte) error {
	type request remoteRemovalConsoleCancellation
	return decodeAgentConfigurationConsoleObject(body, (*request)(r), "enrollment_id", "order_id")
}

func (s *Server) remoteRemovalConsoleAccount(w http.ResponseWriter, r *http.Request) (console.Account, bool) {
	account, ok := console.AuthenticatedAccount(r.Context())
	if !ok || !account.Has(console.PermissionAgentRemove) {
		s.consoleError(w, "remote removal authorization", ErrUnauthorized)
		return console.Account{}, false
	}
	return account, true
}

func (s *Server) authorizeRemoteRemovalConsole(w http.ResponseWriter, r *http.Request) (string, console.Account, bool) {
	account, ok := s.remoteRemovalConsoleAccount(w, r)
	if !ok {
		return "", console.Account{}, false
	}
	id := r.PathValue("id")
	if !identifierPattern.MatchString(id) {
		s.consoleError(w, "remote removal target", ErrInvalid)
		return "", console.Account{}, false
	}
	return id, account, true
}

func (s *Server) consoleRemoteRemoval(w http.ResponseWriter, r *http.Request) {
	id, account, ok := s.authorizeRemoteRemovalConsole(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		state, err := s.remoteRemovalStatus(r.Context(), id, account)
		if err != nil {
			s.consoleError(w, "remote removal state", err)
			return
		}
		respond(w, http.StatusOK, state)
		return
	}
	var request remoteRemovalConsoleRequest
	if !consoleDecode(w, r, remoteRemovalRequestBytes, &request) {
		return
	}
	if request.Confirmation != id || request.EnrollmentID == "" || len(request.EnrollmentID) > 160 {
		s.consoleError(w, "remote removal confirmation", ErrInvalid)
		return
	}
	job, err := s.newRemoteRemovalOrder(r.Context(), id, request.EnrollmentID, account)
	if err != nil {
		s.consoleError(w, "remote removal queue", err)
		return
	}
	respond(w, http.StatusCreated, job)
}

func (s *Server) consoleRemoteRemovalCancel(w http.ResponseWriter, r *http.Request) {
	id, account, ok := s.authorizeRemoteRemovalConsole(w, r)
	if !ok {
		return
	}
	var request remoteRemovalConsoleCancellation
	if !consoleDecode(w, r, remoteRemovalRequestBytes, &request) {
		return
	}
	if request.EnrollmentID == "" || len(request.EnrollmentID) > 160 || !identifierPattern.MatchString(request.OrderID) {
		s.consoleError(w, "remote removal cancellation", ErrInvalid)
		return
	}
	job, err := s.cancelRemoteRemoval(r.Context(), authenticatedAgent{id, request.EnrollmentID}, request.OrderID, account)
	if err != nil {
		s.consoleError(w, "remote removal cancellation", err)
		return
	}
	respond(w, http.StatusOK, job)
}

func (s *Server) remoteRemovalStatus(ctx context.Context, agentID string, account console.Account) (remoteRemovalState, error) {
	now := s.now().UTC()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return remoteRemovalState{}, err
	}
	defer tx.Rollback()
	state, err := loadRemoteRemovalTarget(ctx, tx, agentID, now)
	if err != nil {
		return state, err
	}
	if err := authorizeRemoteRemovalSite(ctx, account, state.SiteID); err != nil {
		return remoteRemovalState{}, err
	}
	job, err := remoteRemovalOrder(ctx, tx, authenticatedAgent{agentID, state.EnrollmentID}, "")
	if err != nil && !errors.Is(err, ErrNotFound) {
		return state, err
	}
	if job != nil {
		var sameSite bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM remote_removal_intents WHERE order_id=? AND site_id=?)", job.OrderID, state.SiteID).Scan(&sameSite); err != nil {
			return remoteRemovalState{}, err
		}
		projectRemoteRemovalJob(job, now, state.Reason == "revoked" || !sameSite)
		if !sameSite {
			job = nil
		}
	}
	if state.Reason == "" {
		pending, err := remoteRemovalPending(ctx, tx, agentID, state.EnrollmentID, now)
		if err != nil {
			return remoteRemovalState{}, err
		}
		if pending {
			state.Reason = "removal_busy"
		}
	}
	state.Job = job
	state.CanRequest = state.Reason == ""
	return state, nil
}

func projectRemoteRemovalJob(job *remoteRemovalJob, now time.Time, inactive bool) {
	switch {
	case (job.State == "queued" || job.State == "claimed") && inactive:
		job.State = "cancelled"
	case job.expiredBeforeStart(now):
		job.State = "expired"
	case job.State == "started" && (!now.Before(job.ExpiresAt) || inactive):
		job.State = "result_unknown"
	}
}

func (s *Server) cancelRemoteRemoval(ctx context.Context, agent authenticatedAgent, orderID string, actor console.Account) (*remoteRemovalJob, error) {
	now := s.now().UTC()
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	state, err := loadRemoteRemovalTarget(ctx, tx, agent.ID, now)
	if err != nil {
		return nil, err
	}
	if err := authorizeRemoteRemovalSite(ctx, actor, state.SiteID); err != nil {
		return nil, err
	}
	if state.EnrollmentID != agent.EnrollmentID || state.Reason == "revoked" {
		return nil, ErrConflict
	}
	job, err := remoteRemovalOrder(ctx, tx, agent, orderID)
	if err != nil {
		return nil, err
	}
	var sameSite bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM remote_removal_intents WHERE order_id=? AND site_id=?)", job.OrderID, state.SiteID).Scan(&sameSite); err != nil {
		return nil, err
	}
	if !sameSite {
		return nil, ErrNotFound
	}
	if job.State == "cancelled" {
		return job, nil
	}
	if job.State != "queued" && job.State != "claimed" || !now.Before(job.ExpiresAt) {
		return nil, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "UPDATE remote_removal_orders SET state='cancelled',updated_at_ns=?,grant_json=NULL WHERE id=? AND state IN ('queued','claimed')",
		now.UnixNano(), orderID); err != nil {
		return nil, err
	}
	job.State, job.UpdatedAt = "cancelled", now
	if err = appendRemoteRemovalAudit(ctx, tx, agent, job, actor.Username, now); err != nil {
		return nil, err
	}
	return job, tx.Commit()
}
