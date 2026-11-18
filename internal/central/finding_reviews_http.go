package central

import (
	"net/http"
	"strconv"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
)

func (s *Server) consoleFindingReviews(w http.ResponseWriter, r *http.Request) {
	account, ok := console.AuthenticatedAccount(r.Context())
	if !ok || (account.Role != console.RoleAdmin && account.Role != console.RoleOperator && !(r.Method == http.MethodGet && account.Role == console.RoleViewer)) {
		s.consoleError(w, "finding review authorization", ErrUnauthorized)
		return
	}
	if r.Method == http.MethodPost {
		var req reviewInput
		if !consoleDecode(w, r, 16<<10, &req) {
			return
		}
		result, created, err := s.store.appendReview(r.Context(), req, account.Username, s.now())
		if err != nil {
			s.consoleError(w, "save finding review", err)
			return
		}
		code := http.StatusOK
		if created {
			code = http.StatusCreated
		}
		respond(w, code, result)
		return
	}
	r, cancel := historyRequest(r)
	defer cancel()
	q := r.URL.Query()
	index, err := strconv.Atoi(q.Get("item"))
	t := reviewTarget{Agent: q.Get("agent_id"), Record: q.Get("record_id"), findingLocation: findingLocation{Source: q.Get("source"), Item: index}}
	if err != nil || t.validate() != nil {
		s.consoleError(w, "finding location", ErrInvalid)
		return
	}
	if q.Has("evidence_id") {
		id := q.Get("evidence_id")
		if id == "" || len(id) > 160 {
			s.consoleError(w, "finding evidence ID", ErrInvalid)
			return
		}
		body, err := s.store.reviewEvidence(r.Context(), t, id)
		if err != nil {
			s.historyError(w, r, "finding evidence", err)
			return
		}
		respond(w, http.StatusOK, body)
		return
	}
	var before int64
	if q.Has("before") {
		before, err = strconv.ParseInt(q.Get("before"), 10, 64)
		if err != nil || before <= 0 {
			s.consoleError(w, "finding review cursor", ErrInvalid)
			return
		}
	}
	result, err := s.store.listReviews(r.Context(), t, before, 20)
	if err != nil {
		s.historyError(w, r, "finding reviews", err)
		return
	}
	respond(w, http.StatusOK, result)
}
