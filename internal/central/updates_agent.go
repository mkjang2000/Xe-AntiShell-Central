package central

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func writeUpdateJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) updateStatus(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	var inventory managed.UpdateInventory
	if !decodeRequest(w, r, managed.MaxUpdateBytes, &inventory) {
		return
	}
	if err := s.recordUpdateInventory(r.Context(), agent, inventory); err != nil {
		s.apiError(w, "update inventory", err)
		return
	}
	respond(w, http.StatusOK, map[string]time.Time{"received_at": s.now().UTC()})
}
func (s *Server) updateDesired(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	body, err := s.desiredUpdate(r.Context(), agent)
	if err != nil {
		s.apiError(w, "update desired", err)
		return
	}
	if len(body) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeUpdateJSON(w, body)
}
func (s *Server) updateClaim(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	var claim managed.UpdateClaim
	if !decodeRequest(w, r, managed.MaxUpdateBytes, &claim) {
		return
	}
	body, err := s.claimUpdate(r.Context(), agent, claim)
	if err != nil {
		s.apiError(w, "update claim", err)
		return
	}
	writeUpdateJSON(w, body)
}
func (s *Server) updateReport(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	var report managed.UpdateReport
	if !decodeRequest(w, r, managed.MaxUpdateBytes, &report) {
		return
	}
	if err := s.recordUpdateReport(r.Context(), agent, report); err != nil {
		s.apiError(w, "update report", err)
		return
	}
	respond(w, http.StatusOK, map[string]uint64{"sequence": report.Sequence})
}

func (s *Server) updateArtifact(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	id := r.PathValue("sha256")
	if !updateDigestPattern.MatchString(id) || strings.Contains(r.Header.Get("Range"), ",") {
		s.apiError(w, "update artifact", ErrInvalid)
		return
	}
	var metadata []byte
	err := s.store.db.QueryRowContext(r.Context(), `SELECT j.target_json FROM update_heads h JOIN update_jobs j ON j.id=h.active_job_id JOIN update_rollouts c ON c.id=j.rollout_id JOIN agents a ON a.agent_id=h.agent_id AND a.enrollment_id=h.enrollment_id WHERE h.agent_id=? AND h.enrollment_id=? AND a.revoked=0 AND h.revision=j.revision AND c.release_id=? AND j.expires_at_ns>? AND j.state IN ('offered','downloading','ready','installing')`, agent.ID, agent.EnrollmentID, id, s.now().UnixNano()).Scan(&metadata)
	if err != nil {
		s.apiError(w, "update artifact", ErrNotFound)
		return
	}
	var release managed.UpdateRelease
	if json.Unmarshal(metadata, &release) != nil || release.Validate() != nil {
		s.apiError(w, "update artifact", ErrConflict)
		return
	}
	select {
	case s.updateBlobs.downloads <- struct{}{}:
		defer func() { <-s.updateBlobs.downloads }()
	default:
		w.Header().Set("Retry-After", "5")
		respond(w, http.StatusTooManyRequests, map[string]string{"error": "artifact transfer capacity reached"})
		return
	}
	file, err := s.updateBlobs.open(id, release.Size)
	if err != nil {
		s.apiError(w, "update artifact", ErrNotFound)
		return
	}
	defer file.Close()
	controller := http.NewResponseController(w)
	if err = controller.SetWriteDeadline(time.Now().Add(5 * time.Minute)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.apiError(w, "update download deadline", ErrConflict)
		return
	}
	w.Header().Set("Content-Type", "application/x-rpm")
	w.Header().Set("Content-Disposition", `attachment; filename="xe-antishell.rpm"`)
	w.Header().Set("ETag", `"`+id+`"`)
	http.ServeContent(w, r, "xe-antishell.rpm", release.CreatedAt, file)
}
