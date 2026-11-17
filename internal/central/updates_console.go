package central

import (
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func updateConsoleActor(w http.ResponseWriter, r *http.Request, adminOnly bool) (string, bool) {
	account, ok := console.AuthenticatedAccount(r.Context())
	allowed := ok && (account.Role == console.RoleAdmin || !adminOnly && (account.Role == console.RoleOperator || r.Method == http.MethodGet && account.Role == console.RoleViewer))
	if !allowed {
		respond(w, http.StatusForbidden, map[string]string{"error": "현재 계정에는 업데이트 작업 권한이 없습니다"})
		return "", false
	}
	return account.Username, true
}

func (s *Server) consoleUpdateReleases(w http.ResponseWriter, r *http.Request) {
	actor, ok := updateConsoleActor(w, r, r.Method == http.MethodPost)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		items, err := listUpdateReleases(r.Context(), s.store.db)
		if err != nil {
			s.consoleError(w, "update catalog", err)
			return
		}
		for index := range items {
			items[index].PublisherVerified = items[index].Publisher.Matches(items[index].UpdateRelease) && s.verifyUpdatePublisher(items[index].Publisher) == nil
		}
		respond(w, http.StatusOK, map[string]any{"items": items, "max_bytes": managed.MaxUpdateArtifactBytes, "max_releases": maxUpdateReleases, "max_total_bytes": maxUpdateStorage, "publisher_keys": s.updatePublisherIDs()})
		return
	}
	publisher, err := s.readUpdatePublisherHeader(r)
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "내장 발행자 공개키로 검증할 수 있는 서명된 릴리스 manifest가 필요합니다"})
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (media != "application/x-rpm" && media != "application/octet-stream") {
		respond(w, http.StatusUnsupportedMediaType, map[string]string{"error": "RPM 파일을 application/x-rpm 형식으로 전송하세요"})
		return
	}
	if r.ContentLength > managed.MaxUpdateArtifactBytes {
		respond(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "RPM 파일이 64 MiB 제한을 초과했습니다"})
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != publisher.Manifest.Size {
		respond(w, http.StatusBadRequest, map[string]string{"error": "RPM 크기가 서명된 manifest와 일치하지 않습니다"})
		return
	}
	select {
	case s.updateBlobs.upload <- struct{}{}:
		defer func() { <-s.updateBlobs.upload }()
	default:
		respond(w, http.StatusTooManyRequests, map[string]string{"error": "다른 릴리스 업로드가 진행 중입니다"})
		return
	}
	controller := http.NewResponseController(w)
	if err = controller.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.consoleError(w, "update upload deadline", err)
		return
	}
	if err = controller.SetWriteDeadline(time.Now().Add(5 * time.Minute)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.consoleError(w, "update upload response deadline", err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, managed.MaxUpdateArtifactBytes)
	release, duplicate, err := s.publishUpdateRelease(r.Context(), r.Body, actor, publisher)
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			respond(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "RPM 파일이 64 MiB 제한을 초과했습니다"})
			return
		}
		s.consoleError(w, "update upload", err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	respond(w, status, map[string]any{"release": release, "duplicate": duplicate})
}

func (s *Server) consoleDeleteUpdateRelease(w http.ResponseWriter, r *http.Request) {
	actor, ok := updateConsoleActor(w, r, true)
	if !ok {
		return
	}
	var request struct {
		Confirm bool `json:"confirm"`
	}
	if !consoleDecode(w, r, 1024, &request) {
		return
	}
	if !request.Confirm {
		s.consoleError(w, "update delete confirmation", ErrInvalid)
		return
	}
	if err := s.deleteUpdateRelease(r.Context(), r.PathValue("id"), actor); err != nil {
		s.consoleError(w, "update delete", err)
		return
	}
	respond(w, http.StatusOK, map[string]bool{"deleted": true})
}
func updatePageLimit(r *http.Request, defaultValue int) (int, error) {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return defaultValue, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 200 {
		return 0, ErrInvalid
	}
	return n, nil
}
func (s *Server) consoleUpdateAgents(w http.ResponseWriter, r *http.Request) {
	if _, ok := updateConsoleActor(w, r, false); !ok {
		return
	}
	limit, err := updatePageLimit(r, 100)
	if err != nil {
		s.consoleError(w, "update agents limit", err)
		return
	}
	items, next, total, err := s.listUpdateAgents(r.Context(), r.URL.Query().Get("after"), r.URL.Query().Get("search"), limit)
	if err != nil {
		s.consoleError(w, "update inventories", err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"items": items, "next": next, "total": total})
}
func (s *Server) consoleUpdatePreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := updateConsoleActor(w, r, false); !ok {
		return
	}
	var request ConsoleUpdateRequest
	if !consoleDecode(w, r, 256<<10, &request) {
		return
	}
	now := s.now().UTC()
	tx, err := s.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.consoleError(w, "update preview transaction", err)
		return
	}
	defer tx.Rollback()
	if err = expireUpdateJobs(r.Context(), tx, now); err != nil {
		s.consoleError(w, "update expiry", err)
		return
	}
	snapshot, release, err := updateSnapshot(r.Context(), tx, request, now)
	if err != nil {
		s.consoleError(w, "update preview", err)
		return
	}
	if err = s.verifyUpdatePublisher(release.Publisher); err != nil {
		s.consoleError(w, "update publisher", err)
		return
	}
	release.PublisherVerified = true
	if err = tx.Commit(); err != nil {
		s.consoleError(w, "update preview commit", err)
		return
	}
	snapshot.Nonce, err = randomToken()
	if err != nil {
		s.consoleError(w, "update nonce", err)
		return
	}
	snapshot.IssuedAt = now
	snapshot.ExpiresAt = now.Add(previewLifetime)
	token, err := s.encodeUpdatePreview(snapshot)
	if err != nil {
		s.consoleError(w, "update preview signing", err)
		return
	}
	eligible := 0
	for _, target := range snapshot.Targets {
		if target.Eligible {
			eligible++
		}
	}
	respond(w, http.StatusOK, map[string]any{"preview_token": token, "expires_at": snapshot.ExpiresAt, "release": release, "targets": snapshot.Targets, "eligible_count": eligible, "excluded_count": len(snapshot.Targets) - eligible})
}
func (s *Server) consoleCreateUpdate(w http.ResponseWriter, r *http.Request) {
	actor, ok := updateConsoleActor(w, r, false)
	if !ok {
		return
	}
	var request struct {
		PreviewToken    string `json:"preview_token"`
		Confirm         bool   `json:"confirm"`
		ClientRequestID string `json:"client_request_id"`
	}
	if !consoleDecode(w, r, 1<<20, &request) {
		return
	}
	if !request.Confirm {
		s.consoleError(w, "update confirmation", ErrInvalid)
		return
	}
	id, err := s.confirmUpdate(r.Context(), actor, request.ClientRequestID, request.PreviewToken)
	if err != nil {
		s.consoleError(w, "update create", err)
		return
	}
	rollout, jobs, _, err := s.updateRolloutDetail(r.Context(), id, "", 1000)
	if err != nil {
		s.consoleError(w, "update created state", err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"rollout": rollout, "jobs": jobs})
}
func (s *Server) consoleUpdateRollouts(w http.ResponseWriter, r *http.Request) {
	if _, ok := updateConsoleActor(w, r, false); !ok {
		return
	}
	limit, err := updatePageLimit(r, 20)
	if err != nil {
		s.consoleError(w, "update list limit", err)
		return
	}
	items, next, err := s.listUpdateRollouts(r.Context(), r.URL.Query().Get("after"), limit)
	if err != nil {
		s.consoleError(w, "update rollouts", err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"items": items, "next": next})
}
func (s *Server) consoleUpdateRollout(w http.ResponseWriter, r *http.Request) {
	if _, ok := updateConsoleActor(w, r, false); !ok {
		return
	}
	limit, err := updatePageLimit(r, 100)
	if err != nil {
		s.consoleError(w, "update detail limit", err)
		return
	}
	rollout, jobs, next, err := s.updateRolloutDetail(r.Context(), r.PathValue("id"), r.URL.Query().Get("after"), limit)
	if err != nil {
		s.consoleError(w, "update detail", err)
		return
	}
	respond(w, http.StatusOK, map[string]any{"rollout": rollout, "jobs": jobs, "next": next})
}
func (s *Server) consoleCancelUpdate(w http.ResponseWriter, r *http.Request) {
	actor, ok := updateConsoleActor(w, r, false)
	if !ok {
		return
	}
	var request struct {
		Confirm bool `json:"confirm"`
	}
	if !consoleDecode(w, r, 1024, &request) {
		return
	}
	if !request.Confirm {
		s.consoleError(w, "update cancel confirmation", ErrInvalid)
		return
	}
	cancelled, installing, err := s.cancelUpdate(r.Context(), r.PathValue("id"), actor)
	if err != nil {
		s.consoleError(w, "update cancel", err)
		return
	}
	respond(w, http.StatusOK, map[string]int{"cancelled": cancelled, "installing": installing})
}
