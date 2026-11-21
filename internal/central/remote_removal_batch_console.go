package central

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const remoteRemovalPreviewDomain = "xe-antishell-central/remote-removal-batch-preview/v1\x00"

type remoteRemovalPreview struct {
	BatchID      string                 `json:"batch_id"`
	Actor        string                 `json:"actor"`
	ActorVersion int64                  `json:"actor_version"`
	SelectedSite string                 `json:"selected_site"`
	IssuedAt     time.Time              `json:"issued_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	Selection    remoteRemovalSelection `json:"selection"`
	Eligible     int                    `json:"eligible"`
	TargetHash   string                 `json:"target_hash"`
}

type remoteRemovalBatchConfirmation struct {
	PreviewToken string `json:"preview_token"`
	Confirmation string `json:"confirmation"`
}

func (request *remoteRemovalBatchConfirmation) UnmarshalJSON(body []byte) error {
	type decoded remoteRemovalBatchConfirmation
	return decodeAgentConfigurationConsoleObject(body, (*decoded)(request), "preview_token", "confirmation")
}

func (s *Server) signRemoteRemovalPreview(preview remoteRemovalPreview) (string, error) {
	body, err := json.Marshal(preview)
	if err != nil {
		return "", err
	}
	if len(body) > previewMaxBytes {
		return "", ErrInvalid
	}
	sig := ed25519.Sign(s.material.PolicyKey, append([]byte(remoteRemovalPreviewDomain), body...))
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Server) verifyRemoteRemovalPreview(token string, account console.Account, site string, now time.Time) (remoteRemovalPreview, error) {
	var preview remoteRemovalPreview
	if len(token) > base64.RawURLEncoding.EncodedLen(previewMaxBytes)+128 {
		return preview, ErrConflict
	}
	encoded, signature, ok := strings.Cut(token, ".")
	if !ok {
		return preview, ErrConflict
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	sig, signErr := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || signErr != nil || !ed25519.Verify(s.material.PolicyKey.Public().(ed25519.PublicKey), append([]byte(remoteRemovalPreviewDomain), body...), sig) {
		return preview, ErrConflict
	}
	if managed.DecodeStrict(body, previewMaxBytes, &preview) != nil || !identifierPattern.MatchString(preview.BatchID) ||
		preview.Actor != account.Username || preview.ActorVersion != account.Version || preview.SelectedSite != site ||
		preview.Eligible < 1 || preview.Eligible > consoleMaxTargets || preview.IssuedAt.IsZero() ||
		preview.IssuedAt.After(now.Add(time.Minute)) || !preview.ExpiresAt.Equal(preview.IssuedAt.Add(previewLifetime)) ||
		!now.Before(preview.ExpiresAt) || preview.Selection.normalize() != nil {
		return remoteRemovalPreview{}, ErrConflict
	}
	return preview, nil
}

func (s *Server) consoleRemoteRemovalBatchPreview(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.remoteRemovalConsoleAccount(w, r)
	if !ok {
		return
	}
	var request remoteRemovalSelection
	if !consoleDecode(w, r, previewMaxBytes, &request) {
		return
	}
	if err := request.normalize(); err != nil {
		s.consoleError(w, "remote removal batch selection", err)
		return
	}
	ctx := r.Context()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		s.consoleError(w, "remote removal batch preview transaction", err)
		return
	}
	defer tx.Rollback()
	now := s.now().UTC()
	witness, eligible, err := remoteRemovalTargets(ctx, tx, actor, request, now)
	if err != nil {
		s.consoleError(w, "remote removal batch targets", err)
		return
	}
	response := map[string]any{"targets": witness.Targets, "eligible_count": eligible}
	if eligible > 0 {
		digest, err := consoleHash(witness)
		if err != nil {
			s.consoleError(w, "remote removal batch target digest", err)
			return
		}
		id, err := randomToken()
		if err != nil {
			s.consoleError(w, "remote removal batch identifier", err)
			return
		}
		preview := remoteRemovalPreview{BatchID: "removal-batch-" + id, Actor: actor.Username, ActorVersion: actor.Version,
			SelectedSite: selectedSite(ctx), IssuedAt: now, ExpiresAt: now.Add(previewLifetime),
			Selection: request, Eligible: eligible, TargetHash: digest}
		token, err := s.signRemoteRemovalPreview(preview)
		if err != nil {
			s.consoleError(w, "remote removal batch preview signature", err)
			return
		}
		response["preview_token"], response["expires_at"], response["batch_id"] = token, preview.ExpiresAt, preview.BatchID
	}
	respond(w, http.StatusOK, response)
}

func (s *Server) consoleRemoteRemovalBatchApply(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.remoteRemovalConsoleAccount(w, r)
	if !ok {
		return
	}
	var request remoteRemovalBatchConfirmation
	if !consoleDecode(w, r, previewMaxBytes*2, &request) {
		return
	}
	preview, err := s.verifyRemoteRemovalPreview(request.PreviewToken, actor, selectedSite(r.Context()), s.now().UTC())
	if err != nil {
		s.consoleError(w, "remote removal batch preview", err)
		return
	}
	if request.Confirmation != strconv.Itoa(preview.Eligible) {
		s.consoleError(w, "remote removal batch target count", ErrInvalid)
		return
	}
	batch, err := s.createRemoteRemovalBatch(r.Context(), actor, preview)
	if err != nil {
		s.consoleError(w, "remote removal batch creation", err)
		return
	}
	respond(w, http.StatusCreated, batch)
}

func (s *Server) consoleRemoteRemovalBatchStatus(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.remoteRemovalConsoleAccount(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !identifierPattern.MatchString(id) {
		s.consoleError(w, "remote removal batch identifier", ErrInvalid)
		return
	}
	ctx := r.Context()
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		s.consoleError(w, "remote removal batch status transaction", err)
		return
	}
	defer tx.Rollback()
	batch, err := s.readRemoteRemovalBatch(ctx, tx, actor, id, s.now().UTC())
	if err != nil {
		s.consoleError(w, "remote removal batch status", err)
		return
	}
	respond(w, http.StatusOK, batch)
}
