package central

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/selfupdate"
)

const centralUpdateBase = "/api/central-update/"

func (s *Server) consoleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	actor, ok := updateConsoleActor(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		if r.URL.Path == centralUpdateBase+"status" {
			status, err := selfupdate.Current(r.Context())
			if err != nil {
				selfUpdateError(w, err)
				return
			}
			respond(w, http.StatusOK, status)
			return
		}
		items, err := selfupdate.ListReleases(r.Context())
		if err != nil {
			respond(w, http.StatusBadGateway, map[string]string{"error": "공식 GitHub 릴리즈 목록을 가져올 수 없습니다."})
			return
		}
		respond(w, http.StatusOK, map[string]any{"items": items})
		return
	}

	// Browser uploads and GitHub transfers can exceed ordinary API deadlines.
	deadline := time.Now().Add(5 * time.Minute)
	controller := http.NewResponseController(w)
	for _, set := range []func(time.Time) error{controller.SetReadDeadline, controller.SetWriteDeadline} {
		if err := set(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			selfUpdateError(w, err)
			return
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	var signed selfupdate.SignedManifest
	var rpm io.Reader
	if r.URL.Path == centralUpdateBase+"github" {
		var request struct {
			Tag     string `json:"tag"`
			Confirm bool   `json:"confirm"`
		}
		if !consoleDecode(w, r, 512, &request) {
			return
		}
		if !request.Confirm || request.Tag == "" {
			respond(w, http.StatusBadRequest, map[string]string{"error": "설치할 센트럴 릴리즈를 선택하고 설치를 확인하세요."})
			return
		}
		manifest, body, err := selfupdate.GithubDownload(ctx, request.Tag)
		if err != nil {
			respond(w, http.StatusBadGateway, map[string]string{"error": "선택한 공식 릴리즈의 RPM과 발행자 서명을 가져올 수 없습니다."})
			return
		}
		defer body.Close()
		signed, rpm = manifest, body
	} else {
		var valid bool
		signed, valid = centralUploadManifest(ctx, w, r)
		if !valid {
			return
		}
		rpm = http.MaxBytesReader(w, r.Body, selfupdate.MaxRPMBytes)
	}
	s.logger.Info("central update requested", "actor", actor, "tag", signed.Manifest.Tag)
	status, err := selfupdate.Apply(ctx, signed, rpm)
	if err != nil {
		selfUpdateError(w, err)
		return
	}
	respond(w, http.StatusAccepted, status)
}

func centralUploadManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) (selfupdate.SignedManifest, bool) {
	var empty selfupdate.SignedManifest
	if r.Header.Get("X-Xeas-Central-Confirm") != "true" {
		respond(w, http.StatusBadRequest, map[string]string{"error": "센트럴 설치 확인이 필요합니다."})
		return empty, false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (media != "application/x-rpm" && media != "application/octet-stream") {
		respond(w, http.StatusUnsupportedMediaType, map[string]string{"error": "센트럴 RPM 파일을 선택하세요."})
		return empty, false
	}
	if r.ContentLength > selfupdate.MaxRPMBytes {
		respond(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "RPM은 최대 64 MiB까지 업로드할 수 있습니다."})
		return empty, false
	}
	headers := r.Header.Values("X-Xeas-Central-Manifest")
	names := r.Header.Values("X-Xeas-Central-Artifact")
	var signed selfupdate.SignedManifest
	switch {
	case len(headers) == 1 && len(names) == 0 && len(headers[0]) > 0 && len(headers[0]) <= base64.RawURLEncoding.EncodedLen(selfupdate.MaxManifestBytes):
		raw, err := base64.RawURLEncoding.Strict().DecodeString(headers[0])
		if err == nil {
			signed, err = selfupdate.DecodeManifest(raw)
		}
		if err != nil {
			respond(w, http.StatusBadRequest, map[string]string{"error": "공식 센트럴 발행자 서명을 검증할 수 없습니다. 해당 RPM의 manifest를 선택하세요."})
			return empty, false
		}
	case len(headers) == 0 && len(names) == 1 && names[0] != "" && len(names[0]) <= 128:
		var err error
		signed, err = selfupdate.GithubManifestForRPM(ctx, names[0])
		if err != nil {
			respond(w, http.StatusBadRequest, map[string]string{"error": "이 RPM의 공식 서명 manifest를 가져올 수 없습니다. 릴리즈의 원래 RPM 파일명 또는 함께 받은 manifest를 확인하세요."})
			return empty, false
		}
	default:
		respond(w, http.StatusBadRequest, map[string]string{"error": "공식 RPM 파일명 또는 해당 RPM의 서명 manifest를 지정하세요."})
		return empty, false
	}
	if r.ContentLength >= 0 && signed.Manifest.Size != r.ContentLength {
		respond(w, http.StatusBadRequest, map[string]string{"error": "RPM 크기가 서명된 manifest와 일치하지 않습니다."})
		return empty, false
	}
	return signed, true
}

func selfUpdateError(w http.ResponseWriter, err error) {
	code, message := http.StatusServiceUnavailable, "센트럴 업데이터에 연결할 수 없습니다. 업데이터 소켓과 설치 상태를 확인하세요."
	var worker *selfupdate.ClientError
	if errors.As(err, &worker) {
		switch worker.StatusCode {
		case http.StatusConflict:
			code, message = worker.StatusCode, "센트럴 설치 조건을 확인하세요. "+worker.Message
		case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusRequestEntityTooLarge:
			code, message = worker.StatusCode, "RPM을 검증할 수 없습니다. "+worker.Message
		}
	}
	respond(w, code, map[string]string{"error": message})
}
