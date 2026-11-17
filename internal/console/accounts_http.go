package console

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *server) serveAccounts(w http.ResponseWriter, r *http.Request, actor Account) {
	if r.Method != http.MethodGet {
		select {
		case s.loginSlots <- struct{}{}:
			defer func() { <-s.loginSlots }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "비밀번호 작업을 처리 중입니다. 잠시 후 다시 시도하세요."})
			return
		}
	}
	if r.URL.Path == "/api/account/password" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.changeAccountPassword(w, r, actor, actor.Username, true)
		return
	}
	if actor.Role != RoleAdmin {
		denyAccountAccess(w)
		return
	}
	if r.URL.Path == "/api/accounts" {
		switch r.Method {
		case http.MethodGet:
			accounts, err := s.accounts.list(r.Context())
			if err != nil {
				s.accountError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, accounts)
		case http.MethodPost:
			var request struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Role     Role   `json:"role"`
			}
			if !decodeAccountRequest(w, r, &request) {
				return
			}
			if !request.Role.valid() {
				s.accountError(w, errAccountInvalid)
				return
			}
			credentials, err := GenerateCredentials(request.Username, request.Password, s.credentials.Parameters)
			if err != nil {
				s.accountError(w, errAccountInvalid)
				return
			}
			account, err := s.accounts.mutate(r.Context(), actor.Username, "created", accountRecord{Account: Account{Username: request.Username, Role: request.Role}, credentials: credentials}, 0, s.now())
			if err != nil {
				s.accountError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, account)
		default:
			methodNotAllowed(w, "GET, POST")
		}
		return
	}
	if r.URL.Path == "/api/account-audit" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		rows, err := s.accounts.db.QueryContext(r.Context(), "SELECT actor,target,operation,role,created_ns FROM account_audit ORDER BY id DESC LIMIT 100")
		if err != nil {
			s.accountError(w, err)
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var actor, target, operation, role string
			var created int64
			if err = rows.Scan(&actor, &target, &operation, &role, &created); err != nil {
				s.accountError(w, err)
				return
			}
			items = append(items, map[string]any{"actor": actor, "target": target, "operation": operation, "role": role, "created_at": time.Unix(0, created).UTC()})
		}
		if err = rows.Err(); err != nil {
			s.accountError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, items)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/accounts/"), "/")
	if len(parts) < 1 || validateUsername(parts[0]) != nil {
		http.NotFound(w, r)
		return
	}
	username := parts[0]
	if len(parts) == 2 && parts[1] == "password" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.changeAccountPassword(w, r, actor, username, actor.Username == username)
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	record, err := s.accounts.get(r.Context(), username)
	if err != nil {
		s.accountError(w, err)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var request struct {
			Role    Role  `json:"role"`
			Version int64 `json:"version"`
		}
		if !decodeAccountRequest(w, r, &request) {
			return
		}
		if !request.Role.valid() {
			s.accountError(w, errAccountInvalid)
			return
		}
		record.Role = request.Role
		if err = rotateAccountSession(&record.credentials); err != nil {
			s.accountError(w, err)
			return
		}
		account, err := s.accounts.mutate(r.Context(), actor.Username, "role_changed", record, request.Version, s.now())
		if err != nil {
			s.accountError(w, err)
			return
		}
		s.accountChanged(w, r, actor.Username == username, account)
	case http.MethodDelete:
		version, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
		if err != nil {
			s.accountError(w, errAccountInvalid)
			return
		}
		if _, err = s.accounts.mutate(r.Context(), actor.Username, "deleted", record, version, s.now()); err != nil {
			s.accountError(w, err)
			return
		}
		s.accountChanged(w, r, actor.Username == username, Account{Username: username})
	default:
		methodNotAllowed(w, "POST, DELETE")
	}
}

func (s *server) changeAccountPassword(w http.ResponseWriter, r *http.Request, actor Account, username string, own bool) {
	var request struct {
		CurrentPassword string `json:"current_password"`
		Password        string `json:"password"`
		Version         int64  `json:"version"`
	}
	if !decodeAccountRequest(w, r, &request) {
		return
	}
	record, err := s.accounts.get(r.Context(), username)
	if err != nil {
		s.accountError(w, err)
		return
	}
	if own && !s.passwordLimiter.allow(username, s.now()) {
		w.Header().Set("Retry-After", "300")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "비밀번호 확인 시도가 많습니다. 5분 후 다시 시도하세요."})
		return
	}
	if own && !record.credentials.Verify(username, request.CurrentPassword) {
		s.accountError(w, ErrInvalidCredentials)
		return
	}
	if own {
		request.Version = record.Version
	}
	credentials, err := GenerateCredentials(username, request.Password, record.credentials.Parameters)
	if err != nil {
		s.accountError(w, errAccountInvalid)
		return
	}
	record.credentials = credentials
	account, err := s.accounts.mutate(r.Context(), actor.Username, "password_changed", record, request.Version, s.now())
	if err != nil {
		s.accountError(w, err)
		return
	}
	s.accountChanged(w, r, own, account)
}

func rotateAccountSession(credentials *Credentials) error {
	key, err := randomBytes(32)
	if err == nil {
		credentials.SessionKey = base64.RawURLEncoding.EncodeToString(key)
	}
	return err
}

func (s *server) accountChanged(w http.ResponseWriter, r *http.Request, reauthenticate bool, account Account) {
	if reauthenticate {
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.origin.secure(r), SameSite: http.SameSiteStrictMode})
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": account, "reauthenticate": reauthenticate})
}

func decodeAccountRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "application/json 형식으로 요청하세요."})
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "계정 입력 형식과 크기를 확인하세요."})
		return false
	}
	return true
}

func (s *server) accountError(w http.ResponseWriter, err error) {
	status, message := http.StatusInternalServerError, "계정 저장소를 처리할 수 없습니다. 다시 시도하세요."
	switch {
	case errors.Is(err, errAccountMissing):
		status, message = http.StatusNotFound, "계정을 찾을 수 없습니다."
	case errors.Is(err, errAccountConflict):
		status, message = http.StatusConflict, "계정이 이미 있거나 변경되었습니다. 목록을 다시 조회하세요."
	case errors.Is(err, errLastAdmin):
		status, message = http.StatusConflict, "마지막 관리자는 삭제하거나 권한을 낮출 수 없습니다. 다른 관리자를 먼저 추가하세요."
	case errors.Is(err, ErrInvalidCredentials):
		status, message = http.StatusForbidden, "현재 비밀번호를 확인하세요."
	case errors.Is(err, errAccountInvalid):
		status, message = http.StatusBadRequest, "사용자 이름, 권한과 비밀번호(16~1,024바이트)를 확인하세요."
	default:
		s.logger.Error("console account operation failed")
	}
	writeJSON(w, status, map[string]string{"error": message})
}
