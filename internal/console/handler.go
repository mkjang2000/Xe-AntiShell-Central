// Copyright (c) 2026 mkjang2000 and Xe-AntiShell contributors
// SPDX-License-Identifier: MIT

// Package console authenticates browser access to the central operator API.
package console

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	sessionCookieName = "xeas_central_session"
	sessionLifetime   = 8 * time.Hour
	maxLoginBody      = 4 * 1024
	maxAPIBody        = 1024 * 1024
)

//go:embed assets/*.html assets/*.css assets/*.js
var assets embed.FS

type server struct {
	credentials     Credentials
	accounts        *accountStore
	api             http.Handler
	logger          *slog.Logger
	now             func() time.Time
	limiter         *loginLimiter
	passwordLimiter *loginLimiter
	loginSlots      chan struct{}
	origin          originPolicy
	siteExists      func(context.Context, string) (bool, error)
}

// New wraps a central business API with browser authentication. The supplied
// handler receives authenticated /api/ requests with their original paths.
// GET /api/session belongs to this wrapper and returns the current CSRF token.
func New(credentials Credentials, apiHandler http.Handler, logger *slog.Logger) (http.Handler, error) {
	return NewWithOptions(credentials, apiHandler, logger, Options{})
}

// NewWithOptions configures an explicitly trusted TLS-terminating proxy while
// retaining New's native HTTP/TLS behavior for all other requests.
func NewWithOptions(credentials Credentials, apiHandler http.Handler, logger *slog.Logger, options Options) (http.Handler, error) {
	origin, err := options.originPolicy()
	if err != nil {
		return nil, err
	}
	if err := credentials.Validate(); err != nil {
		return nil, err
	}
	if apiHandler == nil {
		return nil, errors.New("console API handler is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	for _, filename := range []string{"assets/login.html", "assets/index.html"} {
		if _, err := assets.ReadFile(filename); err != nil {
			return nil, err
		}
	}
	accounts, err := openAccountStore(options.AccountsPath, credentials)
	if err != nil {
		return nil, err
	}
	if options.OnAuthorizationLoader != nil {
		options.OnAuthorizationLoader(accounts.loadAuthorization)
	}
	return &server{
		credentials:     credentials,
		accounts:        accounts,
		api:             apiHandler,
		logger:          logger,
		now:             time.Now,
		limiter:         newLoginLimiter(),
		passwordLimiter: newLoginLimiter(),
		origin:          origin,
		siteExists:      options.SiteExists,
		// At most one expensive password verification per console. This also
		// bounds Argon2 memory when requests use many different source IPs.
		loginSlots: make(chan struct{}, 1),
	}, nil
}

func (s *server) Close() error { return s.accounts.db.Close() }

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	switch {
	case r.URL.Path == "/login":
		switch r.Method {
		case http.MethodGet:
			s.serveAsset(w, r, "login.html")
		case http.MethodPost:
			s.loginSubmit(w, r)
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/"):
		s.serveAPI(w, r)
	case r.URL.Path == "/logout":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		if _, ok := s.authenticate(w, r, true); !ok || !s.authorizeMutation(w, r) {
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookieName, Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: s.origin.secure(r), SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/assets/"):
		name := strings.TrimPrefix(r.URL.Path, "/assets/")
		switch name {
		case "app.css", "app.js", "model.js", "privilege.js", "fleet.js", "fleet.css", "remote-removal.js", "access-management.js", "removal-batches.js", "file-integrity.js", "host-boundary.js", "application-policies.js", "applied-policies.js", "policy-usage.js", "application-policies.css", "policy-editor.css", "policy.js", "policy-services.js", "policy-diff.js", "policy-trials.js", "service-inventory.js", "operations.js", "accounts.js", "accounts.css", "access.js", "theme.js", "theme.css", "history.js", "finding-reviews.js", "capability-editor.js", "updates.js", "updates.css", "updates-source.js", "central-update.js":
		default:
			http.NotFound(w, r)
			return
		}
		s.serveAsset(w, r, name)
	case r.URL.Path == "/":
		if _, ok := s.authenticate(w, r, false); ok {
			s.serveAsset(w, r, "index.html")
		}
	default:
		http.NotFound(w, r)
	}
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	// Chrome applies this policy to the Origin of ordinary form submissions.
	// no-referrer would turn legitimate same-origin login POSTs into Origin:null.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func (s *server) serveAsset(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if name == "" || path.Clean(name) != name || strings.Contains(name, "\\") {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	_, _ = w.Write(data)
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request, api bool) (Account, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		record, err := s.accounts.get(r.Context(), sessionUsername(cookie.Value))
		if err == nil {
			if _, err = record.credentials.VerifySession(cookie.Value, s.now()); err == nil {
				return record.Account, true
			}
		}
	}
	if api {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "로그인이 필요합니다. 다시 로그인해 주세요."})
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	return Account{}, false
}

func (s *server) serveAPI(w http.ResponseWriter, r *http.Request) {
	account, ok := s.authenticate(w, r, true)
	if !ok {
		return
	}
	if r.URL.Path == "/api/session" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		cookie, _ := r.Cookie(sessionCookieName)
		writeJSON(w, http.StatusOK, map[string]string{"username": account.Username, "role": string(accountDisplayRole(account)), "csrf_token": s.csrfToken(cookie.Value)})
		return
	}
	if r.URL.Path == "/api/session/permissions" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"permissions": account.permissionScopes(), "site_ids": account.SiteIDs()})
		return
	}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost, http.MethodDelete:
		if !s.authorizeMutation(w, r) {
			return
		}
	default:
		methodNotAllowed(w, "GET, POST, DELETE")
		return
	}
	_, accountGrants := accountGrantTarget(r.URL.Path)
	if accountGrants || r.URL.Path == "/api/rbac" || strings.HasPrefix(r.URL.Path, "/api/rbac/") {
		r.Body = http.MaxBytesReader(w, r.Body, maxAPIBody)
		s.serveRBAC(w, r, account)
		return
	}
	if r.URL.Path == "/api/account/password" || r.URL.Path == "/api/account-audit" || r.URL.Path == "/api/accounts" || strings.HasPrefix(r.URL.Path, "/api/accounts/") {
		r.Body = http.MaxBytesReader(w, r.Body, maxAPIBody)
		s.serveAccounts(w, r, account)
		return
	}
	if !allowsAccountAPI(account, r.Method, r.URL.Path) {
		denyAccountAccess(w)
		return
	}
	maximum := int64(maxAPIBody)
	if r.Method == http.MethodPost && (r.URL.Path == "/api/updates/releases" || r.URL.Path == "/api/central-update/upload") {
		maximum = managed.MaxUpdateArtifactBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maximum)
	r = r.WithContext(context.WithValue(r.Context(), accountContextKey{}, account))
	s.api.ServeHTTP(w, r)
}

func (s *server) authorizeMutation(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	token := r.Header.Get("X-CSRF-Token")
	if err != nil || len(token) != 43 || !hmac.Equal([]byte(token), []byte(s.csrfToken(cookie.Value))) || !s.origin.sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "요청을 확인할 수 없습니다. 페이지를 새로 고침한 후 다시 시도해 주세요."})
		return false
	}
	return true
}

func (s *server) csrfToken(session string) string {
	key, _ := base64.RawURLEncoding.DecodeString(s.credentials.SessionKey)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("central-console-csrf:" + session))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.origin.sameOrigin(r) {
		s.loginError(w, r, "origin")
		return
	}
	if !s.limiter.allow(remoteIP(r.RemoteAddr), s.now()) {
		w.Header().Set("Retry-After", "300")
		s.loginError(w, r, "rate")
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		s.loginError(w, r, "rate")
		return
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" {
		s.loginError(w, r, "request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if r.ParseForm() != nil || len(r.PostForm["username"]) != 1 || len(r.PostForm["password"]) != 1 {
		s.loginError(w, r, "request")
		return
	}
	record, accountErr := s.accounts.get(r.Context(), r.PostForm.Get("username"))
	credentials := s.credentials
	if accountErr == nil {
		credentials = record.credentials
	}
	valid := credentials.Verify(r.PostForm.Get("username"), r.PostForm.Get("password"))
	if accountErr != nil || !valid {
		s.loginError(w, r, "invalid")
		return
	}
	token, err := credentials.NewSession(s.now(), sessionLifetime)
	if err != nil {
		s.logger.Error("console session creation failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "로그인을 처리할 수 없습니다. 잠시 후 다시 시도해 주세요."})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/",
		MaxAge: int(sessionLifetime.Seconds()), Expires: s.now().Add(sessionLifetime),
		HttpOnly: true, Secure: s.origin.secure(r), SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) loginError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?error="+code, http.StatusSeeOther)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "허용되지 않은 요청 방식입니다."})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
