package console

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) (*server, *int) {
	t.Helper()
	calls := new(int)
	handler, err := New(testCredentials(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		_, _ = w.Write([]byte("business API"))
	}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s := handler.(*server)
	s.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return s, calls
}

func testSession(t *testing.T, s *server) *http.Cookie {
	t.Helper()
	token, err := s.credentials.NewSession(s.now(), sessionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookieName, Value: token}
}

func formRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://localhost:9090")
	return r
}

func TestLoginPageAlwaysWorksWithPortForwardOrigins(t *testing.T) {
	s, _ := testServer(t)
	for _, origin := range []string{"", "null", "https://vscode-forward.example", "http://evil.example"} {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/login?next=https://evil.example", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("GET /login origin %q: status=%d", origin, w.Code)
		}
		for header, value := range map[string]string{
			"Cache-Control": "no-store", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "same-origin",
		} {
			if w.Header().Get(header) != value {
				t.Fatalf("%s=%q", header, w.Header().Get(header))
			}
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Fatalf("unsafe CSP: %q", csp)
		}
	}
}

func TestLoginCookieAndFixedRedirect(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "TLS"}[secure], func(t *testing.T) {
			s, _ := testServer(t)
			body := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple1!"}}.Encode()
			r := formRequest(body)
			r.URL.RawQuery = "next=https://evil.example"
			r.Header.Set("X-Forwarded-Proto", "https")
			if secure {
				r.TLS = &tls.ConnectionState{}
				r.Header.Set("Origin", "https://localhost:9090")
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
				t.Fatalf("login response: %d %q", w.Code, w.Header().Get("Location"))
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].Secure != secure ||
				cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].MaxAge != 8*60*60 || cookies[0].Path != "/" {
				t.Fatalf("session cookie: %#v", cookies)
			}
			if _, err := s.credentials.VerifySession(cookies[0].Value, s.now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoginRejectsMalformedAndCrossOriginInput(t *testing.T) {
	for _, tc := range []struct {
		name, body, origin, code string
	}{
		{"wrong password", "username=admin&password=wrong-password-value", "http://localhost:9090", "invalid"},
		{"duplicate field", "username=admin&username=admin&password=wrong", "http://localhost:9090", "request"},
		{"oversized form", "username=admin&password=" + strings.Repeat("a", maxLoginBody), "http://localhost:9090", "request"},
		{"opaque origin", "username=admin&password=wrong", "null", "origin"},
		{"foreign origin", "username=admin&password=wrong", "http://evil.example", "origin"},
		{"wrong port", "username=admin&password=wrong", "http://localhost:9091", "origin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := testServer(t)
			r := formRequest(tc.body)
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?error="+tc.code || len(w.Result().Cookies()) != 0 {
				t.Fatalf("rejection: status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
		})
	}
}

func TestAllAPIRoutesRequireAuthentication(t *testing.T) {
	s, calls := testServer(t)
	for _, endpoint := range []string{"/api", "/api/session", "/api/state", "/api/unknown", "/api//state", "/api/../api/state", "/api%2fstate"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(method, "http://127.0.0.1:9090"+endpoint, nil))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s: status=%d", method, endpoint, w.Code)
			}
		}
	}
	if *calls != 0 {
		t.Fatal("unauthenticated request reached API")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatal("unauthenticated dashboard did not redirect to login")
	}
}

func TestSessionAndMutationCSRF(t *testing.T) {
	s, calls := testServer(t)
	cookie := testSession(t, s)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/api/session", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var session map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || w.Code != http.StatusOK ||
		session["username"] != "admin" || len(session["csrf_token"]) != 43 || *calls != 0 {
		t.Fatalf("session response: status=%d body=%s err=%v", w.Code, w.Body, err)
	}
	otherSession := testSession(t, s)
	for _, tc := range []struct {
		name, token, origin string
		cookie              *http.Cookie
		status              int
	}{
		{"missing CSRF", "", "http://localhost:9090", cookie, http.StatusForbidden},
		{"invalid CSRF", strings.Repeat("a", 43), "http://localhost:9090", cookie, http.StatusForbidden},
		{"different session", session["csrf_token"], "http://localhost:9090", otherSession, http.StatusForbidden},
		{"cross origin", session["csrf_token"], "http://evil.example:9090", cookie, http.StatusForbidden},
		{"null origin", session["csrf_token"], "null", cookie, http.StatusForbidden},
		{"no origin", session["csrf_token"], "", cookie, http.StatusForbidden},
		{"valid loopback alias", session["csrf_token"], "http://[::1]:9090", cookie, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/api/groups", strings.NewReader("{}"))
			request.AddCookie(tc.cookie)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("X-CSRF-Token", tc.token)
			response := httptest.NewRecorder()
			s.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("mutation status=%d expected=%d", response.Code, tc.status)
			}
		})
	}
	if *calls != 1 {
		t.Fatalf("business mutations=%d expected=1", *calls)
	}
	for _, token := range []string{"", session["csrf_token"]} {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/logout", nil)
		request.AddCookie(cookie)
		request.Header.Set("Origin", "http://localhost:9090")
		request.Header.Set("X-CSRF-Token", token)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, request)
		if token == "" && response.Code != http.StatusForbidden {
			t.Fatal("logout without CSRF was accepted")
		}
		if token != "" && (response.Code != http.StatusNoContent || len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].MaxAge != -1) {
			t.Fatal("valid logout did not clear session")
		}
	}
}

func TestMethodsAndAPIBodyLimit(t *testing.T) {
	s, _ := testServer(t)
	cookie := testSession(t, s)
	for _, endpoint := range []string{"/login", "/logout", "/api/session", "/api/state", "/assets/app.js", "/"} {
		r := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:9090"+endpoint, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") == "" {
			t.Fatalf("PUT %s: status=%d allow=%q", endpoint, w.Code, w.Header().Get("Allow"))
		}
	}
	s.api = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		t.Error("unbounded API body reached handler")
	})
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/api/groups", strings.NewReader(strings.Repeat("x", maxAPIBody+1)))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://localhost:9090")
	r.Header.Set("X-CSRF-Token", s.csrfToken(cookie.Value))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized API body: status=%d", w.Code)
	}
}

func TestAssetsCannotExposeEmbeddedHTMLOrDevelopmentFiles(t *testing.T) {
	s, _ := testServer(t)
	for _, endpoint := range []string{
		"/assets/index.html", "/assets/login.html", "/assets/app.test.mjs",
		"/assets/../auth.go", "/assets/./app.js", "/assets/", "/assets/missing.js",
	} {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090"+endpoint, nil)
		r.AddCookie(testSession(t, s))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("asset %s: status=%d", endpoint, w.Code)
		}
	}
}

func TestLoginRateLimitsAndArgonConcurrency(t *testing.T) {
	s, _ := testServer(t)
	for i := 0; i <= loginIPLimit; i++ {
		r := formRequest("username=admin&password=wrong-password-value")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		want := "/login?error=invalid"
		if i == loginIPLimit {
			want = "/login?error=rate"
		}
		if w.Header().Get("Location") != want {
			t.Fatalf("attempt %d: %q", i, w.Header().Get("Location"))
		}
	}
	s.loginSlots <- struct{}{}
	defer func() { <-s.loginSlots }()
	r := formRequest("username=admin&password=correct-horse-battery-staple1!")
	r.RemoteAddr = "192.0.2.2:1234"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Header().Get("Location") != "/login?error=rate" || len(w.Result().Cookies()) != 0 {
		t.Fatal("busy Argon slot did not reject concurrent login")
	}
}
