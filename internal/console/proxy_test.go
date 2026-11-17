package console

import (
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

func proxyTestServer(t *testing.T) (*server, *int) {
	t.Helper()
	calls := new(int)
	handler, err := NewWithOptions(testCredentials(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.WriteHeader(http.StatusOK)
	}), slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		PublicOrigin: "https://console.example", TrustedProxies: []string{"127.0.0.1/32", "::1/128"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := handler.(*server)
	s.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return s, calls
}

func proxyRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "http://console.example"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Set("Origin", "https://console.example")
	return r
}

func TestProxyLoginSessionCSRFAndLogout(t *testing.T) {
	s, calls := proxyTestServer(t)
	body := url.Values{"username": {"admin"}, "password": {"correct-horse-battery-staple"}}.Encode()
	r := proxyRequest(http.MethodPost, "/login", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("proxy login status=%d, location=%q", w.Code, w.Header().Get("Location"))
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("proxy login did not issue a secure session cookie")
	}
	cookie := cookies[0]
	r = proxyRequest(http.MethodGet, "/api/session", "")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var session map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || w.Code != http.StatusOK || session["username"] != "admin" || len(session["csrf_token"]) != 43 {
		t.Fatalf("proxy session status=%d, decode error=%v", w.Code, err)
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		r = proxyRequest(method, "/api/groups", "{}")
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", session["csrf_token"])
		w = httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("proxy %s mutation status=%d", method, w.Code)
		}
	}
	if *calls != 2 {
		t.Fatalf("proxy business API calls=%d, expected=2", *calls)
	}
	r = proxyRequest(http.MethodPost, "/logout", "")
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", session["csrf_token"])
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	cookies = w.Result().Cookies()
	if w.Code != http.StatusNoContent || len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure {
		t.Fatal("proxy logout did not securely clear the session cookie")
	}
}

func TestProxyRejectsUntrustedAndCrossOriginLoginAndMutations(t *testing.T) {
	for _, tc := range []struct {
		name, host, peer, origin, token string
	}{
		{"untrusted peer", "console.example", "192.0.2.1:4567", "https://console.example", "valid"},
		{"wrong host", "127.0.0.1:9089", "127.0.0.1:4567", "https://console.example", "valid"},
		{"foreign origin", "console.example", "127.0.0.1:4567", "https://evil.example", "valid"},
		{"wrong scheme", "console.example", "127.0.0.1:4567", "http://console.example", "valid"},
		{"wrong port", "console.example", "127.0.0.1:4567", "https://console.example:9089", "valid"},
		{"null origin", "console.example", "127.0.0.1:4567", "null", "valid"},
		{"missing origin", "console.example", "127.0.0.1:4567", "", "valid"},
		{"missing CSRF", "console.example", "127.0.0.1:4567", "https://console.example", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := proxyTestServer(t)
			cookie := testSession(t, s)
			for _, path := range []string{"/login", "/api/groups", "/logout"} {
				if path == "/login" && tc.name == "missing CSRF" {
					continue
				}
				r := proxyRequest(http.MethodPost, path, "username=admin&password=correct-horse-battery-staple")
				r.Host, r.RemoteAddr = tc.host, tc.peer
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("Forwarded", "for=127.0.0.1;proto=https;host=console.example")
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "console.example")
				r.Header.Set("X-Forwarded-For", "127.0.0.1")
				r.Header.Set("CF-Connecting-IP", "127.0.0.1")
				r.AddCookie(cookie)
				if tc.token != "" {
					r.Header.Set("X-CSRF-Token", s.csrfToken(cookie.Value))
				}
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if path == "/login" {
					if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?error=origin" {
						t.Fatalf("login accepted invalid proxy request: status=%d", w.Code)
					}
				} else if w.Code != http.StatusForbidden {
					t.Fatalf("%s status=%d, expected=403", path, w.Code)
				}
				if len(w.Result().Cookies()) != 0 {
					t.Fatalf("rejected %s issued cookies", path)
				}
			}
			if *calls != 0 {
				t.Fatal("rejected proxy mutation reached the business API")
			}
		})
	}
}

func TestConfiguredProxyPreservesDirectLocalLogin(t *testing.T) {
	s, _ := proxyTestServer(t)
	r := formRequest("username=admin&password=correct-horse-battery-staple")
	r.RemoteAddr = "127.0.0.1:4567"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	cookies := w.Result().Cookies()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || len(cookies) != 1 || cookies[0].Secure {
		t.Fatal("configured proxy changed direct local HTTP login")
	}
}
