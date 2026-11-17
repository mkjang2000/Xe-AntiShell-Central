package console

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpdateRolesAndStreamingBodyLimit(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	admin := testSession(t, s)
	_, operator := accountFixture(t, s, "update-operator", RoleOperator)
	_, viewer := accountFixture(t, s, "update-viewer", RoleViewer)
	for _, route := range []struct {
		method, path string
		adminOnly    bool
	}{
		{"POST", "/api/updates/releases", true}, {"POST", "/api/updates/releases/digest/delete", true}, {"POST", "/api/updates/github/import", true},
		{"POST", "/api/updates/preview", false}, {"POST", "/api/updates/rollouts", false}, {"POST", "/api/updates/rollouts/rollout-a/cancel", false},
	} {
		for _, role := range []struct {
			cookie *http.Cookie
			want   int
		}{{admin, 200}, {operator, 200}, {viewer, 403}} {
			want := role.want
			if route.adminOnly && role.cookie == operator {
				want = 403
			}
			if response := accountRequest(t, s, role.cookie, route.method, route.path, map[string]any{}, true); response.Code != want {
				t.Fatalf("%s status %d want %d", route.path, response.Code, want)
			}
		}
	}
	for _, path := range []string{"/api/updates/releases", "/api/updates/agents", "/api/updates/rollouts", "/api/updates/rollouts/rollout-a", "/api/updates/github/releases"} {
		for _, cookie := range []*http.Cookie{admin, operator, viewer} {
			if response := accountRequest(t, s, cookie, "GET", path, nil, false); response.Code != 200 {
				t.Fatalf("read %s denied: %d", path, response.Code)
			}
		}
	}
	called := 0
	s.api = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if _, ok := AuthenticatedAccount(r.Context()); !ok {
			t.Error("missing authenticated context")
		}
		_, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			w.WriteHeader(413)
			return
		}
		w.WriteHeader(200)
	})
	request := func(path string, cookie *http.Cookie, csrf bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:9090"+path, strings.NewReader(strings.Repeat("x", 2<<20)))
		r.Header.Set("Origin", "http://localhost:9090")
		r.Header.Set("Content-Type", "application/x-rpm")
		if cookie != nil {
			r.AddCookie(cookie)
			if csrf {
				r.Header.Set("X-CSRF-Token", s.csrfToken(cookie.Value))
			}
		}
		response := httptest.NewRecorder()
		s.ServeHTTP(response, r)
		return response
	}
	if response := request("/api/updates/releases", admin, true); response.Code != 200 {
		t.Fatal("RPM upload retained nested 1MiB JSON cap")
	}
	if response := request("/api/groups", admin, true); response.Code != 413 {
		t.Fatal("ordinary JSON cap was raised")
	}
	if response := request("/api/updates/github/import", admin, true); response.Code != 413 {
		t.Fatal("GitHub import bypassed ordinary JSON cap")
	}
	before := called
	if response := request("/api/updates/releases", operator, true); response.Code != 403 {
		t.Fatal("operator upload reached backend")
	}
	if response := request("/api/updates/releases", admin, false); response.Code != 403 {
		t.Fatal("upload bypassed CSRF")
	}
	if response := request("/api/updates/releases", nil, false); response.Code != 401 {
		t.Fatal("anonymous upload reached backend")
	}
	if called != before {
		t.Fatal("unauthorized large request reached body reader")
	}
}
