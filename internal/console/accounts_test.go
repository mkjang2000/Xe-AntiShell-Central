package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func accountRequest(t *testing.T, s *server, cookie *http.Cookie, method, endpoint string, body any, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:9090"+endpoint, strings.NewReader(string(encoded)))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://localhost:9090")
	if csrf {
		r.Header.Set("X-CSRF-Token", s.csrfToken(cookie.Value))
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func accountFixture(t *testing.T, s *server, username string, role Role) (accountRecord, *http.Cookie) {
	t.Helper()
	credentials, err := GenerateCredentials(username, "account-password-fixture1!", s.credentials.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.accounts.mutate(context.Background(), "admin", "created", accountRecord{Account: Account{Username: username, Role: role}, credentials: credentials}, 0, s.now()); err != nil {
		t.Fatal(err)
	}
	record, err := s.accounts.get(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	token, err := credentials.NewSession(s.now(), sessionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	return record, &http.Cookie{Name: sessionCookieName, Value: token}
}

func TestConsoleRolesEnforceEveryBusinessAPI(t *testing.T) {
	s, calls := testServer(t)
	defer s.Close()
	_, operator := accountFixture(t, s, "operator", RoleOperator)
	_, viewer := accountFixture(t, s, "viewer", RoleViewer)
	for _, endpoint := range []string{"/api/state", "/api/history", "/api/audit", "/api/errors", "/api/agents/example/policy"} {
		for _, cookie := range []*http.Cookie{viewer, operator} {
			if w := accountRequest(t, s, cookie, "GET", endpoint, nil, false); w.Code != 200 {
				t.Fatalf("read %s: %d", endpoint, w.Code)
			}
		}
	}
	for _, route := range []struct{ method, endpoint string }{
		{"POST", "/api/groups"}, {"DELETE", "/api/groups/example"}, {"POST", "/api/templates"}, {"DELETE", "/api/templates/example"},
		{"POST", "/api/deploy/preview"}, {"POST", "/api/deploy"}, {"POST", "/api/enrollment"}, {"POST", "/api/removal"}, {"POST", "/api/revoke"},
	} {
		before := *calls
		if w := accountRequest(t, s, viewer, route.method, route.endpoint, map[string]string{}, true); w.Code != 403 {
			t.Fatalf("viewer %s: %d", route.endpoint, w.Code)
		}
		if *calls != before {
			t.Fatal("viewer mutation reached the business API")
		}
		if w := accountRequest(t, s, operator, route.method, route.endpoint, map[string]string{}, true); w.Code != 200 {
			t.Fatalf("operator %s: %d", route.endpoint, w.Code)
		}
	}
	for _, cookie := range []*http.Cookie{viewer, operator} {
		for _, endpoint := range []string{"/api/accounts", "/api/account-audit", "/api/future-token", "/api/agents/example/token"} {
			if w := accountRequest(t, s, cookie, "GET", endpoint, nil, false); w.Code != 403 {
				t.Fatalf("restricted read %s: %d", endpoint, w.Code)
			}
		}
		for _, route := range []struct{ method, endpoint string }{
			{"GET", "/api/agents/example/remote-removal"},
			{"POST", "/api/agents/example/remote-removal"},
			{"POST", "/api/agents/example/remote-removal/cancel"},
		} {
			if w := accountRequest(t, s, cookie, route.method, route.endpoint, map[string]string{}, true); w.Code != 403 {
				t.Fatalf("restricted remote removal route %s: %d", route.endpoint, w.Code)
			}
		}
		if w := accountRequest(t, s, cookie, "POST", "/api/accounts", map[string]string{"username": "intruder", "password": "account-password-fixture1!", "role": "admin"}, true); w.Code != 403 {
			t.Fatalf("account escalation: %d", w.Code)
		}
	}
	s.api = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account, ok := AuthenticatedAccount(r.Context())
		if !ok || account.Username != "viewer" || account.Role != RoleViewer {
			t.Error("API did not receive authenticated identity")
		}
	})
	accountRequest(t, s, viewer, "GET", "/api/state", nil, false)
}

func TestAccountMutationsRequireCSRFAndProtectLastAdmin(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	admin := testSession(t, s)
	for _, route := range []struct {
		method, endpoint string
		body             any
	}{
		{"POST", "/api/agents/example/remote-removal", map[string]string{"enrollment_id": "example-enrollment", "confirmation": "example"}},
		{"POST", "/api/agents/example/remote-removal/cancel", map[string]string{"enrollment_id": "example-enrollment", "order_id": "removal-example"}},
		{"POST", "/api/accounts", map[string]string{"username": "created", "password": "account-password-fixture1!", "role": "viewer"}},
		{"POST", "/api/accounts/admin", map[string]any{"role": "viewer", "version": 1}},
		{"DELETE", "/api/accounts/admin?version=1", nil},
		{"POST", "/api/account/password", map[string]string{"current_password": "correct-horse-battery-staple1!", "password": "new-account-password-fixture1!"}},
	} {
		if w := accountRequest(t, s, admin, route.method, route.endpoint, route.body, false); w.Code != 403 {
			t.Fatalf("CSRF bypass %s: %d", route.endpoint, w.Code)
		}
	}
	for _, route := range []struct {
		method, endpoint string
		body             any
	}{
		{"POST", "/api/accounts/admin", map[string]any{"role": "operator", "version": 1}},
		{"DELETE", "/api/accounts/admin?version=1", nil},
	} {
		if w := accountRequest(t, s, admin, route.method, route.endpoint, route.body, true); w.Code != 409 {
			t.Fatalf("last admin protection %s: %d", route.endpoint, w.Code)
		}
	}
	if w := accountRequest(t, s, admin, "GET", "/api/session", nil, false); w.Code != 200 {
		t.Fatal("rejected changes invalidated the administrator")
	}
}

func TestAccountRolePasswordAndDeletionInvalidateAllSessions(t *testing.T) {
	for _, operation := range []string{"role", "password", "delete"} {
		t.Run(operation, func(t *testing.T) {
			s, _ := testServer(t)
			defer s.Close()
			record, cookie := accountFixture(t, s, "member", RoleOperator)
			secondToken, _ := record.credentials.NewSession(s.now(), sessionLifetime)
			second := &http.Cookie{Name: sessionCookieName, Value: secondToken}
			admin := testSession(t, s)
			method, endpoint, body := "POST", "/api/accounts/member", any(map[string]any{"role": "viewer", "version": record.Version})
			if operation == "password" {
				endpoint += "/password"
				body = map[string]any{"password": "new-account-password-fixture1!", "version": record.Version}
			}
			if operation == "delete" {
				method = "DELETE"
				endpoint += "?version=1"
				body = nil
			}
			if w := accountRequest(t, s, admin, method, endpoint, body, true); w.Code != 200 {
				t.Fatalf("mutation: %d %s", w.Code, w.Body)
			}
			for _, old := range []*http.Cookie{cookie, second} {
				if w := accountRequest(t, s, old, "GET", "/api/session", nil, false); w.Code != 401 {
					t.Fatalf("old session survived %s: %d", operation, w.Code)
				}
			}
			w := accountRequest(t, s, admin, "GET", "/api/account-audit", nil, false)
			if w.Code != 200 || !strings.Contains(w.Body.String(), "member") || strings.Contains(w.Body.String(), "password-fixture") || strings.Contains(w.Body.String(), "session_key") {
				t.Fatalf("unsafe/missing audit: %s", w.Body)
			}
		})
	}
}

func TestOwnPasswordRequiresCurrentValueAndRateLimitsAttempts(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	_, viewer := accountFixture(t, s, "viewer", RoleViewer)
	request := map[string]string{"current_password": "wrong-password-fixture", "password": "new-account-password-fixture1!"}
	for attempt := 0; attempt < loginIPLimit; attempt++ {
		if w := accountRequest(t, s, viewer, "POST", "/api/account/password", request, true); w.Code != 403 {
			t.Fatalf("incorrect current password: %d", w.Code)
		}
	}
	request["current_password"] = "account-password-fixture1!"
	if w := accountRequest(t, s, viewer, "POST", "/api/account/password", request, true); w.Code != 429 || w.Header().Get("Retry-After") != "300" {
		t.Fatal("password guessing was not bounded")
	}
	now := s.now().Add(loginWindow)
	s.now = func() time.Time { return now }
	if w := accountRequest(t, s, viewer, "POST", "/api/account/password", request, true); w.Code != 200 || !strings.Contains(w.Body.String(), `"reauthenticate":true`) || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("own password change: %d %s", w.Code, w.Body)
	}
	if w := accountRequest(t, s, viewer, "GET", "/api/session", nil, false); w.Code != 401 {
		t.Fatal("own password change kept the old session")
	}
	body := url.Values{"username": {"viewer"}, "password": {"new-account-password-fixture1!"}}.Encode()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, formRequest(body))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" || len(w.Result().Cookies()) != 1 {
		t.Fatal("new password was not usable")
	}
}

func TestAccountCreationAndAuditNamedAccountRemainManageable(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	admin := testSession(t, s)
	request := map[string]string{"username": "audit", "password": "account-password-fixture1!", "role": "viewer"}
	w := accountRequest(t, s, admin, "POST", "/api/accounts", request, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("create audit account: %d %s", w.Code, w.Body)
	}
	if w = accountRequest(t, s, admin, "POST", "/api/accounts", request, true); w.Code != 409 {
		t.Fatal("duplicate account was accepted")
	}
	for _, role := range []string{"superuser", "", "ADMIN"} {
		request["role"] = role
		request["username"] = "invalid-role"
		if w = accountRequest(t, s, admin, "POST", "/api/accounts", request, true); w.Code != 400 {
			t.Fatalf("invalid role %q: %d", role, w.Code)
		}
	}
	if w = accountRequest(t, s, admin, "POST", "/api/accounts/audit", map[string]any{"role": "operator", "version": 1}, true); w.Code != 200 {
		t.Fatalf("audit username role route conflicted: %d %s", w.Code, w.Body)
	}
	w = accountRequest(t, s, admin, "GET", "/api/accounts", nil, false)
	record, err := s.accounts.get(context.Background(), "audit")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password_hash", "session_key", record.credentials.Hash, record.credentials.SessionKey, "account-password-fixture1!"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("account list exposed credential material")
		}
	}
	if w = accountRequest(t, s, admin, "DELETE", "/api/accounts/audit?version=2", nil, true); w.Code != 200 {
		t.Fatalf("audit username deletion route conflicted: %d %s", w.Code, w.Body)
	}
	w = accountRequest(t, s, admin, "GET", "/api/account-audit", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"created_at"`) || strings.Contains(w.Body.String(), "created_at_ns") {
		t.Fatalf("account audit route/time: %d %s", w.Code, w.Body)
	}
}

func TestLegacyAuditUsernameRetainsAdministratorProtection(t *testing.T) {
	credentials, err := GenerateCredentials("audit", "account-password-fixture1!", testCredentials(t).Parameters)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(credentials, http.NotFoundHandler(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := handler.(*server)
	defer s.Close()
	token, err := credentials.NewSession(s.now(), sessionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: token}
	if w := accountRequest(t, s, cookie, "POST", "/api/accounts/audit", map[string]any{"role": "viewer", "version": 1}, true); w.Code != 409 {
		t.Fatalf("legacy audit administrator route: %d", w.Code)
	}
	if w := accountRequest(t, s, cookie, "DELETE", "/api/accounts/audit?version=1", nil, true); w.Code != 409 {
		t.Fatalf("legacy audit administrator deletion: %d", w.Code)
	}
}
