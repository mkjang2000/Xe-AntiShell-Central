package console

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAccountCreationAndAdminResetApplyNewPasswordPolicy(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	admin := testSession(t, s)
	for _, item := range []struct {
		name, password string
		status         int
	}{{"eight", "Abc123!x", 201}, {"nine", "Abcd123!x", 201}, {"ten", "abcdef12!x", 201}, {"nine-no-upper", "abcde12!x", 400}, {"no-special", "abcdef1234", 400}, {"no-lower", "ABCDEF12!X", 400}} {
		response := accountRequest(t, s, admin, http.MethodPost, "/api/accounts", map[string]string{"username": item.name, "role": "viewer", "password": item.password}, true)
		if response.Code != item.status {
			t.Fatalf("account creation %s: status=%d", item.name, response.Code)
		}
		if item.status == 400 && !strings.Contains(response.Body.String(), PasswordPolicyMessage) {
			t.Fatal("API lost the current password guidance")
		}
	}
	record, err := s.accounts.get(context.Background(), "eight")
	if err != nil || !record.credentials.Verify("eight", "Abc123!x") {
		t.Fatal("short compliant password is not usable")
	}
	endpoint := "/api/accounts/eight/password"
	invalid := accountRequest(t, s, admin, http.MethodPost, endpoint, map[string]any{"password": "abcde12!x", "version": record.Version}, true)
	if invalid.Code != 400 {
		t.Fatal("admin reset skipped composition")
	}
	unchanged, _ := s.accounts.get(context.Background(), "eight")
	if unchanged.Version != record.Version || unchanged.credentials != record.credentials {
		t.Fatal("invalid reset changed stored credentials")
	}
	valid := accountRequest(t, s, admin, http.MethodPost, endpoint, map[string]any{"password": "abcdef12!x", "version": record.Version}, true)
	if valid.Code != 200 {
		t.Fatalf("compliant ten-character reset failed: %d", valid.Code)
	}
}

func TestLegacyCurrentPasswordCanChangeWithoutNewPolicyCheck(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	old := "legacy-password-fixture"
	credentials := legacyPasswordCredentials(t, "legacy", old)
	if _, err := s.accounts.mutate(context.Background(), "admin", "created", accountRecord{Account: Account{Username: "legacy", Role: RoleViewer}, credentials: credentials}, 0, s.now()); err != nil {
		t.Fatal(err)
	}
	token, err := credentials.NewSession(s.now(), sessionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: token}
	response := accountRequest(t, s, cookie, http.MethodPost, "/api/account/password", map[string]string{"current_password": old, "password": "Abc123!x"}, true)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"reauthenticate":true`) {
		t.Fatalf("legacy current password could not change: status=%d", response.Code)
	}
	updated, err := s.accounts.get(context.Background(), "legacy")
	if err != nil || !updated.credentials.Verify("legacy", "Abc123!x") || updated.credentials.Verify("legacy", old) {
		t.Fatal("legacy password replacement did not persist")
	}
	if next := accountRequest(t, s, cookie, http.MethodGet, "/api/session", nil, false); next.Code != http.StatusUnauthorized {
		t.Fatal("actual password change kept its old session")
	}
}
