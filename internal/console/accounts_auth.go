package console

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

type accountContextKey struct{}

// AuthenticatedAccount exposes only safe identity/role data to console APIs.
func AuthenticatedAccount(ctx context.Context) (Account, bool) {
	account, ok := ctx.Value(accountContextKey{}).(Account)
	return account, ok
}

func sessionUsername(token string) string {
	if len(token) > 2048 {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return ""
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(encoded) > 1024 {
		return ""
	}
	var payload sessionPayload
	if json.Unmarshal(encoded, &payload) != nil || validateUsername(payload.Username) != nil {
		return ""
	}
	return payload.Username
}

func allowsAPI(role Role, method, endpoint string) bool {
	if role == RoleAdmin {
		return true
	}
	if role != RoleOperator && role != RoleViewer {
		return false
	}
	partsTrial := strings.Split(endpoint, "/")
	if len(partsTrial) >= 3 && partsTrial[1] == "api" && partsTrial[2] == "policy-trials" {
		if method == http.MethodGet {
			return len(partsTrial) == 3 || len(partsTrial) == 4 && partsTrial[3] != ""
		}
		if role != RoleOperator || method != http.MethodPost {
			return false
		}
		return len(partsTrial) == 3 || len(partsTrial) == 5 && partsTrial[3] != "" && (partsTrial[4] == "report" || partsTrial[4] == "preview" || partsTrial[4] == "apply")
	}
	if method == http.MethodGet {
		if endpoint == "/api/updates/releases" || endpoint == "/api/updates/agents" || endpoint == "/api/updates/rollouts" || endpoint == "/api/updates/github/releases" {
			return true
		}
		parts := strings.Split(endpoint, "/")
		if len(parts) == 5 && parts[1] == "api" && parts[2] == "templates" && parts[3] != "" && parts[4] == "usage" {
			return true
		}
		if len(parts) == 5 && parts[1] == "api" && parts[2] == "updates" && parts[3] == "rollouts" && parts[4] != "" {
			return true
		}
		switch endpoint {
		case "/api/state", "/api/history", "/api/finding-reviews", "/api/audit", "/api/errors":
			return true
		}
		parts = strings.Split(endpoint, "/")
		return len(parts) == 5 && parts[1] == "api" && parts[2] == "agents" && parts[3] != "" && (parts[4] == "policy" || parts[4] == "integrity" || parts[4] == "service-inventory")
	}
	if role != RoleOperator {
		return false
	}
	if method == http.MethodPost {
		if endpoint == "/api/finding-reviews" {
			return true
		}
		if endpoint == "/api/updates/preview" || endpoint == "/api/updates/rollouts" {
			return true
		}
		parts := strings.Split(endpoint, "/")
		if len(parts) == 6 && parts[1] == "api" && parts[2] == "updates" && parts[3] == "rollouts" && parts[4] != "" && parts[5] == "cancel" {
			return true
		}
		switch endpoint {
		case "/api/groups", "/api/templates", "/api/deploy/preview", "/api/deploy", "/api/enrollment", "/api/removal", "/api/revoke":
			return true
		}
	}
	if method == http.MethodDelete {
		parts := strings.Split(endpoint, "/")
		return len(parts) == 4 && parts[1] == "api" && (parts[2] == "groups" || parts[2] == "templates") && parts[3] != ""
	}
	return false
}

func denyAccountAccess(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "현재 계정에는 이 작업을 수행할 권한이 없습니다."})
}
