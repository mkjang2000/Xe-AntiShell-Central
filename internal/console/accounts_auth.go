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
	return allowsAccountAPI(Account{Role: role}, method, endpoint)
}

func allowsAccountAPI(account Account, method, endpoint string) bool {
	if endpoint == "/api/sites" && method == http.MethodGet {
		// The site endpoint filters its list to effective grants. An authenticated
		// account without grants still receives an empty catalog.
		return account.Role.valid() || account.ExplicitGrants
	}
	if endpoint == "/api/state" && method == http.MethodGet {
		return len(account.StateScopes()) != 0
	}
	permission, known := RoutePermission(method, endpoint)
	return known && account.Has(permission)
}

func denyAccountAccess(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "현재 계정에는 이 작업을 수행할 권한이 없습니다."})
}
