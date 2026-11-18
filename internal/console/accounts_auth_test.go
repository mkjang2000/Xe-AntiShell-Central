package console

import (
	"net/http"
	"testing"
)

func TestFileIntegrityReadRole(t *testing.T) {
	for _, role := range []Role{RoleOperator, RoleViewer} {
		if !allowsAPI(role, http.MethodGet, "/api/agents/host/integrity") || allowsAPI(role, http.MethodPost, "/api/agents/host/integrity") {
			t.Fatal(role)
		}
	}
	if allowsAPI(RoleViewer, http.MethodPost, "/api/templates") || allowsAPI(RoleViewer, http.MethodPost, "/api/deploy") {
		t.Fatal("viewer can change file baselines")
	}
}
