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

func TestServiceInventoryReadRole(t *testing.T) {
	path := "/api/agents/host/service-inventory"
	for _, role := range []Role{RoleOperator, RoleViewer} {
		if !allowsAPI(role, http.MethodGet, path) || allowsAPI(role, http.MethodPost, path) {
			t.Fatal(role)
		}
	}
	if allowsAPI("", http.MethodGet, path) || allowsAPI(RoleViewer, http.MethodGet, path+"/other") {
		t.Fatal("service inventory read bypassed account or route limits")
	}
}
