package central

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (f *fixture) siteConsole(t *testing.T, siteID, method, path string, input any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	ctx := context.WithValue(request.Context(), siteContextKey{}, siteID)
	f.server.ConsoleHandler().ServeHTTP(response, request.WithContext(ctx))
	return response
}

func recordSiteFinding(t *testing.T, f *fixture, agentID, findingID string) {
	t.Helper()
	ctx := context.Background()
	payload, err := json.Marshal(map[string]string{"finding_id": findingID})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	record := managed.Record{Kind: managed.RecordKindFinding, ID: findingID}
	if err := persistHistoryRecord(ctx, tx, agentID, record, payload, sha256.Sum256(payload), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestSiteTransferPreservesOriginalHistoryAndInvalidatesCrossSiteTargets(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	agent, _, _ := f.enroll(t, "site-host")
	f.enroll(t, "other-host")
	if siteID, err := agentSite(ctx, f.store.db, agent.AgentID); err != nil || siteID != defaultSiteID {
		t.Fatalf("legacy default site=%s err=%v", siteID, err)
	}
	if _, err := f.store.saveSite(ctx, site{ID: "branch", Name: "Branch"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	f.consoleDrafts(t, []string{agent.AgentID})
	recordSiteFinding(t, f, agent.AgentID, "finding-before")
	scoped := func(siteID, method, path string, body any) *httptest.ResponseRecorder {
		return f.siteConsole(t, siteID, method, path, body)
	}
	var preview struct {
		Token string `json:"preview_token"`
	}
	consoleWant(t, scoped(defaultSiteID, "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "default", GroupIDs: []string{"web"}}), 200, &preview)
	if err := f.store.moveAgentSite(ctx, agent.AgentID, "stale", "branch", "admin", time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale enrollment moved: %v", err)
	}
	if err := f.store.moveAgentSite(ctx, agent.AgentID, agent.EnrollmentID, "branch", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	recordSiteFinding(t, f, agent.AgentID, "finding-after")
	for siteID, want := range map[string]string{defaultSiteID: "finding-before", "branch": "finding-after"} {
		for _, path := range []string{"/api/history?view=detections", "/api/history?kind=detections"} {
			var rows []HistoryRecord
			consoleWant(t, scoped(siteID, "GET", path, nil), http.StatusOK, &rows)
			if len(rows) != 1 || rows[0].ID != want {
				t.Fatalf("site %s history mismatch: %+v", siteID, rows)
			}
		}
	}
	var state struct {
		Agents []Agent        `json:"agents"`
		Groups []ConsoleGroup `json:"groups"`
	}
	consoleWant(t, scoped(defaultSiteID, "GET", "/api/state", nil), 200, &state)
	if len(state.Agents) != 1 || state.Agents[0].ID != "other-host" || len(state.Groups) != 1 || len(state.Groups[0].AgentIDs) != 0 {
		t.Fatalf("site A selection exposed moved agent: %+v", state)
	}
	consoleWant(t, scoped("branch", "GET", "/api/state", nil), 200, &state)
	if len(state.Agents) != 1 || state.Agents[0].ID != agent.AgentID || len(state.Groups) != 0 {
		t.Fatalf("site B selection incorrect: %+v", state)
	}
	consoleWant(t, scoped(defaultSiteID, "POST", "/api/deploy", map[string]any{"confirm": true, "preview_token": preview.Token}), http.StatusConflict, nil)
	consoleWant(t, scoped("branch", "POST", "/api/deploy", map[string]any{"confirm": true, "preview_token": preview.Token}), http.StatusConflict, nil)
	consoleWant(t, scoped("branch", "POST", "/api/deploy/preview", consolePreviewRequest{TemplateID: "default", AgentIDs: []string{"other-host"}}), http.StatusNotFound, nil)
	consoleWant(t, scoped("branch", "DELETE", "/api/groups/web?version=2", nil), http.StatusNotFound, nil)
	consoleWant(t, scoped("branch", "POST", "/api/groups", ConsoleGroup{ID: "other", SiteID: "branch", Name: "Other", AgentIDs: []string{"other-host"}}), http.StatusBadRequest, nil)
	consoleWant(t, scoped(defaultSiteID, "POST", "/api/revoke", map[string]any{"agent_id": agent.AgentID, "confirm": true}), http.StatusNotFound, nil)
}

func TestSiteEnrollmentTokenBindsSiteAndCannotReplaceForeignAgent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.store.saveSite(ctx, site{ID: "east", Name: "East"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	var issued struct {
		Token string `json:"token"`
		Site  string `json:"site_id"`
	}
	consoleWant(t, f.siteConsole(t, "east", "POST", "/api/enrollment", map[string]any{"agent_id": "fresh"}), http.StatusCreated, &issued)
	if issued.Site != "east" || issued.Token == "" {
		t.Fatalf("wrong site enrollment issuance: %+v", issued)
	}
	req, _ := csr(t, "fresh")
	enrollment, _, err := f.store.Enroll(ctx, issued.Token, "fresh", req, f.material, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if siteID, err := agentSite(ctx, f.store.db, "fresh"); err != nil || siteID != "east" {
		t.Fatalf("agent attached to %q err=%v", siteID, err)
	}
	consoleWant(t, f.siteConsole(t, defaultSiteID, "POST", "/api/enrollment", map[string]any{"agent_id": "fresh"}), http.StatusNotFound, nil)
	next := f.token(t, "fresh")
	if err := f.store.moveAgentSite(ctx, "fresh", enrollment, defaultSiteID, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Enroll(ctx, next, "fresh", req, f.material, time.Now()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pre-move token accepted: %v", err)
	}
}

func siteBrowser(t *testing.T, f *fixture) func(username, password string) func(siteID, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	pass := "synthetic-site-password1!"
	credentials, err := console.GenerateCredentials("admin", pass, console.Argon2Parameters{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := console.NewWithOptions(credentials, f.server.ConsoleHandler(), nil, console.Options{
		AccountsPath: filepath.Join(f.directory, "site-accounts.db"), SiteExists: f.store.SiteExists,
	})
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := handler.(interface{ Close() error }); ok {
		t.Cleanup(func() { closer.Close() })
	}
	login := func(username, password string) func(siteID, method, path string, body any) *httptest.ResponseRecorder {
		const base = "http://localhost:9089"
		req := httptest.NewRequest("POST", base+"/login", strings.NewReader(url.Values{"username": {username}, "password": {password}}.Encode()))
		req.Header.Set("Origin", base)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		var cookie *http.Cookie
		for _, item := range response.Result().Cookies() {
			if item.Name == "xeas_central_session" {
				cookie = item
			}
		}
		if cookie == nil {
			t.Fatalf("login response: %d", response.Code)
		}
		req = httptest.NewRequest("GET", base+"/api/session", nil)
		req.AddCookie(cookie)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		var session struct {
			CSRF string `json:"csrf_token"`
		}
		consoleWant(t, response, 200, &session)
		if session.CSRF == "" {
			t.Fatal("missing CSRF token")
		}
		return func(siteID, method, path string, body any) *httptest.ResponseRecorder {
			t.Helper()
			input, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(method, base+path, bytes.NewReader(input))
			req.AddCookie(cookie)
			req.Header.Set("Origin", base)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", session.CSRF)
			if siteID != "" {
				req.Header.Set(siteHeader, siteID)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			return response
		}
	}
	return login
}

func TestSiteFleetPermissionDoesNotExposeGroupOrTemplateContents(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.enroll(t, "default-only")
	other, _, _ := f.enroll(t, "east-only")
	if _, err := f.store.saveSite(ctx, site{ID: "east", Name: "East"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.moveAgentSite(ctx, other.AgentID, other.EnrollmentID, "east", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	f.consoleDrafts(t, []string{"default-only"})
	login := siteBrowser(t, f)
	admin := login("admin", "synthetic-site-password1!")
	consoleWant(t, admin("*", "POST", "/api/rbac/roles", map[string]any{
		"id": "fleet-read", "name": "Fleet Read", "permissions": []string{"agents.read"},
	}), 201, nil)
	const localPassword = "synthetic-site-user1!"
	consoleWant(t, admin("*", "POST", "/api/accounts", map[string]any{
		"username": "site-reader", "password": localPassword,
		"grants": []map[string]string{{"role_id": "fleet-read", "site_id": defaultSiteID}},
	}), 201, nil)
	reader := login("site-reader", localPassword)
	var result struct {
		Agents    []Agent           `json:"agents"`
		Groups    []ConsoleGroup    `json:"groups"`
		Templates []ConsoleTemplate `json:"templates"`
	}
	consoleWant(t, reader(defaultSiteID, "GET", "/api/state", nil), 200, &result)
	if len(result.Agents) != 1 || result.Agents[0].ID != "default-only" || len(result.Groups) != 0 || len(result.Templates) != 0 {
		t.Fatalf("fleet-only role visible contents: %+v", result)
	}
	consoleWant(t, reader("east", "GET", "/api/state", nil), 403, nil)
	consoleWant(t, reader("*", "GET", "/api/state", nil), 403, nil)
	var sites struct {
		Items  []site `json:"sites"`
		Global bool   `json:"global"`
	}
	consoleWant(t, reader("", "GET", "/api/sites", nil), 200, &sites)
	if sites.Global || len(sites.Items) != 1 || sites.Items[0].ID != defaultSiteID {
		t.Fatalf("site roster did not filter: %+v", sites)
	}
	consoleWant(t, reader(defaultSiteID, "GET", "/api/agents/east-only/integrity", nil), 404, nil)
	consoleWant(t, reader(defaultSiteID, "GET", "/api/agents/default-only/policy", nil), 403, nil)
	for _, domain := range []struct {
		name, permission  string
		groups, templates int
	}{
		{"group-reader", "groups.read", 1, 0},
		{"policy-reader", "policies.read", 0, 1},
	} {
		consoleWant(t, admin("*", "POST", "/api/rbac/roles", map[string]any{
			"id": domain.name, "name": domain.name, "permissions": []string{domain.permission},
		}), 201, nil)
		const domainPassword = "synthetic-domain-user1!"
		consoleWant(t, admin("*", "POST", "/api/accounts", map[string]any{
			"username": domain.name, "password": domainPassword,
			"grants": []map[string]string{{"role_id": domain.name, "site_id": defaultSiteID}},
		}), 201, nil)
		domainReader := login(domain.name, domainPassword)
		var read struct {
			Agents    []Agent           `json:"agents"`
			Total     int               `json:"total_agents"`
			Groups    []ConsoleGroup    `json:"groups"`
			Templates []ConsoleTemplate `json:"templates"`
		}
		consoleWant(t, domainReader(defaultSiteID, "GET", "/api/state", nil), 200, &read)
		if len(read.Agents) != 0 || read.Total != 0 || len(read.Groups) != domain.groups || len(read.Templates) != domain.templates {
			t.Fatalf("%s scopes exposed mismatched sections: %+v", domain.name, read)
		}
		consoleWant(t, domainReader(defaultSiteID, "GET", "/api/agents/default-only/integrity", nil), 403, nil)
		consoleWant(t, domainReader("east", "GET", "/api/state", nil), 403, nil)
	}
	consoleWant(t, admin(defaultSiteID, "GET", "/api/state", nil), 200, &result)
	if len(result.Groups) != 1 || len(result.Templates) != 1 {
		t.Fatalf("privileged account lost group/template access: %+v", result)
	}
}

func TestSiteUpdatePreviewRolloutAndCancellationAreScoped(t *testing.T) {
	f := updateFixture(t)
	ctx := context.Background()
	release := f.updateRelease(t, 24)
	own, _ := f.updateInventory(t, "first", 23)
	foreign, _ := f.updateInventory(t, "second", 23)
	if _, err := f.store.saveSite(ctx, site{ID: "foreign", Name: "Foreign"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.moveAgentSite(ctx, foreign.ID, foreign.EnrollmentID, "foreign", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	login := siteBrowser(t, f)
	browser := login("admin", "synthetic-site-password1!")
	var agents struct {
		Items []ConsoleUpdateAgent `json:"items"`
		Total int                  `json:"total"`
	}
	consoleWant(t, browser(defaultSiteID, "GET", "/api/updates/agents", nil), 200, &agents)
	if agents.Total != 1 || len(agents.Items) != 1 || agents.Items[0].AgentID != own.ID {
		t.Fatalf("update inventory leaked across sites: %+v", agents)
	}
	consoleWant(t, browser(defaultSiteID, "POST", "/api/updates/preview", ConsoleUpdateRequest{ReleaseID: release.ID, AgentIDs: []string{foreign.ID}}), 404, nil)
	var preview struct {
		Token string `json:"preview_token"`
	}
	consoleWant(t, browser(defaultSiteID, "POST", "/api/updates/preview", ConsoleUpdateRequest{ReleaseID: release.ID, AgentIDs: []string{own.ID}}), 200, &preview)
	request := map[string]any{"preview_token": preview.Token, "client_request_id": "site-update", "confirm": true}
	consoleWant(t, browser("foreign", "POST", "/api/updates/rollouts", request), 409, nil)
	var body struct {
		Rollout ConsoleUpdateRollout `json:"rollout"`
		Jobs    []ConsoleUpdateJob   `json:"jobs"`
	}
	consoleWant(t, browser(defaultSiteID, "POST", "/api/updates/rollouts", request), 200, &body)
	if body.Rollout.SiteID != defaultSiteID || len(body.Jobs) != 1 || body.Jobs[0].AgentID != own.ID {
		t.Fatalf("created rollout scope not stored: %+v", body)
	}
	rawID := body.Rollout.ID
	if err := f.store.moveAgentSite(ctx, own.ID, own.EnrollmentID, "foreign", "admin", time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("active rollout did not fence move: %v", err)
	}
	consoleWant(t, browser("foreign", "GET", "/api/updates/rollouts/"+rawID, nil), 404, nil)
	consoleWant(t, browser("foreign", "GET", "/api/updates/rollouts?after="+rawID, nil), 400, nil)
	consoleWant(t, browser("foreign", "POST", "/api/updates/rollouts/"+rawID+"/cancel", map[string]bool{"confirm": true}), 404, nil)
	consoleWant(t, browser(defaultSiteID, "POST", "/api/updates/rollouts/"+rawID+"/cancel", map[string]bool{"confirm": true}), 200, nil)
	if err := f.store.moveAgentSite(ctx, own.ID, own.EnrollmentID, "foreign", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	consoleWant(t, browser(defaultSiteID, "GET", "/api/updates/rollouts/"+rawID, nil), 200, nil)
	consoleWant(t, browser("foreign", "GET", "/api/updates/rollouts/"+rawID, nil), 404, nil)
}
