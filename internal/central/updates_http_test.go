package central

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func updateConsoleClient(t *testing.T, f *fixture) func(string, string, []byte, string) *httptest.ResponseRecorder {
	t.Helper()
	credentials, err := console.GenerateCredentials("admin", "synthetic-update-password", console.Argon2Parameters{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := console.NewWithOptions(credentials, f.server.ConsoleHandler(), nil, console.Options{AccountsPath: filepath.Join(f.directory, "update-panel-accounts.db")})
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := handler.(interface{ Close() error }); ok {
		t.Cleanup(func() { closer.Close() })
	}
	token, err := credentials.NewSession(time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "xeas_central_session", Value: token}
	request := httptest.NewRequest("GET", "http://localhost:9089/api/session", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var session map[string]string
	if json.Unmarshal(response.Body.Bytes(), &session) != nil || session["csrf_token"] == "" {
		t.Fatal("missing test session")
	}
	return func(method, path string, body []byte, media string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost:9089"+path, bytes.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://localhost:9089")
		r.Header.Set("X-CSRF-Token", session["csrf_token"])
		r.Header.Set("Content-Type", media)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
}

func TestUpdateAuthenticatedConsoleAndMTLSEndToEnd(t *testing.T) {
	f := updateFixture(t)
	client := updateConsoleClient(t, f)
	pack := updatePackage(24)
	raw, _ := json.Marshal(pack)
	upload := client("POST", "/api/updates/releases", raw, "application/x-rpm")
	if upload.Code != 201 {
		t.Fatalf("upload %d", upload.Code)
	}
	var result struct {
		Release ConsoleUpdateRelease `json:"release"`
	}
	json.Unmarshal(upload.Body.Bytes(), &result)
	enrolled, cert, _ := f.enroll(t, "agent-a")
	current := updatePackage(23)
	inventory := managed.UpdateInventory{ProtocolVersion: 1, Supported: true, Enabled: true, OSFamily: "rhel", OSMajor: "9", Arch: "x86_64", InstalledPackage: &current, RunningVersion: updateVersion(current), ObservedAt: time.Now().UTC()}
	if w := f.request(t, "POST", "/v1/update/status", inventory, cert, ""); w.Code != 200 {
		t.Fatalf("inventory %d", w.Code)
	}
	request, _ := json.Marshal(ConsoleUpdateRequest{ReleaseID: result.Release.ID, AgentIDs: []string{"agent-a"}})
	preview := client("POST", "/api/updates/preview", request, "application/json")
	if preview.Code != 200 {
		t.Fatalf("preview %d %s", preview.Code, preview.Body.String())
	}
	var snapshot struct {
		Token string `json:"preview_token"`
	}
	json.Unmarshal(preview.Body.Bytes(), &snapshot)
	confirm, _ := json.Marshal(map[string]any{"preview_token": snapshot.Token, "confirm": true, "client_request_id": "e2e-request"})
	created := client("POST", "/api/updates/rollouts", confirm, "application/json")
	if created.Code != 200 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	response := f.request(t, "GET", "/v1/update", nil, cert, "")
	if response.Code != 200 {
		t.Fatalf("desired %d", response.Code)
	}
	var plan managed.SignedUpdatePlan
	json.Unmarshal(response.Body.Bytes(), &plan)
	for index, state := range []string{"downloading", "ready"} {
		report := managed.UpdateReport{ProtocolVersion: 1, JobID: plan.Plan.JobID, EnrollmentID: enrolled.EnrollmentID, Revision: plan.Plan.Revision, Sequence: uint64(index + 1), State: state, ObservedAt: time.Now().UTC(), RunningVersion: current.RunningVersion()}
		if w := f.request(t, "POST", "/v1/update/report", report, cert, ""); w.Code != 200 {
			t.Fatalf("%s %d", state, w.Code)
		}
	}
	claim := managed.UpdateClaim{JobID: plan.Plan.JobID, EnrollmentID: enrolled.EnrollmentID, Revision: plan.Plan.Revision}
	if w := f.request(t, "POST", "/v1/update/claim", claim, cert, ""); w.Code != 200 {
		t.Fatalf("claim %d", w.Code)
	}
	success := managed.UpdateReport{ProtocolVersion: 1, JobID: plan.Plan.JobID, EnrollmentID: enrolled.EnrollmentID, Revision: plan.Plan.Revision, Sequence: 3, State: "succeeded", InstalledPackage: &pack, RunningVersion: updateVersion(pack), ObservedAt: time.Now().UTC()}
	if w := f.request(t, "POST", "/v1/update/report", success, cert, ""); w.Code != 200 {
		t.Fatalf("success %d %s", w.Code, w.Body.String())
	}
	if w := client("GET", "/api/updates/rollouts/"+plan.Plan.RolloutID, nil, ""); w.Code != 200 {
		t.Fatalf("details %d", w.Code)
	}
	if w := f.console(t, "GET", "/api/updates/releases", nil); w.Code != 403 {
		t.Fatal("unmounted business API lost auth context")
	}
}
