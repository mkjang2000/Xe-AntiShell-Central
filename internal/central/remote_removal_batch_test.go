package central

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const removalBatchPath = "/api/remote-removal/batches"

type removalBatchPreviewResponse struct {
	PreviewToken string                     `json:"preview_token"`
	BatchID      string                     `json:"batch_id"`
	Eligible     int                        `json:"eligible_count"`
	Targets      []remoteRemovalBatchTarget `json:"targets"`
}

func TestRemoteRemovalBatchPinsEligibleSelectionAndReplaysReceipt(t *testing.T) {
	f := setup(t)
	enableRemovalTestAccounts(f)
	a, certA, _ := f.enroll(t, "agent-a")
	b, certB, _ := f.enroll(t, "agent-b")
	f.remoteRemovalHeartbeat(t, a, certA, "true")
	client := updateConsoleClient(t, f)
	post := func(path string, request any, code int, result any) {
		t.Helper()
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		consoleWant(t, client("POST", path, body, "application/json"), code, result)
	}
	_, err := f.store.saveConsoleGroup(context.Background(), ConsoleGroup{ID: "unused", SiteID: "default", Name: "Ready to retire", AgentIDs: []string{a.AgentID, b.AgentID}}, f.server.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request := remoteRemovalSelection{GroupID: "unused"}
	var sitePreview, before removalBatchPreviewResponse
	post("/api/remote-removal/preview", remoteRemovalSelection{SiteID: "default"}, http.StatusOK, &sitePreview)
	if sitePreview.Eligible != 1 || len(sitePreview.Targets) != 2 {
		t.Fatalf("site preview: %+v", sitePreview)
	}
	post("/api/remote-removal/preview", request, http.StatusOK, &before)
	if before.Eligible != 1 || len(before.Targets) != 2 || before.Targets[0].AgentID != a.AgentID ||
		before.Targets[1].Reason != "unsupported" || before.PreviewToken == "" || before.BatchID == "" {
		t.Fatalf("preview: %+v", before)
	}
	post(removalBatchPath, remoteRemovalBatchConfirmation{before.PreviewToken, "2"}, http.StatusBadRequest, nil)
	f.remoteRemovalHeartbeat(t, b, certB, "true")
	post(removalBatchPath, remoteRemovalBatchConfirmation{before.PreviewToken, "1"}, http.StatusConflict, nil)
	var existing int
	if err := f.store.db.QueryRow("SELECT count(*) FROM remote_removal_orders").Scan(&existing); err != nil || existing != 0 {
		t.Fatalf("stale preview issued %d removal orders: %v", existing, err)
	}

	var ready removalBatchPreviewResponse
	post("/api/remote-removal/preview", request, http.StatusOK, &ready)
	confirm := remoteRemovalBatchConfirmation{ready.PreviewToken, strconv.Itoa(ready.Eligible)}
	var created, replay remoteRemovalBatch
	post(removalBatchPath, confirm, http.StatusCreated, &created)
	post(removalBatchPath, confirm, http.StatusCreated, &replay)
	if ready.Eligible != 2 || created.BatchID != ready.BatchID || replay.BatchID != created.BatchID ||
		len(created.Targets) != 2 || len(replay.Targets) != 2 || created.Targets[0].Job.OrderID != replay.Targets[0].Job.OrderID {
		t.Fatalf("batch receipts: %+v and %+v", created, replay)
	}
	queued := created.Targets[0].Job
	claim := removalClaim(t, queued)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", claim, certA, ""), http.StatusOK, nil)
	cancel := remoteRemovalConsoleCancellation{EnrollmentID: a.EnrollmentID, OrderID: queued.OrderID}
	post(removalConsolePath+"/cancel", cancel, http.StatusOK, nil)
	start := managed.RemoteRemovalReport{OrderID: queued.OrderID, State: "started"}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, certA, ""), http.StatusConflict, nil)
	var status remoteRemovalBatch
	consoleWant(t, client("GET", removalBatchPath+"/"+created.BatchID, nil, ""), http.StatusOK, &status)
	if len(status.Targets) != 2 || status.Targets[0].Job.State != "cancelled" || status.Targets[1].Job.State != "queued" {
		t.Fatalf("batch target outcomes: %+v", status.Targets)
	}
	var recorded int
	if err := f.store.db.QueryRow("SELECT count(*) FROM remote_removal_orders").Scan(&recorded); err != nil || recorded != 2 {
		t.Fatalf("idempotent apply created %d orders: %v", recorded, err)
	}
}

func TestRemoteRemovalRevocationOrSiteChangeCancelsClaimBeforeRPMStart(t *testing.T) {
	for _, test := range []struct {
		name   string
		code   string
		change func(*testing.T, *fixture, string)
	}{
		{"permission_revoked", "authorization_changed", func(_ *testing.T, f *fixture, _ string) {
			f.server.SetRemoteRemovalAccountLoader(func(context.Context, string) (console.Account, error) {
				return console.Account{Username: "admin", Role: console.RoleViewer, Version: 1}, nil
			})
		}},
		{"account_deleted", "authorization_changed", func(_ *testing.T, f *fixture, _ string) {
			f.server.SetRemoteRemovalAccountLoader(func(context.Context, string) (console.Account, error) {
				return console.Account{}, console.ErrAccountNotFound
			})
		}},
		{"new_account", "authorization_changed", func(_ *testing.T, f *fixture, _ string) {
			f.server.SetRemoteRemovalAccountLoader(func(context.Context, string) (console.Account, error) {
				return console.Account{Username: "admin", Role: console.RoleAdmin, Version: 2}, nil
			})
		}},
		{"site_moved", "site_changed", func(t *testing.T, f *fixture, id string) {
			if _, err := f.store.db.Exec("INSERT INTO sites(site_id,name,version) VALUES('secondary','Secondary',1)"); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.db.Exec("UPDATE agents SET site_id='secondary' WHERE agent_id=?", id); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := setup(t)
			enableRemovalTestAccounts(f)
			enrolled, cert, _ := f.enroll(t, "agent-a")
			f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
			ctx := context.Background()
			job, err := f.server.newRemoteRemovalOrder(ctx, enrolled.AgentID, enrolled.EnrollmentID, remoteRemovalTestAdmin)
			if err != nil {
				t.Fatal(err)
			}
			claim := removalClaim(t, job)
			consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", claim, cert, ""), http.StatusOK, nil)
			test.change(t, f, enrolled.AgentID)
			start := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "started"}
			consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusUnauthorized, nil)
			var state, code string
			var grantDiscarded bool
			row := f.store.db.QueryRow("SELECT state,code,grant_json IS NULL FROM remote_removal_orders WHERE id=?", job.OrderID)
			if err := row.Scan(&state, &code, &grantDiscarded); err != nil || state != "cancelled" || code != test.code || !grantDiscarded {
				t.Fatalf("state after authorization changed: %q, %q, grant discarded %v, %v", state, code, grantDiscarded, err)
			}
			success := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "succeeded"}
			consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", success, cert, ""), http.StatusConflict, nil)
		})
	}
}

func TestRemoteRemovalTransientAccountReadErrorKeepsClaim(t *testing.T) {
	f := setup(t)
	enableRemovalTestAccounts(f)
	enrolled, cert, _ := f.enroll(t, "agent-a")
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	job, err := f.server.newRemoteRemovalOrder(context.Background(), enrolled.AgentID, enrolled.EnrollmentID, remoteRemovalTestAdmin)
	if err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", removalClaim(t, job), cert, ""), http.StatusOK, nil)
	f.server.SetRemoteRemovalAccountLoader(func(context.Context, string) (console.Account, error) {
		return console.Account{}, context.DeadlineExceeded
	})
	start := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "started"}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusInternalServerError, nil)
	enableRemovalTestAccounts(f)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusNoContent, nil)
}

func TestRemoteRemovalBatchNeverApprovesOrRevealsOtherSiteTargets(t *testing.T) {
	f := setup(t)
	a, certA, _ := f.enroll(t, "agent-a")
	b, certB, _ := f.enroll(t, "agent-b")
	if _, err := f.store.db.Exec("INSERT INTO sites(site_id,name,version) VALUES('secondary','Secondary',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec("UPDATE agents SET site_id='secondary' WHERE agent_id=?", b.AgentID); err != nil {
		t.Fatal(err)
	}
	f.remoteRemovalHeartbeat(t, a, certA, "true")
	f.remoteRemovalHeartbeat(t, b, certB, "true")

	credentials, err := console.GenerateCredentials("admin", "synthetic-scope-password1!", console.Argon2Parameters{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := console.NewWithOptions(credentials, f.server.ConsoleHandler(), nil, console.Options{
		SiteExists:            f.store.SiteExists,
		OnAuthorizationLoader: f.server.SetRemoteRemovalAccountLoader,
	})
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := handler.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	token, err := credentials.NewSession(time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	session := &http.Cookie{Name: "xeas_central_session", Value: token}
	rawSession := httptest.NewRequest("GET", "http://localhost:9089/api/session", nil)
	rawSession.AddCookie(session)
	var sessionData map[string]any
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, rawSession)
	consoleWant(t, w, http.StatusOK, &sessionData)
	csrf, ok := sessionData["csrf_token"].(string)
	if !ok || csrf == "" {
		t.Fatal("missing test session CSRF token")
	}
	post := func(path, payload string, code int) {
		t.Helper()
		r := httptest.NewRequest("POST", "http://localhost:9089"+path, strings.NewReader(payload))
		r.AddCookie(session)
		r.Header.Set("Origin", "http://localhost:9089")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		consoleWant(t, response, code, nil)
	}
	post("/api/rbac/roles", `{"id":"site-remover","name":"Site removal","permissions":["agents.remove"],"version":0}`, http.StatusCreated)
	post("/api/accounts", `{"username":"site-remover","password":"synthetic-scope-password2!","grants":[{"role_id":"site-remover","site_id":"default"}]}`, http.StatusCreated)
	ctx := context.Background()
	actor, err := f.server.removalActors(ctx, "site-remover")
	if err != nil || !actor.Can(console.PermissionAgentRemove, "default") || actor.Can(console.PermissionAgentRemove, "secondary") {
		t.Fatalf("expected exact removal grants, error %v", err)
	}
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	request := remoteRemovalSelection{AgentIDs: []string{a.AgentID, b.AgentID}}
	if _, _, err := remoteRemovalTargets(ctx, tx, actor, request, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-site explicit selection: %v", err)
	}
	if _, _, err := remoteRemovalTargets(ctx, tx, actor, remoteRemovalSelection{SiteID: "secondary"}, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-site selector: %v", err)
	}
	witness, eligible, err := remoteRemovalTargets(ctx, tx, remoteRemovalTestAdmin, request, now)
	if err != nil || eligible != 2 {
		t.Fatalf("global batch witness: eligible %d, %v", eligible, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	digest, err := consoleHash(witness)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := f.server.createRemoteRemovalBatch(ctx, remoteRemovalTestAdmin, remoteRemovalPreview{
		BatchID: "removal-batch-scoped-test", Selection: request, Eligible: 2, TargetHash: digest, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	readTx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer readTx.Rollback()
	scoped, err := f.server.readRemoteRemovalBatch(ctx, readTx, actor, batch.BatchID, now)
	if err != nil || len(scoped.Targets) != 1 || scoped.Targets[0].AgentID != a.AgentID || scoped.Targets[0].SiteID != "default" {
		t.Fatalf("restricted batch status revealed another site: %+v, %v", scoped, err)
	}
}
