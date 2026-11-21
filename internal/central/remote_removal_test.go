package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

const removalConsolePath = "/api/agents/agent-a/remote-removal"
const removalAgentPath = "/v1/remote-removal"

var remoteRemovalTestAdmin = console.Account{Username: "admin", Role: console.RoleAdmin, Version: 1}

func enableRemovalTestAccounts(f *fixture) {
	f.server.SetRemoteRemovalAccountLoader(func(_ context.Context, username string) (console.Account, error) {
		if username != remoteRemovalTestAdmin.Username {
			return console.Account{}, console.ErrAccountNotFound
		}
		return remoteRemovalTestAdmin, nil
	})
}

func (f *fixture) remoteRemovalHeartbeat(t *testing.T, enrolled managed.EnrollResponse, cert *x509.Certificate, enabled string) {
	t.Helper()
	heartbeat := managed.Heartbeat{AgentID: enrolled.AgentID, EnrollmentID: enrolled.EnrollmentID, SentAt: f.server.now().UTC()}
	if enabled != "" {
		heartbeat.Status.CapabilityReport = &model.CapabilityReport{Capabilities: map[string]model.Capability{
			managed.RemoteRemovalCapability: {Name: managed.RemoteRemovalCapability, State: model.CapabilitySupported,
				Details: map[string]string{"contract": managed.RemoteRemovalContract, "enabled": enabled}},
		}}
	}
	consoleWant(t, f.request(t, "POST", "/v1/heartbeat", heartbeat, cert, ""), 200, nil)
}

func removalClaim(t *testing.T, job *remoteRemovalJob) managed.RemoteRemovalClaim {
	t.Helper()
	challenge, err := managed.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	return managed.RemoteRemovalClaim{OrderID: job.OrderID, OperationID: "test-operation", Challenge: challenge}
}

func TestRemoteRemovalAuthenticatedLifecycleAndReplay(t *testing.T) {
	f := setup(t)
	enableRemovalTestAccounts(f)
	now := time.Now().UTC()
	f.server.now = func() time.Time { return now }
	enrolled, cert, _ := f.enroll(t, "agent-a")
	_, otherCert, _ := f.enroll(t, "agent-b")
	console := updateConsoleClient(t, f)
	get := func() remoteRemovalState {
		t.Helper()
		var status remoteRemovalState
		consoleWant(t, console("GET", removalConsolePath, nil, ""), http.StatusOK, &status)
		return status
	}
	post := func(path string, request any, code int, result any) {
		t.Helper()
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		consoleWant(t, console("POST", path, raw, "application/json"), code, result)
	}
	request := remoteRemovalConsoleRequest{EnrollmentID: enrolled.EnrollmentID, Confirmation: enrolled.AgentID}
	consoleWant(t, f.console(t, "GET", removalConsolePath, nil), http.StatusForbidden, nil)
	consoleWant(t, f.request(t, "GET", removalAgentPath, nil, nil, ""), http.StatusUnauthorized, nil)
	if status := get(); status.CanRequest || status.Reason != "unsupported" {
		t.Fatalf("old agent status: %+v", status)
	}
	f.remoteRemovalHeartbeat(t, enrolled, cert, "false")
	if status := get(); status.CanRequest || !status.Supported || status.Reason != "disabled" {
		t.Fatalf("disabled agent status: %+v", status)
	}
	post(removalConsolePath, request, http.StatusConflict, nil)
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	now = now.Add(remoteRemovalFreshness + time.Second)
	if status := get(); status.CanRequest || !status.Enabled || status.Reason != "stale" {
		t.Fatalf("stale agent status: %+v", status)
	}
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	if status := get(); !status.CanRequest || !status.Fresh || status.EnrollmentID != enrolled.EnrollmentID {
		t.Fatalf("ready status: %+v", status)
	}
	post(removalConsolePath, remoteRemovalConsoleRequest{EnrollmentID: enrolled.EnrollmentID, Confirmation: "agent-b"}, http.StatusBadRequest, nil)
	post(removalConsolePath, remoteRemovalConsoleRequest{EnrollmentID: "stale-enrollment", Confirmation: enrolled.AgentID}, http.StatusConflict, nil)

	var job remoteRemovalJob
	post(removalConsolePath, request, http.StatusCreated, &job)
	post(removalConsolePath, request, http.StatusConflict, nil)
	if state := get(); state.CanRequest || state.Job == nil || state.Job.State != "queued" || state.Job.OrderID != job.OrderID {
		t.Fatalf("queued order status: %+v", state)
	}
	consoleWant(t, f.request(t, "GET", removalAgentPath, nil, otherCert, ""), http.StatusNoContent, nil)
	var signedOrder managed.SignedRemoteRemovalOrder
	consoleWant(t, f.request(t, "GET", removalAgentPath, nil, cert, ""), http.StatusOK, &signedOrder)
	keys := map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}
	order, err := managed.VerifyRemoteRemovalOrder(signedOrder, keys, enrolled.AgentID, enrolled.EnrollmentID, now)
	if err != nil || order.ID != job.OrderID || order.ExpiresAt.Sub(now) != managed.MaxRemoteRemovalLifetime {
		t.Fatalf("signed order verification: %+v %v", order, err)
	}
	claim := removalClaim(t, &job)
	success := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "succeeded"}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", success, cert, ""), http.StatusConflict, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", claim, otherCert, ""), http.StatusNotFound, nil)
	var grant managed.SignedRemovalGrant
	first := f.request(t, "POST", removalAgentPath+"/claim", claim, cert, "")
	consoleWant(t, first, http.StatusOK, &grant)
	verified, err := managed.VerifyRemovalGrant(grant, keys, enrolled.AgentID, enrolled.EnrollmentID, claim.Challenge, now)
	if err != nil || verified.ID != job.OrderID || !verified.ExpiresAt.Equal(job.ExpiresAt) {
		t.Fatalf("bound grant verification: %+v %v", verified, err)
	}
	retry := f.request(t, "POST", removalAgentPath+"/claim", claim, cert, "")
	if retry.Code != http.StatusOK || !bytes.Equal(retry.Body.Bytes(), first.Body.Bytes()) {
		t.Fatal("exact retry did not return the stored grant")
	}
	modified := removalClaim(t, &job)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", modified, cert, ""), http.StatusConflict, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", success, cert, ""), http.StatusConflict, nil)
	start := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "started"}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusNoContent, nil)
	post(removalConsolePath+"/cancel", remoteRemovalConsoleCancellation{EnrollmentID: enrolled.EnrollmentID, OrderID: job.OrderID}, http.StatusConflict, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "GET", removalAgentPath, nil, cert, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "GET", "/v1/policy", nil, cert, ""), http.StatusNoContent, nil)

	now = job.ExpiresAt.Add(time.Second)
	if state := get(); state.CanRequest || state.Job == nil || state.Job.State != "result_unknown" {
		t.Fatalf("missing result incorrectly resolved: %+v", state)
	}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusConflict, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", success, cert, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", success, cert, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "GET", "/v1/policy", nil, cert, ""), http.StatusUnauthorized, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusUnauthorized, nil)
	if state := get(); state.Reason != "revoked" || state.Job == nil || state.Job.State != "succeeded" {
		t.Fatalf("completion state: %+v", state)
	}
	entries, err := f.store.Audit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Kind]++
		if bytes.Contains(entry.Details, []byte(claim.Challenge)) {
			t.Fatal("one-use challenge leaked into the audit")
		}
	}
	for _, kind := range []string{"removal.remote.queued", "removal.remote.claimed", "removal.remote.started", "removal.remote.succeeded", "agent.revoked"} {
		if counts[kind] != 1 {
			t.Fatalf("audit %s count=%d", kind, counts[kind])
		}
	}
}

func TestRemoteRemovalCancellationExpiryAndPolicyChange(t *testing.T) {
	f := setup(t)
	enableRemovalTestAccounts(f)
	ctx := context.Background()
	now := time.Now().UTC()
	f.server.now = func() time.Time { return now }
	enrolled, cert, _ := f.enroll(t, "agent-a")
	agent := authenticatedAgent{enrolled.AgentID, enrolled.EnrollmentID}
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	newJob := func() *remoteRemovalJob {
		t.Helper()
		job, err := f.server.newRemoteRemovalOrder(ctx, agent.ID, agent.EnrollmentID, remoteRemovalTestAdmin)
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	setPolicy := func(revision uint64, mode string) {
		t.Helper()
		policy := managed.DefaultPolicy(agent.ID, agent.EnrollmentID, revision, now)
		policy.UninstallMode = mode
		consoleWant(t, f.request(t, "POST", "/admin/policy", policy, nil, f.operator(t)), 201, nil)
	}
	job := newJob()
	cancellation := remoteRemovalConsoleCancellation{EnrollmentID: enrolled.EnrollmentID, OrderID: job.OrderID}
	body, err := json.Marshal(cancellation)
	if err != nil {
		t.Fatal(err)
	}
	console := updateConsoleClient(t, f)
	var cancelled remoteRemovalJob
	consoleWant(t, console("POST", removalConsolePath+"/cancel", body, "application/json"), http.StatusOK, &cancelled)
	if cancelled.OrderID != job.OrderID || cancelled.State != "cancelled" {
		t.Fatalf("cancellation: %+v", cancelled)
	}
	consoleWant(t, f.request(t, "GET", removalAgentPath, nil, cert, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", removalClaim(t, job), cert, ""), http.StatusConflict, nil)

	job = newJob()
	now = job.ExpiresAt
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	status, err := f.server.remoteRemovalStatus(ctx, agent.ID, remoteRemovalTestAdmin)
	if err != nil || !status.CanRequest || status.Job == nil || status.Job.State != "expired" {
		t.Fatalf("expired queued status: %+v %v", status, err)
	}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", removalClaim(t, job), cert, ""), http.StatusConflict, nil)
	job = newJob()
	claim := removalClaim(t, job)
	setPolicy(1, "deny")
	consoleWant(t, f.request(t, "GET", removalAgentPath, nil, cert, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", claim, cert, ""), http.StatusUnauthorized, nil)
	setPolicy(2, "allow")
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", claim, cert, ""), http.StatusOK, nil)
	setPolicy(3, "deny")
	start := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "started"}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusUnauthorized, nil)
	now = job.ExpiresAt.Add(time.Second)
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	setPolicy(4, "allow")
	status, err = f.server.remoteRemovalStatus(ctx, agent.ID, remoteRemovalTestAdmin)
	if err != nil || !status.CanRequest || status.Job == nil || status.Job.State != "expired" {
		t.Fatalf("expired claim retained a fence: %+v %v", status, err)
	}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusConflict, nil)
	failure := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "failed", Code: "local_gate"}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", failure, cert, ""), http.StatusNoContent, nil)
	status, err = f.server.remoteRemovalStatus(ctx, agent.ID, remoteRemovalTestAdmin)
	if err != nil || !status.CanRequest || status.Job == nil || status.Job.State != "expired" {
		t.Fatalf("late failure mutated the expired claim: %+v %v", status, err)
	}

	replacement := newJob()
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", failure, cert, ""), http.StatusNoContent, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", start, cert, ""), http.StatusConflict, nil)
	success := managed.RemoteRemovalReport{OrderID: job.OrderID, State: "succeeded"}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", success, cert, ""), http.StatusConflict, nil)
	consoleWant(t, f.request(t, "GET", removalAgentPath, nil, cert, ""), http.StatusOK, nil)
	status, err = f.server.remoteRemovalStatus(ctx, agent.ID, remoteRemovalTestAdmin)
	if err != nil || status.CanRequest || status.Job == nil || status.Job.State != "queued" || status.Job.OrderID != replacement.OrderID {
		t.Fatalf("late report affected replacement order: %+v %v", status, err)
	}
	var expiredState string
	var discardedGrant bool
	if err := f.store.db.QueryRowContext(ctx, "SELECT state,grant_json IS NULL FROM remote_removal_orders WHERE id=?", job.OrderID).
		Scan(&expiredState, &discardedGrant); err != nil || expiredState != "expired" || !discardedGrant {
		t.Fatalf("expired claim retained its grant: %s %v %v", expiredState, discardedGrant, err)
	}
}

func TestRemoteRemovalUpdateReservationAndEnrollmentReplacement(t *testing.T) {
	f := updateFixture(t)
	enableRemovalTestAccounts(f)
	ctx := context.Background()
	agent, cert := f.updateInventory(t, "agent-a", 23)
	enrolled := managed.EnrollResponse{AgentID: agent.ID, EnrollmentID: agent.EnrollmentID}
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	release := f.updateRelease(t, 24)
	updateRequest := ConsoleUpdateRequest{ReleaseID: release.ID, AgentIDs: []string{agent.ID}}
	updateToken := f.updatePreview(t, updateRequest)
	job, err := f.server.newRemoteRemovalOrder(ctx, agent.ID, agent.EnrollmentID, remoteRemovalTestAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.confirmUpdate(ctx, "admin", "test-reservation", updateToken); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update preview accepted after removal queued: %v", err)
	}
	if _, err = f.server.cancelRemoteRemoval(ctx, agent, job.OrderID, remoteRemovalTestAdmin); err != nil {
		t.Fatal(err)
	}
	f.createUpdate(t, release, agent.ID)
	status, err := f.server.remoteRemovalStatus(ctx, agent.ID, remoteRemovalTestAdmin)
	if err != nil || status.CanRequest || status.Reason != "update_busy" {
		t.Fatalf("update reservation: %+v %v", status, err)
	}
	if _, err := f.server.newRemoteRemovalOrder(ctx, agent.ID, agent.EnrollmentID, remoteRemovalTestAdmin); !errors.Is(err, ErrConflict) {
		t.Fatalf("removal accepted while an update is queued: %v", err)
	}

	fresh, freshCert, _ := f.enroll(t, agent.ID)
	f.remoteRemovalHeartbeat(t, fresh, freshCert, "true")
	newJob, err := f.server.newRemoteRemovalOrder(ctx, fresh.AgentID, fresh.EnrollmentID, remoteRemovalTestAdmin)
	if err != nil || newJob == nil || newJob.OrderID == job.OrderID {
		t.Fatalf("new enrollment queue: %+v %v", newJob, err)
	}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", removalClaim(t, newJob), cert, ""), http.StatusUnauthorized, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", removalClaim(t, job), freshCert, ""), http.StatusNotFound, nil)
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/report", managed.RemoteRemovalReport{OrderID: newJob.OrderID, State: "succeeded"}, cert, ""), http.StatusUnauthorized, nil)
}

func TestRemoteRemovalExpiredClaimDoesNotBlockUpdate(t *testing.T) {
	f := updateFixture(t)
	enableRemovalTestAccounts(f)
	ctx := context.Background()
	now := time.Now().UTC()
	f.server.now = func() time.Time { return now }
	agent, cert := f.updateInventory(t, "agent-a", 23)
	enrolled := managed.EnrollResponse{AgentID: agent.ID, EnrollmentID: agent.EnrollmentID}
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	release := f.updateRelease(t, 24)
	job, err := f.server.newRemoteRemovalOrder(ctx, agent.ID, agent.EnrollmentID, remoteRemovalTestAdmin)
	if err != nil {
		t.Fatal(err)
	}
	consoleWant(t, f.request(t, "POST", removalAgentPath+"/claim", removalClaim(t, job), cert, ""), http.StatusOK, nil)
	now = job.ExpiresAt
	f.remoteRemovalHeartbeat(t, enrolled, cert, "true")
	f.createUpdate(t, release, agent.ID)
	status, err := f.server.remoteRemovalStatus(ctx, agent.ID, remoteRemovalTestAdmin)
	if err != nil || status.Reason != "update_busy" || status.Job == nil || status.Job.State != "expired" {
		t.Fatalf("expired claim and active update status: %+v %v", status, err)
	}
}
