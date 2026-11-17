package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func updatePackage(release int) managed.RPMPackage {
	return managed.RPMPackage{Name: "xe-antishell", Epoch: 0, Version: "0.1.0", Release: fmt.Sprintf("%d.el9", release), Arch: "x86_64"}
}
func updateVersion(pack managed.RPMPackage) string {
	return pack.RunningVersion()
}
func updateFixture(t *testing.T) *fixture {
	f := setup(t)
	f.server.updateBlobs.inspect = func(ctx context.Context, path string) (managed.RPMPackage, string, error) {
		var pack managed.RPMPackage
		body, err := os.ReadFile(path)
		if err != nil {
			return pack, "", err
		}
		if json.Unmarshal(body, &pack) != nil || pack.Validate() != nil {
			return pack, "", ErrInvalid
		}
		return pack, "9", nil
	}
	return f
}
func (f *fixture) updateRelease(t *testing.T, n int) ConsoleUpdateRelease {
	t.Helper()
	body, _ := json.Marshal(updatePackage(n))
	release, _, err := f.server.publishUpdateRelease(context.Background(), bytes.NewReader(body), "admin")
	if err != nil {
		t.Fatal(err)
	}
	return release
}
func (f *fixture) updateInventory(t *testing.T, id string, n int) (authenticatedAgent, *x509.Certificate) {
	t.Helper()
	enrolled, cert, _ := f.enroll(t, id)
	agent := authenticatedAgent{ID: id, EnrollmentID: enrolled.EnrollmentID}
	f.putUpdateInventory(t, agent, n)
	return agent, cert
}
func (f *fixture) putUpdateInventory(t *testing.T, agent authenticatedAgent, n int) {
	t.Helper()
	pack := updatePackage(n)
	inventory := managed.UpdateInventory{ProtocolVersion: 1, Supported: true, Enabled: true, OSFamily: "rhel", OSMajor: "9", Arch: "x86_64", InstalledPackage: &pack, RunningVersion: updateVersion(pack), ObservedAt: f.server.now().UTC()}
	if err := f.server.recordUpdateInventory(context.Background(), agent, inventory); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) updatePreview(t *testing.T, request ConsoleUpdateRequest) string {
	t.Helper()
	tx, err := f.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = expireUpdateJobs(context.Background(), tx, f.server.now().UTC()); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	snapshot, _, err := updateSnapshot(context.Background(), tx, request, f.server.now().UTC())
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	snapshot.Nonce = "synthetic-preview"
	snapshot.IssuedAt = f.server.now().UTC()
	snapshot.ExpiresAt = snapshot.IssuedAt.Add(previewLifetime)
	token, err := f.server.encodeUpdatePreview(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func (f *fixture) createUpdate(t *testing.T, release ConsoleUpdateRelease, ids ...string) string {
	t.Helper()
	token := f.updatePreview(t, ConsoleUpdateRequest{ReleaseID: release.ID, AgentIDs: ids, Concurrency: 1})
	key, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.server.confirmUpdate(context.Background(), "admin", "request-"+key, token)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func (f *fixture) offerUpdate(t *testing.T, agent authenticatedAgent) managed.SignedUpdatePlan {
	t.Helper()
	body, err := f.server.desiredUpdate(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("no update offered")
	}
	var plan managed.SignedUpdatePlan
	if err = json.Unmarshal(body, &plan); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}
	if _, err = managed.VerifyUpdatePlan(plan, keys, agent.ID, agent.EnrollmentID, plan.Plan.Revision, f.server.now()); err != nil {
		t.Fatal(err)
	}
	return plan
}
func (f *fixture) updateReport(t *testing.T, plan managed.SignedUpdatePlan, sequence uint64, state string) managed.UpdateReport {
	t.Helper()
	report := managed.UpdateReport{ProtocolVersion: 1, JobID: plan.Plan.JobID, EnrollmentID: plan.Plan.EnrollmentID, Revision: plan.Plan.Revision, Sequence: sequence, State: state, ObservedAt: f.server.now().UTC(), RunningVersion: updateVersion(plan.Plan.ExpectedPackage)}
	if state == "failed" {
		report.ErrorCode = "install_failed"
	}
	if state == "succeeded" {
		pack := plan.Plan.Release.Package
		report.InstalledPackage = &pack
		report.RunningVersion = updateVersion(pack)
	}
	if err := f.server.recordUpdateReport(context.Background(), authenticatedAgent{ID: plan.Plan.AgentID, EnrollmentID: plan.Plan.EnrollmentID}, report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestUpdateReleaseImmutableDedupAndMetadata(t *testing.T) {
	f := updateFixture(t)
	release := f.updateRelease(t, 24)
	body, _ := json.Marshal(updatePackage(24))
	duplicate, same, err := f.server.publishUpdateRelease(context.Background(), bytes.NewReader(body), "admin")
	if err != nil || !same || duplicate.ID != release.ID {
		t.Fatalf("dedupe: %v %v", same, err)
	}
	path, _ := f.server.updateBlobs.path(release.ID)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("release not private regular blob")
	}
	f.server.updateBlobs.inspect = func(context.Context, string) (managed.RPMPackage, string, error) { return updatePackage(24), "9", nil }
	if _, _, err = f.server.publishUpdateRelease(context.Background(), bytes.NewReader([]byte("different bytes, identical NEVRA")), "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("version was replaced")
	}
	staged, _ := os.ReadDir(filepath.Join(f.directory, "update-blobs/staging"))
	if len(staged) != 0 {
		t.Fatal("upload staging leaked")
	}
	if _, err = f.server.updateBlobs.open("../outside", 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("unsafe artifact identifier")
	}
	if err = f.server.deleteUpdateRelease(context.Background(), release.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreferenced release not removed")
	}
}

func TestUpdatePlanClaimReportAndAuthorizedDownload(t *testing.T) {
	f := updateFixture(t)
	release := f.updateRelease(t, 24)
	agent, cert := f.updateInventory(t, "agent-a", 23)
	_, foreign := f.updateInventory(t, "agent-b", 23)
	rollout := f.createUpdate(t, release, "agent-a")
	plan := f.offerUpdate(t, agent)
	first, _ := f.server.desiredUpdate(context.Background(), agent)
	second, _ := f.server.desiredUpdate(context.Background(), agent)
	if !bytes.Equal(first, second) {
		t.Fatal("plan reissue changed bytes")
	}
	if w := f.request(t, "GET", "/v1/update/artifacts/"+release.ID, nil, foreign, ""); w.Code != 404 {
		t.Fatalf("foreign artifact: %d", w.Code)
	}
	w := f.request(t, "GET", "/v1/update/artifacts/"+release.ID, nil, cert, "")
	if w.Code != 200 || int64(w.Body.Len()) != release.Size {
		t.Fatalf("artifact %d", w.Code)
	}
	if err := f.server.deleteUpdateRelease(context.Background(), release.ID, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("active artifact deleted")
	}
	f.updateReport(t, plan, 1, "downloading")
	ready := f.updateReport(t, plan, 2, "ready")
	claim := managed.UpdateClaim{JobID: plan.Plan.JobID, EnrollmentID: agent.EnrollmentID, Revision: plan.Plan.Revision}
	auth, err := f.server.claimUpdate(context.Background(), agent, claim)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.server.claimUpdate(context.Background(), agent, claim)
	if err != nil || !bytes.Equal(auth, retry) {
		t.Fatal("claim retry changed lease")
	}
	var signed managed.SignedUpdateAuthorization
	json.Unmarshal(auth, &signed)
	keys := map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}
	if _, err = managed.VerifyUpdateAuthorization(signed, keys, plan.Plan, f.server.now()); err != nil {
		t.Fatal(err)
	}
	if err = f.server.recordUpdateReport(context.Background(), agent, ready); err != nil {
		t.Fatal("late exact ready retry rejected")
	}
	_, jobs, _, err := f.server.updateRolloutDetail(context.Background(), rollout, "", 100)
	if err != nil || jobs[0].State != "installing" {
		t.Fatal("ready retry regressed claim")
	}
	f.updateReport(t, plan, 3, "installing")
	success := f.updateReport(t, plan, 4, "succeeded")
	if err = f.server.recordUpdateReport(context.Background(), agent, success); err != nil {
		t.Fatal(err)
	}
	success.RunningVersion = "changed"
	if err = f.server.recordUpdateReport(context.Background(), agent, success); !errors.Is(err, ErrConflict) {
		t.Fatal("same-sequence conflict accepted")
	}
	_, jobs, _, err = f.server.updateRolloutDetail(context.Background(), rollout, "", 100)
	if err != nil || jobs[0].State != "succeeded" || !jobs[0].Terminal {
		t.Fatal("success not persisted")
	}
}

func TestUpdateReEnrollmentRejectsOldInventoryPlanArtifactClaimReport(t *testing.T) {
	f := updateFixture(t)
	release := f.updateRelease(t, 24)
	old, oldCert := f.updateInventory(t, "agent-a", 23)
	f.createUpdate(t, release, "agent-a")
	plan := f.offerUpdate(t, old)
	newEnrollment, newCert, _ := f.enroll(t, "agent-a")
	items, _, _, err := f.server.listUpdateAgents(context.Background(), "", "", 100)
	if err != nil || len(items) != 1 || items[0].EnrollmentID != newEnrollment.EnrollmentID || items[0].Inventory != nil {
		t.Fatal("old inventory crossed enrollment")
	}
	for _, test := range []struct {
		method, path string
		value        any
	}{
		{"GET", "/v1/update", nil}, {"GET", "/v1/update/artifacts/" + release.ID, nil},
		{"POST", "/v1/update/claim", managed.UpdateClaim{JobID: plan.Plan.JobID, EnrollmentID: old.EnrollmentID, Revision: 1}},
		{"POST", "/v1/update/report", managed.UpdateReport{ProtocolVersion: 1, JobID: plan.Plan.JobID, EnrollmentID: old.EnrollmentID, Revision: 1, Sequence: 1, State: "ready", ObservedAt: time.Now()}},
	} {
		if w := f.request(t, test.method, test.path, test.value, oldCert, ""); w.Code != 401 {
			t.Fatalf("old %s accepted: %d", test.path, w.Code)
		}
	}
	if w := f.request(t, "GET", "/v1/update", nil, newCert, ""); w.Code != 204 {
		t.Fatal("old desired update crossed enrollment")
	}
	if w := f.request(t, "POST", "/v1/update/claim", managed.UpdateClaim{JobID: plan.Plan.JobID, EnrollmentID: newEnrollment.EnrollmentID, Revision: 1}, newCert, ""); w.Code < 400 {
		t.Fatal("new certificate claimed old job")
	}
}

func TestUpdatePreviewBindsGroupGenerationPackageAndMixedExclusions(t *testing.T) {
	f := updateFixture(t)
	release := f.updateRelease(t, 24)
	a, _ := f.updateInventory(t, "agent-a", 23)
	f.enroll(t, "old-agent")
	f.consoleDrafts(t, []string{"agent-a", "old-agent"})
	token := f.updatePreview(t, ConsoleUpdateRequest{ReleaseID: release.ID, GroupIDs: []string{"web"}})
	snapshot, err := f.server.decodeUpdatePreview(token, f.server.now())
	if err != nil || len(snapshot.Targets) != 2 {
		t.Fatal(err)
	}
	eligible := 0
	for _, target := range snapshot.Targets {
		if target.Eligible {
			eligible++
		}
	}
	if eligible != 1 {
		t.Fatal("missing inventory was eligible")
	}
	f.putUpdateInventory(t, a, 22)
	if _, err = f.server.confirmUpdate(context.Background(), "admin", "changed-pkg", token); !errors.Is(err, ErrConflict) {
		t.Fatal("changed package confirmation accepted")
	}
	token = f.updatePreview(t, ConsoleUpdateRequest{ReleaseID: release.ID, GroupIDs: []string{"web"}})
	consoleWant(t, f.console(t, "DELETE", "/api/groups/web?version=1", nil), 200, nil)
	consoleWant(t, f.console(t, "POST", "/api/groups", ConsoleGroup{ID: "web", Name: "recreated", AgentIDs: []string{"agent-a", "old-agent"}}), 200, nil)
	if _, err = f.server.confirmUpdate(context.Background(), "admin", "aba", token); !errors.Is(err, ErrConflict) {
		t.Fatal("group ABA confirmation accepted")
	}
	token = f.updatePreview(t, ConsoleUpdateRequest{ReleaseID: release.ID, GroupIDs: []string{"web"}})
	id, err := f.server.confirmUpdate(context.Background(), "admin", "fixed-key", token)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.server.confirmUpdate(context.Background(), "admin", "fixed-key", token)
	if err != nil || retry != id {
		t.Fatal("create retry duplicated rollout")
	}
	_, jobs, _, err := f.server.updateRolloutDetail(context.Background(), id, "", 100)
	if err != nil || len(jobs) != 1 || jobs[0].AgentID != "agent-a" {
		t.Fatal("mixed exclusions not preserved")
	}
}
