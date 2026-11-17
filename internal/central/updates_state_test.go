package central

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestUpdateOfferedExpiryStopsCampaignAndFreesHeads(t *testing.T) {
	f := updateFixture(t)
	clock := time.Now().UTC()
	f.server.now = func() time.Time { return clock }
	release := f.updateRelease(t, 24)
	a, _ := f.updateInventory(t, "agent-a", 23)
	b, _ := f.updateInventory(t, "agent-b", 23)
	id := f.createUpdate(t, release, a.ID, b.ID)
	old := f.offerUpdate(t, a)
	if body, err := f.server.desiredUpdate(context.Background(), b); err != nil || len(body) != 0 {
		t.Fatal("campaign concurrency exceeded")
	}
	clock = clock.Add(updatePlanTTL + time.Second)
	if body, err := f.server.desiredUpdate(context.Background(), b); err != nil || len(body) != 0 {
		t.Fatal("expired campaign continued dispatch")
	}
	rollout, jobs, _, err := f.server.updateRolloutDetail(context.Background(), id, "", 100)
	if err != nil || !rollout.Paused || rollout.StopReason != "expired" {
		t.Fatal("expiry did not stop rollout")
	}
	for _, job := range jobs {
		if !job.Terminal {
			t.Fatal("unfinished old campaign target")
		}
	}
	f.putUpdateInventory(t, a, 23)
	f.putUpdateInventory(t, b, 23)
	f.createUpdate(t, release, a.ID, b.ID)
	next := f.offerUpdate(t, a)
	if next.Plan.Revision <= old.Plan.Revision {
		t.Fatal("expired head revision reused")
	}
}

func TestUpdateClaimTimeoutLateHistoryCannotResumeOrChangeNewHead(t *testing.T) {
	f := updateFixture(t)
	clock := time.Now().UTC()
	f.server.now = func() time.Time { return clock }
	release := f.updateRelease(t, 24)
	agent, _ := f.updateInventory(t, "agent-a", 23)
	id := f.createUpdate(t, release, agent.ID)
	plan := f.offerUpdate(t, agent)
	f.updateReport(t, plan, 1, "ready")
	claim := managed.UpdateClaim{JobID: plan.Plan.JobID, EnrollmentID: agent.EnrollmentID, Revision: plan.Plan.Revision}
	if _, err := f.server.claimUpdate(context.Background(), agent, claim); err != nil {
		t.Fatal(err)
	}
	if cancelled, installing, err := f.server.cancelUpdate(context.Background(), id, "admin"); err != nil || cancelled != 0 || installing != 1 {
		t.Fatal("cancellation interrupted claimed job")
	}
	clock = clock.Add(updateInstallTimeout + time.Second)
	rollout, jobs, _, err := f.server.updateRolloutDetail(context.Background(), id, "", 100)
	if err != nil || !rollout.Paused || rollout.StopReason != "interrupted" || jobs[0].State != "failed" || jobs[0].ErrorCode != "interrupted" {
		t.Fatal("unreported install did not become unknown-result failure")
	}
	f.putUpdateInventory(t, agent, 23)
	newID := f.createUpdate(t, release, agent.ID)
	newPlan := f.offerUpdate(t, agent)
	f.updateReport(t, plan, 2, "installing")
	f.updateReport(t, plan, 3, "succeeded")
	old, oldJobs, _, err := f.server.updateRolloutDetail(context.Background(), id, "", 100)
	if err != nil || !old.Paused || oldJobs[0].State != "failed" || oldJobs[0].ErrorCode != "interrupted" || !oldJobs[0].LateReport || oldJobs[0].ObservedPackage == nil {
		t.Fatal("late history changed terminal truth")
	}
	_, newJobs, _, err := f.server.updateRolloutDetail(context.Background(), newID, "", 100)
	if err != nil || newJobs[0].State != "offered" || newJobs[0].Revision != newPlan.Plan.Revision {
		t.Fatal("late history changed newer job")
	}
	if _, err = f.server.claimUpdate(context.Background(), agent, claim); !errors.Is(err, ErrConflict) {
		t.Fatal("old claimed revision reused")
	}
}

func TestUpdateCannotSucceedOrInstallWithoutClaim(t *testing.T) {
	f := updateFixture(t)
	release := f.updateRelease(t, 24)
	agent, _ := f.updateInventory(t, "agent-a", 23)
	f.createUpdate(t, release, agent.ID)
	plan := f.offerUpdate(t, agent)
	pack := release.Package
	report := managed.UpdateReport{ProtocolVersion: managed.UpdateProtocolVersion, JobID: plan.Plan.JobID, EnrollmentID: agent.EnrollmentID, Revision: 1, Sequence: 1, State: "succeeded", InstalledPackage: &pack, RunningVersion: updateVersion(pack), ObservedAt: f.server.now(), CollectionCheck: "verified"}
	if err := f.server.recordUpdateReport(context.Background(), agent, report); !errors.Is(err, ErrConflict) {
		t.Fatal("success without authorization")
	}
	report.State = "installing"
	report.CollectionCheck = ""
	report.InstalledPackage = nil
	if err := f.server.recordUpdateReport(context.Background(), agent, report); !errors.Is(err, ErrConflict) {
		t.Fatal("installing without authorization")
	}
	if _, err := f.store.db.Exec("UPDATE update_heads SET revision=revision+1 WHERE agent_id=?", agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.server.desiredUpdate(context.Background(), agent); !errors.Is(err, ErrConflict) {
		t.Fatal("lower revision was redelivered")
	}
}

func TestUpdateFirstFailureStopsUnclaimedRemainingTargets(t *testing.T) {
	f := updateFixture(t)
	release := f.updateRelease(t, 24)
	a, _ := f.updateInventory(t, "agent-a", 23)
	b, _ := f.updateInventory(t, "agent-b", 23)
	id := f.createUpdate(t, release, a.ID, b.ID)
	plan := f.offerUpdate(t, a)
	f.updateReport(t, plan, 1, "failed")
	rollout, jobs, _, err := f.server.updateRolloutDetail(context.Background(), id, "", 100)
	if err != nil || !rollout.Paused || rollout.StopReason != "failed" {
		t.Fatal("failure did not pause rollout")
	}
	for _, job := range jobs {
		if job.AgentID == b.ID && (job.State != "cancelled" || !job.StoppedAfterFailure) {
			t.Fatal("remaining target not stopped")
		}
	}
	if body, err := f.server.desiredUpdate(context.Background(), b); err != nil || len(body) != 0 {
		t.Fatal("failed release spread to next target")
	}
}

func TestUpdateCancelledLateReadyIsOnlyHistoryAndInventoryPagingIsBounded(t *testing.T) {
	f := updateFixture(t)
	release := f.updateRelease(t, 24)
	a, _ := f.updateInventory(t, "agent-a", 23)
	f.updateInventory(t, "agent-b", 23)
	id := f.createUpdate(t, release, a.ID)
	plan := f.offerUpdate(t, a)
	if _, _, err := f.server.cancelUpdate(context.Background(), id, "operator"); err != nil {
		t.Fatal(err)
	}
	f.updateReport(t, plan, 1, "ready")
	_, jobs, _, err := f.server.updateRolloutDetail(context.Background(), id, "", 100)
	if err != nil || jobs[0].State != "cancelled" || !jobs[0].LateReport {
		t.Fatal("cancelled ready resumed")
	}
	items, next, total, err := f.server.listUpdateAgents(context.Background(), "", "", 1)
	if err != nil || len(items) != 1 || next == "" || total != 2 {
		t.Fatal("inventory paging")
	}
	items, _, _, err = f.server.listUpdateAgents(context.Background(), next, "", 1)
	if err != nil || len(items) != 1 || items[0].AgentID == a.ID {
		t.Fatal("inventory page repeated")
	}
}
