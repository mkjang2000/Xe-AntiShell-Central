package central

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func TestTrialGuardsGroupChangesUnsupportedTargetsAndExpiredExceptions(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	enroll, _, _ := f.enroll(t, "host-a")
	id := enroll.EnrollmentID
	old := managed.DefaultPolicy("host-a", id, 1, now)
	signed, err := managed.SignPolicy(old, f.material.PolicyKeyID, f.material.PolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.AssignPolicy(ctx, signed, now); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Minute)
	settings := defaultConsoleSettings(now)
	settings.Detection.WebServices = []string{"example.service"}
	settings.Detection.ServiceRuleControls = []managed.ServiceRuleControl{{Service: "example.service", RuleID: managed.RuleServiceProtectedFileWrite, Mode: "suppress_until", Reason: "승인 작업", ExpiresAt: &expires}}
	tpl, err := f.store.saveConsoleTemplate(ctx, ConsoleTemplate{ID: "trial", Name: "example", Settings: settings}, now)
	if err != nil {
		t.Fatal(err)
	}
	group, err := f.store.saveConsoleGroup(ctx, ConsoleGroup{ID: "group", Name: "group", AgentIDs: []string{"host-a"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	hb := managed.Heartbeat{AgentID: "host-a", EnrollmentID: id, SentAt: now, Status: model.AgentStatus{Health: "healthy"}, PolicyStatus: managed.PolicyStatus{ActiveRevision: 1, DesiredRevision: 1, Result: "applied", AppliedAt: &now}}
	if err = f.store.Heartbeat(ctx, "host-a", hb, now); err != nil {
		t.Fatal(err)
	}
	req := consolePreviewRequest{TemplateID: tpl.ID, GroupIDs: []string{group.ID}}
	getSnap := func() (consolePreviewToken, error) {
		tx, err := f.store.db.BeginTx(ctx, nil)
		if err != nil {
			return consolePreviewToken{}, err
		}
		defer tx.Rollback()
		s, _, err := consoleSnapshot(ctx, tx, req, now)
		s.IssuedAt = now
		s.Nonce = "guard"
		return s, err
	}
	if _, err := getSnap(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported %v", err)
	}
	hb.Status.CapabilityReport = &model.CapabilityReport{Capabilities: map[string]model.Capability{"detection.service_rule_controls": {Implementation: "implemented", RuntimeState: "available", Details: map[string]string{"contract": "1"}}}}
	if err = f.store.Heartbeat(ctx, "host-a", hb, now); err != nil {
		t.Fatal(err)
	}
	snap, err := getSnap()
	if err != nil {
		t.Fatal(err)
	}
	tr := policyTrial{ID: "trial-guard", Canary: "host-a", Phase: "prepared", Snapshot: snap, Template: tpl}
	plan := func(at time.Time) error {
		tx, err := f.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer tx.Rollback()
		_, err = tr.plan(ctx, tx, trialAction{Action: "canary", Phase: "prepared"}, at)
		return err
	}
	if err := plan(expires); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired comparison: %v", err)
	}
	group.Name = "renamed"
	if _, err = f.store.saveConsoleGroup(ctx, group, now); err != nil {
		t.Fatal(err)
	}
	if err := plan(now); !errors.Is(err, ErrConflict) {
		t.Fatalf("group mutation: %v", err)
	}
}
