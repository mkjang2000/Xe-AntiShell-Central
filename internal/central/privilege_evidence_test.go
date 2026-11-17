package central

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func credentialEventFixture() model.Event {
	uid, euid, gid, zero := uint32(1000), uint32(1000), uint32(1000), int64(0)
	before := &model.CredentialSnapshot{UID: &uid, EUID: &euid, GID: &gid, EGID: &gid, SUID: &uid, SGID: &gid, FSUID: &uid, FSGID: &gid, UserNamespace: &model.UserNamespace{Inum: 10}, Capabilities: &model.CredentialCapabilities{Effective: []string{}, Permitted: []string{}, Inheritable: []string{}}}
	after := before.Clone()
	root := uint32(0)
	after.EUID = &root
	return model.Event{ID: "credential-event", Type: "process.credential_change", Source: "tetragon", BootID: "boot", EventTime: time.Now().UTC(), Process: model.Process{PID: 33, ExecID: "source-exec", StartTime: time.Now().Add(-time.Minute)}, Credential: &model.CredentialObservation{Before: before, After: after, TGID: 33, TID: 34, TaskStartTimeNS: 123, Evidence: model.CredentialEvidence, PolicyName: model.CredentialPolicyName, Function: "commit_creds", ReturnValue: &zero, Outcome: "applied"}}
}
func TestCredentialEvidenceValidatedForSingleAndBundledRecords(t *testing.T) {
	for _, kind := range []string{"event", "event_bundle"} {
		t.Run(kind, func(t *testing.T) {
			event := credentialEventFixture()
			record := func(event model.Event) managed.Record {
				var value any = event
				if kind == "event_bundle" {
					value = map[string]any{"event": event, "findings": []any{}}
				}
				body, _ := json.Marshal(value)
				return managed.Record{Sequence: 1, Kind: kind, ID: event.ID, Payload: body}
			}
			if _, err := validateRecord(record(event)); err != nil {
				t.Fatal("valid paired evidence rejected", err)
			}
			for _, mutate := range []func(*model.Event){func(e *model.Event) { e.Credential.Before = nil }, func(e *model.Event) { e.Credential.TGID++ }, func(e *model.Event) { e.Credential.Evidence = "cached_exec" }, func(e *model.Event) { e.Source = "audit" }, func(e *model.Event) { e.Process.ExecID = "" }, func(e *model.Event) { e.Credential = nil }, func(e *model.Event) { e.Type = "process.exec" }} {
				bad := credentialEventFixture()
				mutate(&bad)
				if _, err := validateRecord(record(bad)); err == nil {
					t.Fatal("invalid credential proof accepted")
				}
			}
			unknown := credentialEventFixture()
			unknown.Credential.Before = nil
			unknown.Credential.Outcome = "unknown"
			if _, err := validateRecord(record(unknown)); err != nil {
				t.Fatal("explicit unknown observation rejected", err)
			}
		})
	}
}
