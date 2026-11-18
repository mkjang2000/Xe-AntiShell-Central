package central

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

func sampleReport(a contract.Assignment, pack managed.RPMPackage, at time.Time, hash string) contract.Report {
	samples := map[string]contract.Sample{}
	for id := range contract.Targets() {
		samples[id] = contract.Sample{State: "measured", SHA256: hash, MeasuredAt: at}
	}
	return contract.Report{Assignment: a, Package: pack, Samples: samples, RulePolicy: contract.Sample{State: "measured", SHA256: a.PolicySHA256, MeasuredAt: at}, CompletedAt: at}
}

func TestFileMeasurementConsoleLifecycle(t *testing.T) {
	ctx := context.Background()
	f := updateFixture(t)
	agent, cert := f.updateInventory(t, "files-agent", 34)
	_, otherCert := f.updateInventory(t, "other-agent", 34)
	f.consoleDrafts(t, []string{agent.ID})
	settings := defaultConsoleSettings(time.Now())
	expected := strings.Repeat("1", 64)
	settings.Integrity.PackageFiles = true
	settings.Integrity.ConfigSHA256 = expected
	consoleWant(t, f.console(t, "POST", "/api/templates", ConsoleTemplate{ID: "default", Name: "file policy", Version: 1, Settings: settings}), 200, nil)
	consoleWant(t, f.deploy(t, f.preview(t)), 200, nil)
	var a contract.Assignment
	consoleWant(t, f.request(t, "GET", "/v1/integrity/files", nil, cert, ""), 200, &a)
	if a.Revision != 1 || a.EnrollmentID != agent.EnrollmentID || !contract.ValidDigest(a.PolicySHA256) {
		t.Fatal(a)
	}
	consoleWant(t, f.request(t, "GET", "/v1/integrity/files", nil, otherCert, ""), 204, nil)
	consoleWant(t, f.request(t, "GET", "/v1/integrity/files", nil, nil, ""), 401, nil)
	now := f.server.now().UTC()
	pack := updatePackage(34)
	r := sampleReport(a, pack, now, expected)
	consoleWant(t, f.request(t, "POST", "/v1/integrity/files", r, otherCert, ""), 400, nil)
	endpoint := "/api/agents/" + agent.ID + "/integrity"
	result := func(want string) fileResult {
		t.Helper()
		var actual fileResult
		consoleWant(t, f.console(t, "GET", endpoint, nil), 200, &actual)
		if actual.State != want {
			t.Fatalf("want %s got %+v", want, actual)
		}
		return actual
	}
	result("unverified_support")
	hb := privilegeHeartbeat(agent.ID, agent.EnrollmentID, now)
	hb.Status.Version = pack.RunningVersion()
	hb.PolicyStatus = managed.PolicyStatus{ActiveRevision: 1, Result: "applied"}
	hb.Status.CapabilityReport.Capabilities["integrity.agent_files"] = model.Capability{Implementation: "implemented", Details: map[string]string{"contract": "1"}}
	if err := f.store.Heartbeat(ctx, agent.ID, hb, now); err != nil {
		t.Fatal(err)
	}
	result("awaiting_measurement")
	consoleWant(t, f.request(t, "POST", "/v1/integrity/files", r, cert, ""), 200, nil)
	original := result("baseline_missing").ReceivedAt
	f.server.now = func() time.Time { return now.Add(time.Minute) }

	consoleWant(t, f.request(t, "POST", "/v1/integrity/files", r, cert, ""), 200, nil)
	if actual := result("baseline_missing"); actual.Files[contract.ConfigID].Verdict != "matched" || actual.Files["signed-policy"].Verdict != "matched" {
		t.Fatal(actual)
	}
	if another := result("baseline_missing").ReceivedAt; original == nil || another == nil || !another.Equal(*original) {
		t.Fatal("replay refreshed original receipt")
	}
	f.server.now = func() time.Time { return now }

	release := f.updateRelease(t, 34)
	files := map[string]string{}
	for id := range contract.Targets() {
		if id != contract.ConfigID {
			files[id] = expected
		}
	}
	raw, _ := json.Marshal(files)
	if _, err := f.store.db.Exec("INSERT INTO integrity_package_files(release_id,files_json) VALUES(?,?)", release.ID, raw); err != nil {
		t.Fatal(err)
	}
	result("matched")
	r.RulePolicy.SHA256 = strings.Repeat("2", 64)
	consoleWant(t, f.request(t, "POST", "/v1/integrity/files", r, cert, ""), 409, nil)
	r.CompletedAt = r.CompletedAt.Add(time.Nanosecond)
	consoleWant(t, f.request(t, "POST", "/v1/integrity/files", r, cert, ""), 200, nil)
	if actual := result("mismatch"); actual.Files["signed-policy"].Verdict != "mismatch" {
		t.Fatal(actual)
	}
	r.Assignment.Revision++
	consoleWant(t, f.request(t, "POST", "/v1/integrity/files", r, cert, ""), 409, nil)
	f.server.now = func() time.Time { return now.Add(3 * time.Hour) }
	result("stale")
}

func TestFileVerdictClassification(t *testing.T) {
	now := time.Now()
	hash := strings.Repeat("1", 64)
	r := sampleReport(contract.Assignment{PolicySHA256: hash}, updatePackage(34), now, hash)
	files := map[string]string{}
	for id := range contract.Targets() {
		files[id] = hash
	}
	for _, tc := range []struct {
		state, stage, want string
		changed            bool
	}{{"measured", "", "approved_update", false}, {"measured", "", "mismatch", true}, {"missing", "", "missing", false}, {"unreadable", "", "unreadable", false}, {"changed_during_read", "", "changed_during_read", false}, {"measured", "update_in_progress", "update_in_progress", false}, {"measured", "inventory_unverified", "inventory_unverified", false}} {
		s := r.Samples["sentineld"]
		s.SHA256 = hash
		if tc.changed {
			s.SHA256 = strings.Repeat("2", 64)
		}
		s.State = tc.state
		r.Samples["sentineld"] = s
		if got := evaluateFileReport(fileResult{}, r, files, hash, tc.stage, true, now).State; got != tc.want {
			t.Fatalf("%+v: %s", tc, got)
		}
	}
}
