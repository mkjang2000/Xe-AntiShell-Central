package central

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type updateCountingReader struct {
	io.Reader
	reads int
}

func (r *updateCountingReader) Read(body []byte) (int, error) { r.reads++; return r.Reader.Read(body) }

func TestUpdatePublisherRejectedBeforeRPMBodyIsRead(t *testing.T) {
	f := updateFixture(t)
	send := updateAuthenticatedConsole(t, f)
	body, _ := json.Marshal(updatePackage(24))
	valid := f.signedUpdateBody(t, body, updatePackage(24))
	forged, err := managed.SignReleaseManifest(valid.Manifest, valid.KeyID, f.material.PolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		header string
	}{
		{"missing", ""}, {"non-json", base64.RawURLEncoding.EncodeToString([]byte("not a manifest"))},
		{"oversize", strings.Repeat("x", base64.RawURLEncoding.EncodedLen(managed.MaxReleaseManifestBytes)+1)},
		{"central-key", func() string { value, _ := json.Marshal(forged); return base64.RawURLEncoding.EncodeToString(value) }()},
		{"unknown-field", func() string {
			value, _ := json.Marshal(valid)
			value = append(value[:len(value)-1], []byte(`,"private_key":"SYNTHETIC_MUST_NOT_ECHO"}`)...)
			return base64.RawURLEncoding.EncodeToString(value)
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			counter := &updateCountingReader{Reader: bytes.NewReader(body)}
			r := httptest.NewRequest("POST", "http://localhost:9089/api/updates/releases", counter)
			r.ContentLength = -1
			r.Header.Set("Content-Type", "application/x-rpm")
			if test.header != "" {
				r.Header.Set("X-XEAS-Release-Manifest", test.header)
			}
			response := send(r)
			if response.Code != 400 || counter.reads != 0 {
				t.Fatalf("publisher rejected too late status%d reads%d", response.Code, counter.reads)
			}
			if strings.Contains(response.Body.String(), "SYNTHETIC_MUST_NOT_ECHO") {
				t.Fatal("untrusted manifest field echoed")
			}
		})
	}
}

func TestUpdatePublisherHashAndMetadataBoundBeforeActivation(t *testing.T) {
	f := updateFixture(t)
	body, _ := json.Marshal(updatePackage(24))
	signed := f.signedUpdateBody(t, body, updatePackage(24))
	calls := 0
	inspect := f.server.updateBlobs.inspect
	f.server.updateBlobs.inspect = func(ctx context.Context, path string) (managed.RPMPackage, string, error) {
		calls++
		return inspect(ctx, path)
	}
	changed := bytes.Clone(body)
	changed[0] = '!'
	if _, _, err := f.server.publishUpdateRelease(context.Background(), bytes.NewReader(changed), "admin", signed); err == nil || calls != 0 {
		t.Fatal("unsigned bytes reached native metadata query")
	}
	f.server.updateBlobs.inspect = func(context.Context, string) (managed.RPMPackage, string, error) { return updatePackage(25), "9", nil }
	if _, _, err := f.server.publishUpdateRelease(context.Background(), bytes.NewReader(body), "admin", signed); err == nil {
		t.Fatal("RPM header mismatch accepted")
	}
	items, err := listUpdateReleases(context.Background(), f.store.db)
	if err != nil || len(items) != 0 {
		t.Fatal("unverified publisher release activated")
	}
}

func TestUpdateSuccessRequiresPostRestartCollectionCheck(t *testing.T) {
	for _, accepted := range []string{"verified", "not_applicable"} {
		t.Run(accepted, func(t *testing.T) {
			f := updateFixture(t)
			release := f.updateRelease(t, 24)
			agent, _ := f.updateInventory(t, "agent-a", 23)
			id := f.createUpdate(t, release, agent.ID)
			plan := f.offerUpdate(t, agent)
			f.updateReport(t, plan, 1, "ready")
			if _, err := f.server.claimUpdate(context.Background(), agent, managed.UpdateClaim{JobID: plan.Plan.JobID, EnrollmentID: agent.EnrollmentID, Revision: plan.Plan.Revision}); err != nil {
				t.Fatal(err)
			}
			pack := release.Package
			report := managed.UpdateReport{ProtocolVersion: managed.UpdateProtocolVersion, JobID: plan.Plan.JobID, EnrollmentID: agent.EnrollmentID, Revision: plan.Plan.Revision, Sequence: 2, State: "succeeded", InstalledPackage: &pack, RunningVersion: pack.RunningVersion(), ObservedAt: f.server.now()}
			for _, rejected := range []string{"", "failed", "unknown"} {
				report.CollectionCheck = rejected
				if err := f.server.recordUpdateReport(context.Background(), agent, report); err == nil {
					t.Fatal("missing or failed collection verification confirmed success")
				}
			}
			report.CollectionCheck = accepted
			if err := f.server.recordUpdateReport(context.Background(), agent, report); err != nil {
				t.Fatal(err)
			}
			_, jobs, _, err := f.server.updateRolloutDetail(context.Background(), id, "", 100)
			if err != nil || jobs[0].State != "succeeded" || jobs[0].CollectionCheck != accepted {
				t.Fatal("collection verification missing from job result")
			}
		})
	}
}
