package central

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestRemovalDenialAndLifetimeBounds(t *testing.T) {
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	operator := f.operator(t)
	challenge, err := managed.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []int64{-1, 901, math.MaxInt64} {
		response := f.request(t, http.MethodPost, "/admin/removal", removalRequest{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Challenge: challenge, TTLSeconds: ttl}, nil, operator)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("TTL %d accepted: %d", ttl, response.Code)
		}
	}
	policy := managed.DefaultPolicy("agent-a", enrolled.EnrollmentID, 1, time.Now().UTC())
	policy.UninstallMode = "deny"
	response := f.request(t, http.MethodPost, "/admin/policy", policy, nil, operator)
	if response.Code != http.StatusCreated {
		t.Fatalf("policy=%d %s", response.Code, response.Body.String())
	}
	response = f.request(t, http.MethodPost, "/admin/removal", removalRequest{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Challenge: challenge}, nil, operator)
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied policy granted removal: %d", response.Code)
	}
	entries, err := f.store.Audit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Kind == "removal.authorized" {
			t.Fatal("rejected removal issued authorization")
		}
	}
}

func TestEnrollmentExpiresAndReplacedCertificateIsRejected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	token := f.token(t, "agent-a")
	requestCSR, _ := csr(t, "agent-a")
	if _, _, err := f.store.Enroll(ctx, token, "agent-a", requestCSR, f.material, time.Now().Add(2*time.Hour)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token error=%v", err)
	}
	_, oldCertificate, _ := f.enroll(t, "agent-a")
	_, newCertificate, _ := f.enroll(t, "agent-a")
	if response := f.request(t, http.MethodGet, "/v1/policy", nil, oldCertificate, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("replaced certificate accepted: %d", response.Code)
	}
	if response := f.request(t, http.MethodGet, "/v1/policy", nil, newCertificate, ""); response.Code != http.StatusNoContent {
		t.Fatalf("replacement certificate rejected: %d", response.Code)
	}
}

func TestMaterialRejectsMismatchedCAAndDirectorySymlink(t *testing.T) {
	f := setup(t)
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := privatePEM(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(key); block == nil {
		t.Fatal("invalid test key")
	}
	if err := os.WriteFile(filepath.Join(f.directory, "ca-key.pem"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMaterial(f.directory); err == nil {
		t.Fatal("mismatched CA signing key accepted")
	}
	link := filepath.Join(t.TempDir(), "central-link")
	if err := os.Symlink(f.directory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMaterial(link); err == nil {
		t.Fatal("symlinked central state directory accepted")
	}
}

func TestCentralStoreRejectsNewerSchemaAndSymlink(t *testing.T) {
	f := setup(t)
	if _, err := f.store.db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(context.Background(), filepath.Join(f.directory, "central.db")); err == nil {
		other.Close()
		t.Fatal("newer database schema accepted")
	}
	link := filepath.Join(t.TempDir(), "central.db")
	if err := os.Symlink(filepath.Join(f.directory, "central.db"), link); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(context.Background(), link); err == nil {
		other.Close()
		t.Fatal("symlinked database accepted")
	}
}
