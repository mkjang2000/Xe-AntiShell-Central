package central

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestInstallationCodeIssuanceMatchesEnrollmentAndTrust(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	if err := f.server.ConfigureEnrollmentURL("https://localhost:9443"); err != nil {
		t.Fatal(err)
	}
	var issued struct {
		AgentID          string    `json:"agent_id"`
		Token            string    `json:"token"`
		ExpiresAt        time.Time `json:"expires_at"`
		InstallationCode string    `json:"installation_code"`
	}
	response := f.console(t, "POST", "/api/enrollment", map[string]any{"agent_id": "installation-agent", "ttl_seconds": 60})
	consoleWant(t, response, http.StatusCreated, &issued)
	code, err := managed.DecodeInstallationCode(issued.InstallationCode, now)
	if err != nil {
		t.Fatalf("issued installation code could not be decoded: %v", err)
	}
	if code.Version != "1" || code.CentralURL != "https://localhost:9443" || code.AgentID != issued.AgentID || code.Token != issued.Token || code.CAPEM != string(f.material.CAPEM) || !code.ExpiresAt.Equal(issued.ExpiresAt) || !code.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("installation code does not match the bound enrollment credential")
	}
	if _, err = managed.DecodeInstallationCode(issued.InstallationCode, issued.ExpiresAt); err == nil {
		t.Fatal("installation code accepted at expiration")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(code.CAPEM)) {
		t.Fatal("installation CA could not be loaded")
	}
	if _, err = handshake(f.material.TLSConfig(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"}); err != nil {
		t.Fatalf("installation code did not carry the server trust anchor: %v", err)
	}
	requestCSR, _ := csr(t, code.AgentID)
	if _, _, err = f.store.Enroll(context.Background(), code.Token, code.AgentID, requestCSR, f.material, now); err != nil {
		t.Fatalf("installation credential unusable: %v", err)
	}
	digest := sha256.Sum256([]byte(code.Token))
	var storedHash string
	if err = f.store.db.QueryRow("SELECT token_hash FROM enrollment_tokens WHERE agent_id=?", code.AgentID).Scan(&storedHash); err != nil || storedHash != hex.EncodeToString(digest[:]) {
		t.Fatal("enrollment credential was not stored only as a hash")
	}
	for _, path := range []string{"/api/state", "/api/audit?limit=500", "/api/history?limit=500"} {
		readback := f.console(t, "GET", path, nil)
		consoleWant(t, readback, http.StatusOK, nil)
		for _, secret := range []string{issued.Token, issued.InstallationCode, f.operator(t)} {
			if strings.Contains(readback.Body.String(), secret) {
				t.Fatalf("issuance secret disclosed by %s", path)
			}
		}
	}
	var state struct {
		Enrollment struct {
			CentralURL string `json:"central_url"`
			Ready      bool   `json:"ready"`
		} `json:"enrollment"`
	}
	consoleWant(t, f.console(t, "GET", "/api/state", nil), http.StatusOK, &state)
	if !state.Enrollment.Ready || state.Enrollment.CentralURL != code.CentralURL {
		t.Fatal("public enrollment readiness missing")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("installation code response can be cached")
	}
}

func TestUnconfiguredEnrollmentRetainsLegacyResponse(t *testing.T) {
	f := setup(t)
	var response map[string]json.RawMessage
	consoleWant(t, f.console(t, "POST", "/api/enrollment", map[string]any{"agent_id": "legacy"}), http.StatusCreated, &response)
	if len(response) != 3 || response["agent_id"] == nil || response["token"] == nil || response["expires_at"] == nil || response["installation_code"] != nil {
		t.Fatal("unconfigured server changed the legacy credential response")
	}
	var state struct {
		Enrollment struct {
			CentralURL string `json:"central_url"`
			Ready      bool   `json:"ready"`
		} `json:"enrollment"`
	}
	consoleWant(t, f.console(t, "GET", "/api/state", nil), http.StatusOK, &state)
	if state.Enrollment.Ready || state.Enrollment.CentralURL != "" {
		t.Fatal("new server enabled installation codes without an explicit URL")
	}
}

func TestConfigureEnrollmentURLRejectsInvalidOriginsAndCertificates(t *testing.T) {
	f := setup(t)
	for _, raw := range []string{"http://localhost:9443", "https://user:secret@localhost:9443", "https://localhost:9443/enroll", "https://localhost:9443?query", "https://localhost:9443#fragment", "https://localhost:0", "https://localhost:65536", "https://localhost:", "https://localhost:09443", "https://wrong.example:9443"} {
		if err := f.server.ConfigureEnrollmentURL(raw); err == nil || f.server.enrollmentURL != "" {
			t.Fatal("invalid origin or mismatched server name enabled installation codes")
		}
	}
	if err := f.server.ConfigureEnrollmentURL("https://localhost:9443/"); err != nil || f.server.enrollmentURL != "https://localhost:9443" {
		t.Fatalf("valid origin was not normalized: %v", err)
	}
	if err := f.server.ConfigureEnrollmentURL("https://wrong.example"); err == nil || f.server.enrollmentURL != "https://localhost:9443" {
		t.Fatal("failed reconfiguration changed the validated enrollment URL")
	}
	if err := f.server.ConfigureEnrollmentURL(""); err != nil || f.server.enrollmentURL != "" {
		t.Fatal("explicit disabling did not restore legacy issuance")
	}
	other := setup(t)
	f.material.CAPEM = other.material.CAPEM
	if err := f.server.ConfigureEnrollmentURL("https://localhost:9443"); err == nil {
		t.Fatal("installation CA that cannot verify the central certificate was accepted")
	}
	f.material.CAPEM = []byte("invalid CA")
	if err := f.server.ConfigureEnrollmentURL("https://localhost:9443"); err == nil {
		t.Fatal("malformed installation CA was accepted")
	}
	f.material.Server.Certificate = nil
	if err := f.server.ConfigureEnrollmentURL("https://localhost:9443"); err == nil {
		t.Fatal("missing central certificate was accepted")
	}
}

func TestInstallationEncodingFailureDoesNotPersistCredential(t *testing.T) {
	f := setup(t)
	if err := f.server.ConfigureEnrollmentURL("https://localhost:9443"); err != nil {
		t.Fatal(err)
	}
	// A runtime material inconsistency must fail before persisting a token.
	f.material.CAPEM = []byte("private-material-marker")
	response := f.console(t, "POST", "/api/enrollment", map[string]any{"agent_id": "never-issued"})
	consoleWant(t, response, http.StatusInternalServerError, nil)
	if strings.Contains(response.Body.String(), "private-material-marker") {
		t.Fatal("encoding failure exposed material")
	}
	for _, table := range []string{"enrollment_tokens", "audit"} {
		var count int
		if err := f.store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatal("failed installation issuance persisted an unused credential or audit record")
		}
	}
}
