package central

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

type fixture struct {
	store     *Store
	material  *Material
	server    *Server
	directory string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	directory := t.TempDir()
	if err := Initialize(directory, nil); err != nil {
		t.Fatal(err)
	}
	material, err := LoadMaterial(directory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), filepath.Join(directory, "central.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	server, err := NewServer(store, material, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{store: store, material: material, server: server, directory: directory}
}

func csr(t *testing.T, agent string) (string, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agent}}, private)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), private
}
func (f *fixture) token(t *testing.T, agent string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := f.store.CreateEnrollmentToken(context.Background(), agent, time.Hour, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}
func (f *fixture) enroll(t *testing.T, agent string) (managed.EnrollResponse, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	requestCSR, private := csr(t, agent)
	request := managed.EnrollRequest{AgentID: agent, CSRPEM: requestCSR}
	response := f.request(t, http.MethodPost, "/v1/enroll", request, nil, f.token(t, agent))
	if response.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", response.Code, response.Body.String())
	}
	var enrolled managed.EnrollResponse
	if err := json.Unmarshal(response.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(enrolled.CertificatePEM))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.material.CA)
	if _, err = certificate.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	return enrolled, certificate, private
}
func (f *fixture) request(t *testing.T, method, path string, value any, certificate *x509.Certificate, token string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if value != nil {
		var err error
		data, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "https://localhost"+path, bytes.NewReader(data))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if certificate != nil {
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate, f.material.CA}}}
	}
	response := httptest.NewRecorder()
	if strings.HasPrefix(path, "/admin/") {
		f.server.AdminHandler().ServeHTTP(response, request)
	} else {
		f.server.AgentHandler().ServeHTTP(response, request)
	}
	return response
}
func (f *fixture) operator(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.directory, "operator-token"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestEnrollmentSingleUseScopedAndPrivate(t *testing.T) {
	f := setup(t)
	requestCSR, _ := csr(t, "agent-a")
	token := f.token(t, "agent-a")
	wrong := f.request(t, http.MethodPost, "/v1/enroll", managed.EnrollRequest{AgentID: "agent-b", CSRPEM: requestCSR}, nil, token)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token target accepted: %d", wrong.Code)
	}
	valid := f.request(t, http.MethodPost, "/v1/enroll", managed.EnrollRequest{AgentID: "agent-a", CSRPEM: requestCSR}, nil, token)
	if valid.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", valid.Code, valid.Body.String())
	}
	replay := f.request(t, http.MethodPost, "/v1/enroll", managed.EnrollRequest{AgentID: "agent-a", CSRPEM: requestCSR}, nil, token)
	if replay.Code != http.StatusCreated || !bytes.Equal(replay.Body.Bytes(), valid.Body.Bytes()) {
		t.Fatalf("lost enrollment response could not be retrieved idempotently: %d", replay.Code)
	}
	differentCSR, _ := csr(t, "agent-a")
	changed := f.request(t, http.MethodPost, "/v1/enroll", managed.EnrollRequest{AgentID: "agent-a", CSRPEM: differentCSR}, nil, token)
	if changed.Code != http.StatusUnauthorized {
		t.Fatalf("consumed token reused for a different client key: %d", changed.Code)
	}
	for _, name := range []string{"ca-key.pem", "server-key.pem", "policy-key", "operator-token", "state.json", "central.db"} {
		info, err := os.Stat(filepath.Join(f.directory, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private file %s info=%v err=%v", name, info, err)
		}
	}
	if err := Initialize(f.directory, nil); err == nil {
		t.Fatal("central initialization overwrote existing state")
	}
}

func eventRecord(t *testing.T, sequence uint64, id string) managed.Record {
	t.Helper()
	event := model.Event{ID: id, SchemaVersion: model.SchemaVersion, Type: "process.exec", Source: "test", EventTime: time.Unix(100, 0).UTC(), IngestTime: time.Unix(101, 0).UTC(), Sequence: 1000 + sequence*100}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return managed.Record{Sequence: sequence, Kind: "event", ID: id, Payload: data}
}

func TestDurableAckDedupAndConflictRollback(t *testing.T) {
	f := setup(t)
	enrolled, certificate, _ := f.enroll(t, "agent-a")
	batch := managed.Batch{EnrollmentID: enrolled.EnrollmentID, SpoolID: "spool-generation-1", Records: []managed.Record{eventRecord(t, 1, "event-1"), eventRecord(t, 2, "event-2")}}
	missing := f.request(t, http.MethodPost, "/v1/ingest", batch, nil, "")
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing certificate accepted: %d", missing.Code)
	}
	for _, iteration := range []string{"first", "lost-response retry"} {
		response := f.request(t, http.MethodPost, "/v1/ingest", batch, certificate, "")
		var ack managed.Ack
		_ = json.Unmarshal(response.Body.Bytes(), &ack)
		if response.Code != http.StatusOK || ack.Acknowledged != 2 || ack.SpoolID != batch.SpoolID {
			t.Fatalf("%s ack=%#v status=%d", iteration, ack, response.Code)
		}
	}
	rows, err := f.store.History(context.Background(), "agent-a", "event", 100)
	if err != nil || len(rows) != 2 {
		t.Fatalf("dedup rows=%d err=%v", len(rows), err)
	}
	conflicting := batch
	conflicting.Records = append([]managed.Record(nil), batch.Records...)
	conflicting.Records[0] = eventRecord(t, 1, "different-id")
	response := f.request(t, http.MethodPost, "/v1/ingest", conflicting, certificate, "")
	if response.Code != http.StatusConflict {
		t.Fatalf("conflicting retry=%d", response.Code)
	}
	gap := batch
	gap.Records = []managed.Record{eventRecord(t, 3, "event-3"), eventRecord(t, 5, "event-5")}
	response = f.request(t, http.MethodPost, "/v1/ingest", gap, certificate, "")
	if response.Code != http.StatusConflict && response.Code != http.StatusBadRequest {
		t.Fatalf("gapped delivery=%d", response.Code)
	}
	rows, err = f.store.History(context.Background(), "agent-a", "event", 100)
	if err != nil || len(rows) != 2 {
		t.Fatalf("batch partially committed: rows=%d err=%v", len(rows), err)
	}
	batch.EnrollmentID = "other-generation"
	response = f.request(t, http.MethodPost, "/v1/ingest", batch, certificate, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong enrollment accepted=%d", response.Code)
	}
}

func TestRecordCanonicalizationPreservesLargeSourceIntegers(t *testing.T) {
	record := eventRecord(t, 1, "large-source-sequence")
	var event model.Event
	if err := json.Unmarshal(record.Payload, &event); err != nil {
		t.Fatal(err)
	}
	event.Sequence = 9007199254740993
	record.Payload, _ = json.Marshal(event)
	body, err := validateRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	var stored model.Event
	if err := json.Unmarshal(body, &stored); err != nil || stored.Sequence != event.Sequence {
		t.Fatalf("source sequence rounded during ingestion: got=%d want=%d error=%v", stored.Sequence, event.Sequence, err)
	}
}

func TestPolicyHeartbeatRemovalAndRevocation(t *testing.T) {
	f := setup(t)
	enrolled, certificate, _ := f.enroll(t, "agent-a")
	other, otherCertificate, _ := f.enroll(t, "agent-b")
	operator := f.operator(t)
	response := f.request(t, http.MethodGet, "/v1/policy", nil, certificate, "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("default must not replace host policy: %d", response.Code)
	}
	policy := managed.DefaultPolicy("agent-a", enrolled.EnrollmentID, 1, time.Now().UTC())
	response = f.request(t, http.MethodPost, "/admin/policy", policy, nil, operator)
	if response.Code != http.StatusCreated {
		t.Fatalf("assign policy %d %s", response.Code, response.Body.String())
	}
	response = f.request(t, http.MethodGet, "/v1/policy", nil, certificate, "")
	var signed managed.SignedPolicy
	if err := json.Unmarshal(response.Body.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.VerifyPolicy(signed, map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}, "agent-a", enrolled.EnrollmentID, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	response = f.request(t, http.MethodGet, "/v1/policy", nil, otherCertificate, "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("agent-b received agent-a policy: %d", response.Code)
	}
	response = f.request(t, http.MethodPost, "/v1/heartbeat", managed.Heartbeat{AgentID: "agent-a", EnrollmentID: other.EnrollmentID, Hostname: "spoofed"}, otherCertificate, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross agent heartbeat accepted %d", response.Code)
	}
	response = f.request(t, http.MethodPost, "/v1/heartbeat", managed.Heartbeat{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Hostname: "host-a", Status: model.AgentStatus{Health: model.HealthHealthy}}, certificate, "")
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat %d", response.Code)
	}
	challenge, err := managed.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	response = f.request(t, http.MethodPost, "/admin/removal", removalRequest{AgentID: "agent-a", EnrollmentID: enrolled.EnrollmentID, Challenge: challenge, TTLSeconds: 60}, nil, operator)
	if response.Code != http.StatusCreated {
		t.Fatalf("removal %d %s", response.Code, response.Body.String())
	}
	var grant managed.SignedRemovalGrant
	if err = json.Unmarshal(response.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if _, err = managed.VerifyRemovalGrant(grant, map[string]ed25519.PublicKey{f.material.PolicyKeyID: f.material.PolicyKey.Public().(ed25519.PublicKey)}, "agent-a", enrolled.EnrollmentID, challenge, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	audit, err := f.store.Audit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range audit {
		if entry.Kind == "removal.authorized" {
			found = true
		}
	}
	if !found {
		t.Fatal("removal issued before durable audit")
	}
	response = f.request(t, http.MethodPost, "/admin/revoke", map[string]string{"agent_id": "agent-a"}, nil, operator)
	if response.Code != http.StatusOK {
		t.Fatalf("revoke=%d", response.Code)
	}
	response = f.request(t, http.MethodGet, "/v1/policy", nil, certificate, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked identity accepted=%d", response.Code)
	}
	response = f.request(t, http.MethodGet, "/admin/agents", nil, nil, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unguarded operator API=%d", response.Code)
	}
}
