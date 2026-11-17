package central

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"
)

// net.Pipe performs a real TLS handshake without depending on the test runner
// being allowed to bind a TCP port.
func handshake(serverConfig, clientConfig *tls.Config) (tls.ConnectionState, error) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)
	server := tls.Server(serverConn, serverConfig)
	client := tls.Client(clientConn, clientConfig)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Handshake() }()
	clientErr := client.Handshake()
	readDone := make(chan struct{})
	if clientErr != nil {
		_ = clientConn.Close()
		close(readDone)
	} else {
		// TLS 1.3 may deliver a peer authentication alert just after the
		// client's handshake returns. Drain it so a net.Pipe alert write
		// cannot be mistaken for an otherwise unrelated deadline failure.
		go func() { _, _ = client.Read(make([]byte, 1)); close(readDone) }()
	}
	serverErr := <-serverDone
	_ = serverConn.Close()
	_ = clientConn.Close()
	<-readDone
	return server.ConnectionState(), errors.Join(clientErr, serverErr)
}

func clientCertificate(t *testing.T, certificatePEM string, private ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestTLSChecksCentralTrustAndAgentCA(t *testing.T) {
	f := setup(t)
	enrolled, _, private := f.enroll(t, "agent-a")
	pool := x509.NewCertPool()
	pool.AddCert(f.material.CA)
	clientConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{clientCertificate(t, enrolled.CertificatePEM, private)}}
	state, err := handshake(f.material.TLSConfig(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) != 1 || state.PeerCertificates[0].Subject.CommonName != "agent-a" {
		t.Fatalf("unexpected TLS identity/version: %#v", state)
	}
	bootstrapConfig := clientConfig.Clone()
	bootstrapConfig.Certificates = nil
	state, err = handshake(f.material.TLSConfig(), bootstrapConfig)
	if err != nil || len(state.PeerCertificates) != 0 {
		t.Fatalf("bootstrap TLS must allow no certificate: %v", err)
	}
	other := setup(t)
	rogue, _, rogueKey := other.enroll(t, "rogue")
	rogueConfig := clientConfig.Clone()
	rogueConfig.Certificates = []tls.Certificate{clientCertificate(t, rogue.CertificatePEM, rogueKey)}
	if _, err = handshake(f.material.TLSConfig(), rogueConfig); err == nil {
		t.Fatal("client from untrusted CA was accepted")
	}
	wrongTrust := clientConfig.Clone()
	wrongTrust.RootCAs = x509.NewCertPool()
	wrongTrust.RootCAs.AddCert(other.material.CA)
	if _, err = handshake(f.material.TLSConfig(), wrongTrust); err == nil {
		t.Fatal("client accepted server with untrusted CA")
	}
}
