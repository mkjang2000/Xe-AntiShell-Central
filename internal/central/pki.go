package central

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Material is loaded only by the central service. Private keys are never sent
// to agents; enrollment issues a certificate for the agent's own CSR key.
type Material struct {
	Directory    string
	CA           *x509.Certificate
	CAKey        crypto.Signer
	CAPEM        []byte
	Server       tls.Certificate
	PolicyKey    ed25519.PrivateKey
	PolicyKeyID  string
	OperatorHash []byte
}

type stateConfig struct {
	Version      int    `json:"version"`
	PolicyKeyID  string `json:"policy_key_id"`
	OperatorHash string `json:"operator_hash"`
}

func Initialize(directory string, hosts []string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("central state directory must be absolute")
	}
	if _, err := os.Stat(filepath.Join(directory, "state.json")); err == nil {
		return errors.New("central state is already initialized")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("central state directory must be a directory without symlinks")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Xe-AntiShell Central CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Xe-AntiShell Central"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			return errors.New("empty certificate host")
		}
		if address := net.ParseIP(host); address != nil {
			serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, address)
		} else {
			serverTemplate.DNSNames = append(serverTemplate.DNSNames, host)
		}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, serverPub, caPriv)
	if err != nil {
		return err
	}
	_, policyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	operator, err := randomToken()
	if err != nil {
		return err
	}
	operatorHash := sha256.Sum256([]byte(operator))
	policyHash := sha256.Sum256(policyPriv.Public().(ed25519.PublicKey))
	config := stateConfig{Version: 1, PolicyKeyID: "policy_" + hex.EncodeToString(policyHash[:8]), OperatorHash: hex.EncodeToString(operatorHash[:])}
	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	caPrivate, err := privatePEM(caPriv)
	if err != nil {
		return err
	}
	serverPrivate, err := privatePEM(serverPriv)
	if err != nil {
		return err
	}
	files := []struct {
		name string
		body []byte
	}{
		{"ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})},
		{"ca-key.pem", caPrivate}, {"server.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})},
		{"server-key.pem", serverPrivate}, {"policy-key", []byte(base64.StdEncoding.EncodeToString(policyPriv) + "\n")},
		{"operator-token", []byte(operator + "\n")}, {"state.json", append(configBytes, '\n')},
	}
	for _, file := range files {
		if err := writePrivateExclusive(filepath.Join(directory, file.name), file.body); err != nil {
			return err
		}
	}
	return nil
}

func LoadMaterial(directory string) (*Material, error) {
	if err := privateDirectory(directory); err != nil {
		return nil, err
	}
	read := func(name string) ([]byte, error) {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("central %s must be a private regular file", name)
		}
		if info.Size() > 1<<20 {
			return nil, errors.New("central key file too large")
		}
		return os.ReadFile(path)
	}
	configBytes, err := read("state.json")
	if err != nil {
		return nil, err
	}
	var config stateConfig
	if err = json.Unmarshal(configBytes, &config); err != nil {
		return nil, err
	}
	if config.Version != 1 {
		return nil, errors.New("unsupported central state version")
	}
	caPEM, err := read("ca.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, errors.New("invalid central CA")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	caKeyPEM, err := read("ca-key.pem")
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return nil, errors.New("invalid CA key")
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	caKey, ok := private.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid CA signer")
	}
	caPublic, err := x509.MarshalPKIXPublicKey(caKey.Public())
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || !bytes.Equal(ca.RawSubjectPublicKeyInfo, caPublic) {
		return nil, errors.New("central CA certificate and signer do not match")
	}
	serverPEM, err := read("server.pem")
	if err != nil {
		return nil, err
	}
	serverKey, err := read("server-key.pem")
	if err != nil {
		return nil, err
	}
	server, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		return nil, err
	}
	policyBytes, err := read("policy-key")
	if err != nil {
		return nil, err
	}
	policyKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(policyBytes)))
	if err != nil || len(policyKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid policy key")
	}
	operatorHash, err := hex.DecodeString(config.OperatorHash)
	if err != nil || len(operatorHash) != sha256.Size {
		return nil, errors.New("invalid operator credential hash")
	}
	return &Material{Directory: directory, CA: ca, CAKey: caKey, CAPEM: caPEM, Server: server, PolicyKey: ed25519.PrivateKey(policyKey), PolicyKeyID: config.PolicyKeyID, OperatorHash: operatorHash}, nil
}

func privateDirectory(directory string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("central state directory must be absolute")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("central state directory must be a private directory")
	}
	return nil
}

func (m *Material) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(m.CA)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{m.Server}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}
}

func (m *Material) IssueClient(csrPEM, agentID, enrollmentID string, now time.Time) ([]byte, string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", errors.New("invalid certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, "", errors.New("invalid CSR signature")
	}
	switch key := csr.PublicKey.(type) {
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, "", errors.New("invalid Ed25519 key")
		}
	default:
		return nil, "", errors.New("enrollment requires an Ed25519 client key")
	}
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: agentID, OrganizationalUnit: []string{enrollmentID}}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(0, 0, 90), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, m.CA, csr.PublicKey, m.CAKey)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), template.SerialNumber.Text(16), nil
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
func serial() *big.Int {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic("cryptographic random unavailable")
	}
	return value
}
func privatePEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func writePrivateExclusive(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(body); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	success = true
	return nil
}
