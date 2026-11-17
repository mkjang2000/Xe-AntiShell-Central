package central

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

// ValidateEnrollmentURL validates an explicit agent HTTPS origin before startup.
func ValidateEnrollmentURL(raw string) error {
	return managed.ValidateEnrollmentURL(raw)
}

// ConfigureEnrollmentURL enables complete installation codes. Call it before
// serving requests; NewServer leaves this optional feature disabled for legacy
// callers. An empty value disables issuance of complete installation codes.
func (s *Server) ConfigureEnrollmentURL(raw string) error {
	if raw == "" {
		s.enrollmentURL = ""
		return nil
	}
	if err := ValidateEnrollmentURL(raw); err != nil {
		return err
	}
	parsed, _ := url.Parse(raw)
	if len(s.material.Server.Certificate) == 0 || s.material.Server.PrivateKey == nil {
		return errors.New("central TLS server certificate is required for the enrollment URL")
	}
	certificate, err := x509.ParseCertificate(s.material.Server.Certificate[0])
	if err != nil {
		return errors.New("invalid central TLS server certificate")
	}
	if err = certificate.VerifyHostname(parsed.Hostname()); err != nil {
		return errors.New("enrollment URL hostname is not covered by the central TLS server certificate")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.material.CAPEM) {
		return errors.New("invalid central CA for the enrollment URL")
	}
	if _, err = certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: s.now().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("central TLS server certificate is not valid under the installation CA")
	}
	s.enrollmentURL = strings.TrimSuffix(raw, "/")
	return nil
}

func (s *Server) consoleEnrollment(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AgentID    string `json:"agent_id"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if !consoleDecode(w, r, 1024, &request) {
		return
	}
	if request.TTLSeconds == 0 {
		request.TTLSeconds = 3600
	}
	if !identifierPattern.MatchString(request.AgentID) || request.TTLSeconds < 1 || request.TTLSeconds > 86400 {
		s.consoleError(w, "enrollment input", fmt.Errorf("%w: 에이전트 ID와 유효 시간(1~86400초)을 확인하세요", ErrInvalid))
		return
	}
	token, err := randomToken()
	if err != nil {
		s.consoleError(w, "enrollment credential", err)
		return
	}
	now := s.now().UTC()
	expires := now.Add(time.Duration(request.TTLSeconds) * time.Second)
	response := map[string]any{"agent_id": request.AgentID, "token": token, "expires_at": expires}
	if s.enrollmentURL != "" {
		code, encodeErr := managed.EncodeInstallationCode(managed.InstallationCode{Version: "1", CentralURL: s.enrollmentURL, AgentID: request.AgentID, Token: token, CAPEM: string(s.material.CAPEM), ExpiresAt: expires})
		if encodeErr != nil {
			s.consoleError(w, "installation code", encodeErr)
			return
		}
		response["installation_code"] = code
	}
	digest := sha256.Sum256([]byte(token))
	tx, err := s.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.consoleError(w, "enrollment transaction", err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO enrollment_tokens(token_hash,agent_id,expires_at_ns) VALUES(?,?,?)", hex.EncodeToString(digest[:]), request.AgentID, expires.UnixNano()); err == nil {
		err = appendAudit(r.Context(), tx, request.AgentID, "console.enrollment.issued", map[string]any{"expires_at": expires}, now)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		_ = tx.Rollback()
		s.consoleError(w, "enrollment issuance", err)
		return
	}
	respond(w, http.StatusCreated, response)
}
