package central

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type Server struct {
	store            *Store
	material         *Material
	logger           *slog.Logger
	now              func() time.Time
	enrollmentURL    string
	updateBlobs      *updateBlobStore
	updatePublishers map[string]ed25519.PublicKey
	updateGitHub     *updateGitHubClient
}
type authenticatedAgent struct{ ID, EnrollmentID string }

func NewServer(store *Store, material *Material, logger *slog.Logger) (*Server, error) {
	if store == nil || material == nil || len(material.OperatorHash) != sha256.Size {
		return nil, errors.New("central store and initialized material required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	blobs, err := newUpdateBlobStore(material.Directory)
	if err != nil {
		return nil, err
	}
	return &Server{store: store, material: material, logger: logger, now: time.Now, updateBlobs: blobs, updatePublishers: managed.BuiltinReleasePublisherKeys(), updateGitHub: newUpdateGitHubClient()}, nil
}

func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/ingest", s.withAgent(s.ingest))
	mux.HandleFunc("POST /v1/heartbeat", s.withAgent(s.heartbeat))
	mux.HandleFunc("GET /v1/policy", s.withAgent(s.policy))
	mux.HandleFunc("POST /v1/update/status", s.withAgent(s.updateStatus))
	mux.HandleFunc("GET /v1/update", s.withAgent(s.updateDesired))
	mux.HandleFunc("GET /v1/update/artifacts/{sha256}", s.withAgent(s.updateArtifact))
	mux.HandleFunc("POST /v1/update/claim", s.withAgent(s.updateClaim))
	mux.HandleFunc("POST /v1/update/report", s.withAgent(s.updateReport))
	return secureHeaders(mux)
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/agents", s.adminAgents)
	mux.HandleFunc("GET /admin/history", s.adminHistory)
	mux.HandleFunc("GET /admin/audit", s.adminAudit)
	mux.HandleFunc("POST /admin/policy", s.adminPolicy)
	mux.HandleFunc("POST /admin/removal", s.adminRemoval)
	mux.HandleFunc("POST /admin/revoke", s.adminRevoke)
	return secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		actual := sha256.Sum256([]byte(token))
		if len(token) > 256 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(actual[:], s.material.OperatorHash) != 1 {
			respond(w, http.StatusUnauthorized, map[string]string{"error": "operator authentication required"})
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

func (s *Server) withAgent(handler func(http.ResponseWriter, *http.Request, authenticatedAgent)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			respond(w, http.StatusUnauthorized, map[string]string{"error": "verified agent certificate required"})
			return
		}
		cert := r.TLS.PeerCertificates[0]
		if len(cert.Subject.OrganizationalUnit) != 1 {
			respond(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment identity"})
			return
		}
		agent := authenticatedAgent{ID: cert.Subject.CommonName, EnrollmentID: cert.Subject.OrganizationalUnit[0]}
		if err := s.store.Authenticate(r.Context(), agent.ID, agent.EnrollmentID, cert.SerialNumber.Text(16)); err != nil {
			respond(w, http.StatusUnauthorized, map[string]string{"error": "agent identity rejected"})
			return
		}
		handler(w, r, agent)
	}
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var request managed.EnrollRequest
	if !decodeRequest(w, r, 32<<10, &request) {
		return
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		respond(w, http.StatusUnauthorized, map[string]string{"error": "enrollment credential required"})
		return
	}
	enrollment, certificate, err := s.store.Enroll(r.Context(), strings.TrimPrefix(header, "Bearer "), request.AgentID, request.CSRPEM, s.material, s.now().UTC())
	if err != nil {
		s.apiError(w, "enrollment", err)
		return
	}
	respond(w, http.StatusCreated, managed.EnrollResponse{AgentID: request.AgentID, EnrollmentID: enrollment, CertificatePEM: certificate, CAPEM: string(s.material.CAPEM), PolicyKeyID: s.material.PolicyKeyID, PolicyPublicKey: managed.EncodePublicKey(s.material.PolicyKey.Public().(ed25519.PublicKey))})
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	var batch managed.Batch
	if !decodeRequest(w, r, 4<<20, &batch) {
		return
	}
	if batch.EnrollmentID != agent.EnrollmentID {
		respond(w, http.StatusForbidden, map[string]string{"error": "enrollment mismatch"})
		return
	}
	ack, err := s.store.Ingest(r.Context(), agent.ID, batch, s.now().UTC())
	if err != nil {
		s.apiError(w, "ingest", err)
		return
	}
	respond(w, http.StatusOK, ack)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	var heartbeat managed.Heartbeat
	if !decodeRequest(w, r, managed.MaxHeartbeatBytes, &heartbeat) {
		return
	}
	if heartbeat.AgentID != agent.ID || heartbeat.EnrollmentID != agent.EnrollmentID {
		respond(w, http.StatusForbidden, map[string]string{"error": "agent identity mismatch"})
		return
	}
	if len(heartbeat.Hostname) > 255 {
		respond(w, http.StatusBadRequest, map[string]string{"error": "hostname too long"})
		return
	}
	if err := s.store.Heartbeat(r.Context(), agent.ID, heartbeat, s.now().UTC()); err != nil {
		s.apiError(w, "heartbeat", err)
		return
	}
	respond(w, http.StatusOK, map[string]time.Time{"received_at": s.now().UTC()})
}

func (s *Server) policy(w http.ResponseWriter, r *http.Request, agent authenticatedAgent) {
	policy, err := s.store.LatestPolicy(r.Context(), agent.ID, agent.EnrollmentID)
	if errors.Is(err, ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		s.apiError(w, "policy", err)
		return
	}
	respond(w, http.StatusOK, policy)
}

func (s *Server) apiError(w http.ResponseWriter, operation string, err error) {
	status := http.StatusInternalServerError
	message := "central storage or service unavailable"
	switch {
	case errors.Is(err, errHistoryTimeout):
		status = http.StatusServiceUnavailable
		message = "history query timed out; narrow the period, agent or type"
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, ErrInvalid):
		status = http.StatusBadRequest
		message = "request rejected"
	case errors.Is(err, ErrUnauthorized):
		status = http.StatusUnauthorized
		message = "authorization rejected"
	case errors.Is(err, ErrConflict):
		status = http.StatusConflict
		message = "immutable record or delivery conflict"
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
		message = "record not found"
	default:
		s.logger.Warn("central request rejected", "operation", operation, "error", err)
	}
	respond(w, status, map[string]string{"error": message})
}

func decodeRequest(w http.ResponseWriter, r *http.Request, maximum int64, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maximum)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		err = managed.DecodeStrict(body, int(maximum), value)
	}
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized JSON request"})
		return false
	}
	return true
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func HTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
}
func Listen(address string, loopbackOnly bool) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || (loopbackOnly && !ip.IsLoopback()) {
		return nil, errors.New("listener requires an allowed literal IP")
	}
	return net.Listen("tcp", address)
}
