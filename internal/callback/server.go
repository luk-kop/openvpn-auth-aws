package callback

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/config"
)

type Server struct {
	sessions  *auth.SessionStore
	exchanger auth.TokenExchanger
	signer    auth.StateSigner
	sink      auth.DecisionSink
	cfg       config.Config
	metrics   auth.Metrics
	server    *http.Server
}

func NewServer(sessions *auth.SessionStore, exchanger auth.TokenExchanger, signer auth.StateSigner, sink auth.DecisionSink, cfg config.Config, metrics auth.Metrics) *Server {
	return &Server{
		sessions:  sessions,
		exchanger: exchanger,
		signer:    signer,
		sink:      sink,
		cfg:       cfg,
		metrics:   metrics,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /callback", s.handleCallback)
	return mux
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	// Verify X-Internal-Token header (HMAC of body)
	token := r.Header.Get("X-Internal-Token")
	if token == "" || !s.signer.Verify(string(body), token) {
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	var req auth.CallbackRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Check timestamp ±30s
	now := time.Now().Unix()
	if abs(now-req.Timestamp) > 30 {
		http.Error(w, "timestamp out of range", http.StatusBadRequest)
		return
	}

	s.metrics.CallbackReceived()
	slog.Info("callback received", "session", req.SessionID)

	// Atomically transition PENDING → PROCESSING
	session, err := s.sessions.TryProcess(req.SessionID)
	if err != nil {
		if isNotFound(err) {
			slog.Warn("callback session not found", "session", req.SessionID)
			http.Error(w, "session not found", http.StatusNotFound)
		} else {
			slog.Warn("callback session not pending", "session", req.SessionID)
			http.Error(w, "session not pending", http.StatusConflict)
		}
		return
	}

	// Token exchange
	claims, err := s.exchanger.Exchange(r.Context(), req.Code, session.CodeVerifier, s.cfg.CognitoRedirectURI)
	if err != nil {
		slog.Error("callback token exchange failed", "cid", session.CID, "cn", session.CommonName, "error", err)
		s.metrics.TokenExchangeError("exchange_failed")
		s.sessions.MarkFailed(req.SessionID)
		s.sink.Send(auth.Decision{Type: auth.DecisionDeny, CID: session.CID, KID: session.KID, Reason: "token exchange failed"})
		http.Error(w, "token exchange failed", http.StatusForbidden)
		return
	}

	// Validate nonce (skip if exchanger didn't provide one, e.g. StaticExchanger)
	if claims.Nonce != "" && claims.Nonce != session.Nonce {
		slog.Warn("callback denied", "cid", session.CID, "cn", session.CommonName, "reason", "nonce mismatch")
		s.sessions.MarkFailed(req.SessionID)
		s.sink.Send(auth.Decision{Type: auth.DecisionDeny, CID: session.CID, KID: session.KID, Reason: "nonce mismatch"})
		http.Error(w, "nonce mismatch", http.StatusForbidden)
		return
	}

	// CN cross-check
	if session.CNCrossCheck && claims.Email != session.CommonName {
		slog.Warn("callback denied", "cid", session.CID, "cn", session.CommonName, "reason", "CN mismatch", "email", claims.Email)
		s.sessions.MarkFailed(req.SessionID)
		s.sink.Send(auth.Decision{Type: auth.DecisionDeny, CID: session.CID, KID: session.KID, Reason: fmt.Sprintf("CN mismatch: %s != %s", claims.Email, session.CommonName)})
		http.Error(w, "CN mismatch", http.StatusForbidden)
		return
	}

	// Group check
	if session.RequiredGroup != "" {
		found := false
		for _, g := range claims.Groups {
			if g == session.RequiredGroup {
				found = true
				break
			}
		}
		if !found {
			slog.Warn("callback denied", "cid", session.CID, "cn", session.CommonName, "reason", "group denied", "group", session.RequiredGroup)
			s.sessions.MarkFailed(req.SessionID)
			s.sink.Send(auth.Decision{Type: auth.DecisionDeny, CID: session.CID, KID: session.KID, Reason: fmt.Sprintf("not in required group: %s", session.RequiredGroup)})
			http.Error(w, "group check failed", http.StatusForbidden)
			return
		}
	}

	// Success
	s.sessions.MarkDone(req.SessionID)
	s.sink.Send(auth.Decision{Type: auth.DecisionAllow, CID: session.CID, KID: session.KID})
	slog.Info("callback auth success", "cid", session.CID, "cn", session.CommonName)
	s.metrics.AuthSuccess()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) Start(addr string) error {
	s.server = &http.Server{
		Addr:    addr,
		Handler: s.Handler(),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	slog.Info("callback server listening", "addr", addr)

	if err := s.server.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func isNotFound(err error) bool {
	return err != nil && err.Error() == "session not found"
}
