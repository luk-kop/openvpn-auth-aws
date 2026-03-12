package callback

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/secrets"
)

type captureSink struct {
	decisions []auth.Decision
}

func (c *captureSink) Send(d auth.Decision) {
	c.decisions = append(c.decisions, d)
}

type fakeExchanger struct {
	claims *auth.IDTokenClaims
	err    error
}

func (e *fakeExchanger) Exchange(_ context.Context, _, _, _ string) (*auth.IDTokenClaims, error) {
	return e.claims, e.err
}

type fakeMetrics struct{}

func (fakeMetrics) Heartbeat(bool, int)        {}
func (fakeMetrics) AuthAttempt(string)          {}
func (fakeMetrics) AuthSuccess()                {}
func (fakeMetrics) AuthDenied(string)           {}
func (fakeMetrics) ReauthSuccess()              {}
func (fakeMetrics) ReauthDenied(string)         {}
func (fakeMetrics) ReauthCacheHit()             {}
func (fakeMetrics) CallbackReceived()           {}
func (fakeMetrics) TokenExchangeError(string)   {}

func newTestServer(exchanger auth.TokenExchanger) (*Server, *captureSink) {
	sessions := auth.NewSessionStore()
	signer := secrets.NewStaticSigner("test-secret")
	sink := &captureSink{}
	cfg := config.Config{CognitoRedirectURI: "https://example.com/callback"}
	srv := NewServer(sessions, exchanger, signer, sink, cfg, fakeMetrics{})
	return srv, sink
}

func TestCallbackHappyPath(t *testing.T) {
	exchanger := &fakeExchanger{
		claims: &auth.IDTokenClaims{
			Email: "user@example.com",
			Nonce: "test-nonce",
		},
	}
	srv, sink := newTestServer(exchanger)

	// Put a pending session
	srv.sessions.Put(&auth.PendingSession{
		SessionID:    "sid-1",
		CodeVerifier: "cv-1",
		Nonce:        "test-nonce",
		CommonName:   "user@example.com",
		CID:          "1",
		KID:          "1",
		CNCrossCheck: true,
		Status:       auth.SessionPending,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	})

	body := mustJSON(auth.CallbackRequest{Code: "auth-code", SessionID: "sid-1", Timestamp: time.Now().Unix()})
	signer := secrets.NewStaticSigner("test-secret")
	mac := signer.Sign(string(body))

	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", mac)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) != 1 || sink.decisions[0].Type != auth.DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %v", sink.decisions)
	}
}

func TestCallbackBadHMAC(t *testing.T) {
	srv, _ := newTestServer(&fakeExchanger{})

	body := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "sid-1", Timestamp: time.Now().Unix()})
	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", "bad-mac")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestCallbackExpiredTimestamp(t *testing.T) {
	srv, _ := newTestServer(&fakeExchanger{})
	signer := secrets.NewStaticSigner("test-secret")

	body := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "sid-1", Timestamp: time.Now().Add(-60 * time.Second).Unix()})
	mac := signer.Sign(string(body))

	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", mac)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCallbackSessionNotFound(t *testing.T) {
	srv, _ := newTestServer(&fakeExchanger{})
	signer := secrets.NewStaticSigner("test-secret")

	body := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "nonexistent", Timestamp: time.Now().Unix()})
	mac := signer.Sign(string(body))

	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", mac)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCallbackSessionConflict(t *testing.T) {
	exchanger := &fakeExchanger{
		claims: &auth.IDTokenClaims{Email: "user@example.com", Nonce: "nonce"},
	}
	srv, _ := newTestServer(exchanger)
	signer := secrets.NewStaticSigner("test-secret")

	srv.sessions.Put(&auth.PendingSession{
		SessionID: "sid-1",
		Status:    auth.SessionPending,
		Nonce:     "nonce",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	// First call should succeed (PENDING → PROCESSING)
	body := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "sid-1", Timestamp: time.Now().Unix()})
	mac := signer.Sign(string(body))

	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", mac)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first call: expected 200, got %d", w.Code)
	}

	// Second call should fail (already DONE)
	body2 := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "sid-1", Timestamp: time.Now().Unix()})
	mac2 := signer.Sign(string(body2))

	req2 := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body2))
	req2.Header.Set("X-Internal-Token", mac2)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Fatalf("second call: expected 409, got %d", w2.Code)
	}
}

func TestCallbackNonceMismatch(t *testing.T) {
	exchanger := &fakeExchanger{
		claims: &auth.IDTokenClaims{Email: "user@example.com", Nonce: "wrong-nonce"},
	}
	srv, sink := newTestServer(exchanger)
	signer := secrets.NewStaticSigner("test-secret")

	srv.sessions.Put(&auth.PendingSession{
		SessionID: "sid-1",
		Nonce:     "correct-nonce",
		CID:       "1",
		KID:       "1",
		Status:    auth.SessionPending,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	body := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "sid-1", Timestamp: time.Now().Unix()})
	mac := signer.Sign(string(body))

	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", mac)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if len(sink.decisions) != 1 || sink.decisions[0].Type != auth.DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %v", sink.decisions)
	}
}

func TestCallbackCNMismatch(t *testing.T) {
	exchanger := &fakeExchanger{
		claims: &auth.IDTokenClaims{Email: "other@example.com", Nonce: "nonce"},
	}
	srv, sink := newTestServer(exchanger)
	signer := secrets.NewStaticSigner("test-secret")

	srv.sessions.Put(&auth.PendingSession{
		SessionID:    "sid-1",
		Nonce:        "nonce",
		CommonName:   "user@example.com",
		CNCrossCheck: true,
		CID:          "1",
		KID:          "1",
		Status:       auth.SessionPending,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	})

	body := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "sid-1", Timestamp: time.Now().Unix()})
	mac := signer.Sign(string(body))

	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", mac)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if len(sink.decisions) != 1 || sink.decisions[0].Type != auth.DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %v", sink.decisions)
	}
}

func TestCallbackGroupCheckFailed(t *testing.T) {
	exchanger := &fakeExchanger{
		claims: &auth.IDTokenClaims{Email: "user@example.com", Nonce: "nonce", Groups: []string{"other-group"}},
	}
	srv, sink := newTestServer(exchanger)
	signer := secrets.NewStaticSigner("test-secret")

	srv.sessions.Put(&auth.PendingSession{
		SessionID:     "sid-1",
		Nonce:         "nonce",
		CommonName:    "user@example.com",
		RequiredGroup: "vpn-users",
		CID:           "1",
		KID:           "1",
		Status:        auth.SessionPending,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})

	body := mustJSON(auth.CallbackRequest{Code: "code", SessionID: "sid-1", Timestamp: time.Now().Unix()})
	mac := signer.Sign(string(body))

	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("X-Internal-Token", mac)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if len(sink.decisions) != 1 || sink.decisions[0].Type != auth.DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %v", sink.decisions)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
