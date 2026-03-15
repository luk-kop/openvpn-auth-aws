package callback

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/secrets"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

type captureSink struct {
	decisions []auth.Decision
}

func (c *captureSink) Send(d auth.Decision) {
	c.decisions = append(c.decisions, d)
}

type fakeMetrics struct{}

func (fakeMetrics) Heartbeat(bool, int)       {}
func (fakeMetrics) AuthAttempt(string)        {}
func (fakeMetrics) AuthSuccess()              {}
func (fakeMetrics) AuthDenied(string)         {}
func (fakeMetrics) ReauthSuccess()            {}
func (fakeMetrics) ReauthDenied(string)       {}
func (fakeMetrics) ReauthCacheHit()           {}
func (fakeMetrics) CallbackReceived()         {}
func (fakeMetrics) TokenExchangeError(string) {}

// fakeGroupsChecker implements GroupsChecker for tests.
type fakeGroupsChecker struct {
	inGroup bool
	err     error
}

func (f *fakeGroupsChecker) CheckUser(_ context.Context, _, _ string, _ bool) (auth.IdentityResult, error) {
	return auth.IdentityResult{InGroup: f.inGroup}, f.err
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestServer builds a Server with sensible defaults for unit tests.
// albARN is empty by default (dev mode — skip JWT signature validation).
func newTestServer(cfg config.Config, identity GroupsChecker) (*Server, *captureSink) {
	sessions := auth.NewSessionStore()
	signer := secrets.NewStaticSigner("test-secret")
	sink := &captureSink{}
	srv := NewServer(sessions, signer, sink, cfg, fakeMetrics{}, identity, func() bool { return true })
	return srv, sink
}

// newTestServerWithSessions builds a Server and returns the session store too.
func newTestServerWithSessions(cfg config.Config, identity GroupsChecker) (*Server, *auth.SessionStore, *captureSink) {
	sessions := auth.NewSessionStore()
	signer := secrets.NewStaticSigner("test-secret")
	sink := &captureSink{}
	srv := &Server{
		sessions:      sessions,
		signer:        signer,
		sink:          sink,
		cfg:           cfg,
		metrics:       fakeMetrics{},
		identity:      identity,
		albARN:        cfg.ALBARN,
		awsRegion:     cfg.AWSRegion,
		keyCache:      make(map[string]*ecdsa.PublicKey),
		mgmtConnected: func() bool { return true },
		startTime:     time.Now(),
	}
	return srv, sessions, sink
}

// validStateParam creates a valid HMAC-signed state blob for the given session ID.
func validStateParam(t *testing.T, sid string) string {
	t.Helper()
	signer := secrets.NewStaticSigner("test-secret")
	return auth.EncodeState(auth.StatePayload{
		SID: sid,
		IAT: time.Now().Unix(),
		EXP: time.Now().Add(5 * time.Minute).Unix(),
	}, signer)
}

// expiredStateParam creates an expired state blob.
func expiredStateParam(t *testing.T, sid string) string {
	t.Helper()
	signer := secrets.NewStaticSigner("test-secret")
	return auth.EncodeState(auth.StatePayload{
		SID: sid,
		IAT: time.Now().Add(-10 * time.Minute).Unix(),
		EXP: time.Now().Add(-1 * time.Minute).Unix(),
	}, signer)
}

// makeUnsignedJWT builds a minimal unsigned JWT (header.claims.) for dev-mode tests.
func makeUnsignedJWT(email, sub string, groups []string, exp int64) string {
	header := map[string]interface{}{
		"alg": "none",
		"kid": "test-kid",
	}
	claims := map[string]interface{}{
		"email":          email,
		"sub":            sub,
		"iss":            "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test",
		"exp":            exp,
		"cognito:groups": groups,
	}
	hBytes, _ := json.Marshal(header)
	cBytes, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(hBytes)
	c := base64.RawURLEncoding.EncodeToString(cBytes)
	return h + "." + c + "."
}

// makeSignedJWT builds a real ES256-signed JWT for ALB validation tests.
func makeSignedJWT(t *testing.T, key *ecdsa.PrivateKey, kid, signerARN, email, sub string, exp int64) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"email": email,
		"sub":   sub,
		"iss":   "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test",
		"exp":   exp,
	})
	token.Header["kid"] = kid
	token.Header["signer"] = signerARN
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// addSessionPending adds a pending session to the store and returns it.
func addSessionPending(sessions *auth.SessionStore, sid, cid, kid, cn string) *auth.PendingSession {
	sess := &auth.PendingSession{
		SessionID:  sid,
		CommonName: cn,
		CID:        cid,
		KID:        kid,
		Status:     auth.SessionPending,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	sessions.Put(sess)
	return sess
}

// defaultCfg returns a minimal config suitable for unit tests (dev mode: no ALBARN).
func defaultCfg() config.Config {
	return config.Config{
		AWSRegion: "eu-west-1",
	}
}

// ---------------------------------------------------------------------------
// handleCallback unit tests (subtask 5.4)
// ---------------------------------------------------------------------------

func TestHandleCallback_MissingState(t *testing.T) {
	srv, _ := newTestServer(defaultCfg(), nil)
	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleCallback_InvalidStateHMAC(t *testing.T) {
	srv, _ := newTestServer(defaultCfg(), nil)
	valid := validStateParam(t, "some-sid")
	parts := strings.SplitN(valid, ".", 2)
	tampered := parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+tampered, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCallback_ExpiredState(t *testing.T) {
	srv, _ := newTestServer(defaultCfg(), nil)
	state := expiredStateParam(t, "some-sid")

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCallback_SessionNotFound(t *testing.T) {
	srv, _, _ := newTestServerWithSessions(defaultCfg(), nil)
	state := validStateParam(t, "nonexistent-sid")

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCallback_SessionNotPending(t *testing.T) {
	srv, sessions, _ := newTestServerWithSessions(defaultCfg(), nil)
	sid := "already-processing"
	addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")
	_, _ = sessions.TryProcess(sid)

	state := validStateParam(t, sid)
	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCallback_ALBJWTValidationFailure(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const albARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/test/abc"
	cfg := config.Config{
		AWSRegion: "eu-west-1",
		ALBARN:    albARN,
	}

	srv, sessions, sink := newTestServerWithSessions(cfg, nil)
	// Cache the WRONG public key so signature verification fails.
	srv.keyCache["test-kid"] = &wrongKey.PublicKey

	sid := "jwt-fail-sid"
	addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")

	tokenStr := makeSignedJWT(t, privKey, "test-kid", albARN, "user@example.com", "sub123", time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", tokenStr)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionDeny {
		t.Fatalf("expected client-deny decision, got %+v", sink.decisions)
	}
}

func TestHandleCallback_GroupCheckFailure(t *testing.T) {
	cfg := defaultCfg()
	identity := &fakeGroupsChecker{inGroup: false}
	srv, sessions, sink := newTestServerWithSessions(cfg, identity)

	sid := "group-fail-sid"
	sess := addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")
	sess.RequiredGroup = "vpn-users"

	oidcJWT := makeUnsignedJWT("user@example.com", "sub123", []string{"other-group"}, time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", oidcJWT)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionDeny {
		t.Fatalf("expected client-deny decision, got %+v", sink.decisions)
	}
}

func TestHandleCallback_GroupCheckFromClaims_Failure(t *testing.T) {
	cfg := defaultCfg()
	cfg.CognitoGroupsClaims = true
	srv, sessions, sink := newTestServerWithSessions(cfg, nil)

	sid := "claims-group-fail-sid"
	sess := addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")
	sess.RequiredGroup = "vpn-users"

	oidcJWT := makeUnsignedJWT("user@example.com", "sub123", []string{"other-group"}, time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", oidcJWT)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionDeny {
		t.Fatalf("expected client-deny, got %+v", sink.decisions)
	}
}

func TestHandleCallback_Success_DevMode(t *testing.T) {
	cfg := defaultCfg()
	identity := &fakeGroupsChecker{inGroup: true}
	srv, sessions, sink := newTestServerWithSessions(cfg, identity)

	sid := "success-sid"
	sess := addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")
	sess.RequiredGroup = "vpn-users"

	oidcJWT := makeUnsignedJWT("user@example.com", "sub123", []string{"vpn-users"}, time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", oidcJWT)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionAllow {
		t.Fatalf("expected client-auth decision, got %+v", sink.decisions)
	}
}

func TestHandleCallback_Success_GroupFromClaims(t *testing.T) {
	cfg := defaultCfg()
	cfg.CognitoGroupsClaims = true
	srv, sessions, sink := newTestServerWithSessions(cfg, nil)

	sid := "claims-success-sid"
	sess := addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")
	sess.RequiredGroup = "vpn-users"

	oidcJWT := makeUnsignedJWT("user@example.com", "sub123", []string{"vpn-users", "other"}, time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", oidcJWT)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionAllow {
		t.Fatalf("expected client-auth decision, got %+v", sink.decisions)
	}
}

func TestHandleCallback_Success_WithALBJWT(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const albARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/test/abc"
	cfg := config.Config{
		AWSRegion: "eu-west-1",
		ALBARN:    albARN,
	}
	identity := &fakeGroupsChecker{inGroup: true}
	srv, sessions, sink := newTestServerWithSessions(cfg, identity)
	srv.keyCache["test-kid"] = &privKey.PublicKey

	sid := "alb-success-sid"
	sess := addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")
	sess.RequiredGroup = "vpn-users"

	tokenStr := makeSignedJWT(t, privKey, "test-kid", albARN, "user@example.com", "sub123", time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", tokenStr)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionAllow {
		t.Fatalf("expected client-auth decision, got %+v", sink.decisions)
	}
}

func TestHandleCallback_CNMismatch(t *testing.T) {
	cfg := defaultCfg()
	srv, sessions, sink := newTestServerWithSessions(cfg, nil)

	sid := "cn-mismatch-sid"
	sess := addSessionPending(sessions, sid, "cid1", "kid1", "cert-cn@example.com")
	sess.CNCrossCheck = true

	oidcJWT := makeUnsignedJWT("different@example.com", "sub123", nil, time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", oidcJWT)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionDeny {
		t.Fatalf("expected client-deny, got %+v", sink.decisions)
	}
}

// ---------------------------------------------------------------------------
// handleHealthz unit tests
// ---------------------------------------------------------------------------

func TestHandleHealthz_Connected(t *testing.T) {
	sessions := auth.NewSessionStore()
	signer := secrets.NewStaticSigner("test-secret")
	sink := &captureSink{}
	cfg := defaultCfg()
	srv := NewServer(sessions, signer, sink, cfg, fakeMetrics{}, nil, func() bool { return true })

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp healthzResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %q", resp.Status)
	}
	if !resp.MgmtConnected {
		t.Error("expected mgmt_connected true")
	}
}

func TestHandleHealthz_Disconnected(t *testing.T) {
	sessions := auth.NewSessionStore()
	signer := secrets.NewStaticSigner("test-secret")
	sink := &captureSink{}
	cfg := defaultCfg()
	srv := NewServer(sessions, signer, sink, cfg, fakeMetrics{}, nil, func() bool { return false })

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	var resp healthzResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "degraded" {
		t.Errorf("expected status degraded, got %q", resp.Status)
	}
	if resp.MgmtConnected {
		t.Error("expected mgmt_connected false")
	}
}

// ---------------------------------------------------------------------------
// Property test: Healthz reflects socket state (subtask 5.5)
// Validates: Requirements 6.2, 6.3
// ---------------------------------------------------------------------------

// TestHealthzReflectsSocketState is a property test verifying that GET /healthz
// returns 200 iff mgmtConnected() is true at request time.
//
// Validates: Requirements 6.2, 6.3
func TestHealthzReflectsSocketState(t *testing.T) {
	cases := []struct {
		connected      bool
		wantStatus     int
		wantStatusText string
	}{
		{connected: true, wantStatus: http.StatusOK, wantStatusText: "ok"},
		{connected: false, wantStatus: http.StatusServiceUnavailable, wantStatusText: "degraded"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("connected=%v", tc.connected), func(t *testing.T) {
			// Run many iterations to confirm the closure is evaluated at request time.
			for i := 0; i < 50; i++ {
				sessions := auth.NewSessionStore()
				signer := secrets.NewStaticSigner("test-secret")
				sink := &captureSink{}
				cfg := defaultCfg()

				connected := tc.connected
				srv := NewServer(sessions, signer, sink, cfg, fakeMetrics{}, nil, func() bool { return connected })

				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, req)

				if w.Code != tc.wantStatus {
					t.Fatalf("iteration %d: connected=%v: expected %d, got %d",
						i, tc.connected, tc.wantStatus, w.Code)
				}

				var resp healthzResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("iteration %d: decode response: %v", i, err)
				}
				if resp.MgmtConnected != tc.connected {
					t.Fatalf("iteration %d: mgmt_connected mismatch: got %v, want %v",
						i, resp.MgmtConnected, tc.connected)
				}
				if resp.Status != tc.wantStatusText {
					t.Fatalf("iteration %d: status mismatch: got %q, want %q",
						i, resp.Status, tc.wantStatusText)
				}
			}
		})
	}
}

// TestHealthzReflectsSocketState_DynamicSwitch verifies that the healthz
// response changes immediately when the mgmtConnected closure changes state.
//
// Validates: Requirements 6.2, 6.3
func TestHealthzReflectsSocketState_DynamicSwitch(t *testing.T) {
	sessions := auth.NewSessionStore()
	signer := secrets.NewStaticSigner("test-secret")
	sink := &captureSink{}
	cfg := defaultCfg()

	connected := true
	srv := NewServer(sessions, signer, sink, cfg, fakeMetrics{}, nil, func() bool { return connected })
	handler := srv.Handler()

	// Initially connected -> 200.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when connected, got %d", w.Code)
	}

	// Switch to disconnected -> 503.
	connected = false
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when disconnected, got %d", w.Code)
	}

	// Switch back to connected -> 200.
	connected = true
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after reconnect, got %d", w.Code)
	}
}
