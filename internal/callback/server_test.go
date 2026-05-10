package callback

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/cognito"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/secrets"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

type captureSink struct {
	decisions []auth.Decision
	ackErr    error
}

func (c *captureSink) Send(d auth.Decision) error {
	c.decisions = append(c.decisions, d)
	return nil
}

func (c *captureSink) SendAck(d auth.Decision) error {
	c.decisions = append(c.decisions, d)
	return c.ackErr
}

type captureTracker struct {
	calls []trackedAuth
}

type trackedAuth struct {
	cid             string
	cognitoUsername string
}

func (c *captureTracker) MarkAuthenticated(cid, cognitoUsername string) {
	c.calls = append(c.calls, trackedAuth{cid: cid, cognitoUsername: cognitoUsername})
}

type fakeMetrics struct {
	rejectedReasons []string
	deniedReasons   []string
}

func (m *fakeMetrics) Heartbeat(bool, int) {}
func (m *fakeMetrics) AuthAttempt(string)  {}
func (m *fakeMetrics) AuthSuccess()        {}
func (m *fakeMetrics) AuthDenied(reason string) {
	m.deniedReasons = append(m.deniedReasons, reason)
}
func (m *fakeMetrics) ReauthSuccess()      {}
func (m *fakeMetrics) ReauthDenied(string) {}
func (m *fakeMetrics) ReauthCacheHit()     {}
func (m *fakeMetrics) CallbackReceived()   {}
func (m *fakeMetrics) CallbackRejected(reason string) {
	m.rejectedReasons = append(m.rejectedReasons, reason)
}
func (m *fakeMetrics) TokenExchangeError(string) {}
func (m *fakeMetrics) SessionExpired(string)     {}

// fakeGroupsChecker implements GroupsChecker for tests.
type fakeGroupsChecker struct {
	inGroup bool
	enabled bool
	err     error
}

func (f *fakeGroupsChecker) CheckUser(_ context.Context, _, _ string, _ bool) (auth.IdentityResult, error) {
	return auth.IdentityResult{Enabled: f.enabled, InGroup: f.inGroup}, f.err
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestServer builds a Server with sensible defaults for unit tests.
// albARN is empty by default (dev mode — skip JWT signature validation).
func newTestServer(cfg config.Config, identity GroupsChecker) (*Server, *captureSink, *fakeMetrics) {
	sessions := auth.NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	m := &fakeMetrics{}
	srv, err := NewServer(sessions, signer, sink, nil, cfg, m, identity, func() bool { return true })
	if err != nil {
		panic("newTestServer: " + err.Error())
	}
	return srv, sink, m
}

// newTestServerWithSessions builds a Server and returns the session store too.
func newTestServerWithSessions(cfg config.Config, identity GroupsChecker) (*Server, *auth.SessionStore, *captureSink, *fakeMetrics) {
	sessions := auth.NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	m := &fakeMetrics{}
	tmpl, err := loadTemplates("")
	if err != nil {
		panic("newTestServerWithSessions: " + err.Error())
	}
	srv := &Server{
		sessions:            sessions,
		signer:              signer,
		sink:                sink,
		tracker:             nil,
		cfg:                 cfg,
		metrics:             m,
		identity:            identity,
		tmpl:                tmpl,
		albARN:              cfg.ALBARN,
		albPublicKeyBaseURL: cognito.DefaultALBPublicKeyBaseURL(cfg.AWSRegion),
		keyCache:            make(map[string]*ecdsa.PublicKey),
		mgmtConnected:       func() bool { return true },
		startTime:           time.Now(),
	}
	return srv, sessions, sink, m
}

// validStateParam creates a valid HMAC-signed state blob for the given session ID.
func validStateParam(t *testing.T, sid string) string {
	t.Helper()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	return auth.EncodeState(auth.StatePayload{
		SID: sid,
		IAT: time.Now().Unix(),
		EXP: time.Now().Add(5 * time.Minute).Unix(),
	}, signer)
}

// expiredStateParam creates an expired state blob.
func expiredStateParam(t *testing.T, sid string) string {
	t.Helper()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
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
	srv, _, m := newTestServer(defaultCfg(), nil)
	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	assertHTMLResponse(t, w, "Session Error")
	assertRejectedReason(t, m, "missing_state")
}

func TestHandleCallback_InvalidStateHMAC(t *testing.T) {
	srv, _, m := newTestServer(defaultCfg(), nil)
	valid := validStateParam(t, "some-sid")
	parts := strings.SplitN(valid, ".", 2)
	tampered := parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+tampered, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	assertHTMLResponse(t, w, "Session Error")
	assertRejectedReason(t, m, "invalid_state")
}

func TestHandleCallback_ExpiredState(t *testing.T) {
	srv, _, m := newTestServer(defaultCfg(), nil)
	state := expiredStateParam(t, "some-sid")

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	assertHTMLResponse(t, w, "Session Error")
	assertRejectedReason(t, m, "invalid_state")
}

func TestHandleCallback_SessionNotFound(t *testing.T) {
	srv, _, _, m := newTestServerWithSessions(defaultCfg(), nil)
	state := validStateParam(t, "nonexistent-sid")

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	assertHTMLResponse(t, w, "Session Expired")
	assertRejectedReason(t, m, "session_not_found")
}

func TestHandleCallback_SessionNotPending(t *testing.T) {
	srv, sessions, _, m := newTestServerWithSessions(defaultCfg(), nil)
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
	assertHTMLResponse(t, w, "Session Error")
	assertRejectedReason(t, m, "session_not_pending")
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

	srv, sessions, sink, m := newTestServerWithSessions(cfg, nil)
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
	assertHTMLResponse(t, w, "Authentication Failed")
	assertRejectedReason(t, m, "jwt_validation_failed")
	assertDeniedReason(t, m, "jwt_validation_failed")
}

func TestHandleCallback_GroupCheckFailure(t *testing.T) {
	cfg := defaultCfg()
	identity := &fakeGroupsChecker{enabled: true, inGroup: false}
	srv, sessions, sink, m := newTestServerWithSessions(cfg, identity)

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
	assertHTMLResponse(t, w, "Access Denied")
	assertRejectedReason(t, m, "group_denied")
	assertDeniedReason(t, m, "group_denied")
}

func TestHandleCallback_GroupCheckFromClaims_Failure(t *testing.T) {
	cfg := defaultCfg()
	cfg.CognitoGroupsClaims = true
	srv, sessions, sink, m := newTestServerWithSessions(cfg, nil)

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
	assertHTMLResponse(t, w, "Access Denied")
	assertRejectedReason(t, m, "group_denied")
	assertDeniedReason(t, m, "group_denied")
}

func TestHandleCallback_Success_DevMode(t *testing.T) {
	cfg := defaultCfg()
	identity := &fakeGroupsChecker{enabled: true, inGroup: true}
	srv, sessions, sink, m := newTestServerWithSessions(cfg, identity)

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
	assertHTMLResponse(t, w, "Authenticated")
	assertContains(t, w.Body.String(), "user@example.com")
	assertNoRejection(t, m)
}

func TestHandleCallback_ToleratesTrailingApostropheInState(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
	}{
		{name: "direct_encoded_apostrophe", suffix: "%27"},
		{name: "lambda_router_double_encoded_apostrophe", suffix: "%2527"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultCfg()
			identity := &fakeGroupsChecker{enabled: true, inGroup: true}
			srv, sessions, sink, m := newTestServerWithSessions(cfg, identity)

			sid := "trailing-apostrophe-sid-" + tc.name
			sess := addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")
			sess.RequiredGroup = "vpn-users"

			oidcJWT := makeUnsignedJWT("user@example.com", "sub123", []string{"vpn-users"}, time.Now().Add(5*time.Minute).Unix())
			state := validStateParam(t, sid)

			req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state+tc.suffix, nil)
			req.Header.Set("x-amzn-oidc-data", oidcJWT)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionAllow {
				t.Fatalf("expected client-auth decision, got %+v", sink.decisions)
			}
			assertHTMLResponse(t, w, "Authenticated")
			assertNoRejection(t, m)
		})
	}
}

func TestHandleCallback_Success_GroupFromClaims(t *testing.T) {
	cfg := defaultCfg()
	cfg.CognitoGroupsClaims = true
	srv, sessions, sink, _ := newTestServerWithSessions(cfg, nil)

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
	assertHTMLResponse(t, w, "Authenticated")
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
	identity := &fakeGroupsChecker{enabled: true, inGroup: true}
	srv, sessions, sink, _ := newTestServerWithSessions(cfg, identity)
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
	assertHTMLResponse(t, w, "Authenticated")
}

func TestHandleCallback_AllowAckFailureDoesNotPromoteSession(t *testing.T) {
	cfg := defaultCfg()
	srv, sessions, sink, m := newTestServerWithSessions(cfg, nil)
	sink.ackErr = errors.New("management socket write failed")
	tracker := &captureTracker{}
	srv.tracker = tracker

	sid := "allow-ack-fail-sid"
	addSessionPending(sessions, sid, "cid1", "kid1", "user@example.com")

	oidcJWT := makeUnsignedJWT("user@example.com", "sub123", nil, time.Now().Add(5*time.Minute).Unix())
	state := validStateParam(t, sid)

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+state, nil)
	req.Header.Set("x-amzn-oidc-data", oidcJWT)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	if len(sink.decisions) == 0 || sink.decisions[0].Type != auth.DecisionAllow {
		t.Fatalf("expected attempted client-auth decision, got %+v", sink.decisions)
	}
	if len(tracker.calls) != 0 {
		t.Fatalf("expected MarkAuthenticated not to be called, got %+v", tracker.calls)
	}
	assertHTMLResponse(t, w, "Service Unavailable")
	assertRejectedReason(t, m, "send_failed")
}

func TestHandleCallback_CNMismatch(t *testing.T) {
	cfg := defaultCfg()
	srv, sessions, sink, m := newTestServerWithSessions(cfg, nil)

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
	assertHTMLResponse(t, w, "Certificate Mismatch")
	assertRejectedReason(t, m, "cn_mismatch")
	assertDeniedReason(t, m, "cn_mismatch")
}

// ---------------------------------------------------------------------------
// handleHealthz unit tests
// ---------------------------------------------------------------------------

func TestHandleHealthz_Connected(t *testing.T) {
	sessions := auth.NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	cfg := defaultCfg()
	srv, err := NewServer(sessions, signer, sink, nil, cfg, &fakeMetrics{}, nil, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}

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
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	cfg := defaultCfg()
	srv, err := NewServer(sessions, signer, sink, nil, cfg, &fakeMetrics{}, nil, func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}

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
				signer, _ := secrets.NewStaticSigner("test-secret-key!!")
				sink := &captureSink{}
				cfg := defaultCfg()

				connected := tc.connected
				srv, err := NewServer(sessions, signer, sink, nil, cfg, &fakeMetrics{}, nil, func() bool { return connected })
				if err != nil {
					t.Fatal(err)
				}

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
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	cfg := defaultCfg()

	connected := true
	srv, err := NewServer(sessions, signer, sink, nil, cfg, &fakeMetrics{}, nil, func() bool { return connected })
	if err != nil {
		t.Fatal(err)
	}
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

// ---------------------------------------------------------------------------
// HTML response assertion helpers
// ---------------------------------------------------------------------------

func assertHTMLResponse(t *testing.T, w *httptest.ResponseRecorder, expectedText string) {
	t.Helper()
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected Cache-Control no-store, got %q", cc)
	}
	if xcto := w.Header().Get("X-Content-Type-Options"); xcto != "nosniff" {
		t.Errorf("expected X-Content-Type-Options nosniff, got %q", xcto)
	}
	assertContains(t, w.Body.String(), expectedText)
}

func assertContains(t *testing.T, body, substr string) {
	t.Helper()
	if !strings.Contains(body, substr) {
		t.Errorf("expected body to contain %q, got:\n%s", substr, body)
	}
}

func assertRejectedReason(t *testing.T, m *fakeMetrics, expected string) {
	t.Helper()
	if len(m.rejectedReasons) == 0 {
		t.Fatalf("expected CallbackRejected(%q) but no rejections were recorded", expected)
	}
	got := m.rejectedReasons[len(m.rejectedReasons)-1]
	if got != expected {
		t.Errorf("expected CallbackRejected reason %q, got %q (all: %v)", expected, got, m.rejectedReasons)
	}
}

func assertDeniedReason(t *testing.T, m *fakeMetrics, expected string) {
	t.Helper()
	if len(m.deniedReasons) == 0 {
		t.Fatalf("expected AuthDenied(%q) but no denials were recorded", expected)
	}
	got := m.deniedReasons[len(m.deniedReasons)-1]
	if got != expected {
		t.Errorf("expected AuthDenied reason %q, got %q (all: %v)", expected, got, m.deniedReasons)
	}
}

func assertNoRejection(t *testing.T, m *fakeMetrics) {
	t.Helper()
	if len(m.rejectedReasons) > 0 {
		t.Errorf("expected no CallbackRejected calls, got %v", m.rejectedReasons)
	}
}

// ---------------------------------------------------------------------------
// Template loading tests
// ---------------------------------------------------------------------------

func TestLoadTemplates_Embedded(t *testing.T) {
	tmpl, err := loadTemplates("")
	if err != nil {
		t.Fatalf("loadTemplates embedded: %v", err)
	}
	if tmpl.Lookup("success.html") == nil {
		t.Error("missing success.html")
	}
	if tmpl.Lookup("error.html") == nil {
		t.Error("missing error.html")
	}
}

func TestLoadTemplates_OverrideOK(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "success.html", `<!DOCTYPE html><html><body>{{.Email}} {{.SessionID}}</body></html>`)
	writeFile(t, dir, "error.html", `<!DOCTYPE html><html><body>{{.Title}} {{.Message}} {{.StatusCode}}</body></html>`)

	tmpl, err := loadTemplates(dir)
	if err != nil {
		t.Fatalf("loadTemplates override: %v", err)
	}
	if tmpl.Lookup("success.html") == nil {
		t.Error("missing success.html")
	}
}

func TestLoadTemplates_OverrideMissingFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "success.html", `<!DOCTYPE html><html><body>ok</body></html>`)
	// error.html is missing

	_, err := loadTemplates(dir)
	if err == nil {
		t.Fatal("expected error for missing error.html")
	}
	if !strings.Contains(err.Error(), "error.html") {
		t.Errorf("expected error to mention error.html, got: %v", err)
	}
}

func TestLoadTemplates_OverrideSyntaxError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "success.html", `{{.Unclosed`)
	writeFile(t, dir, "error.html", `<!DOCTYPE html><html><body>ok</body></html>`)

	_, err := loadTemplates(dir)
	if err == nil {
		t.Fatal("expected error for syntax error in template")
	}
}

func TestLoadTemplates_NotADirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	writeFile(t, filepath.Dir(f), "file.txt", "not a dir")

	_, err := loadTemplates(f)
	if err == nil {
		t.Fatal("expected error when path is a file")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Render fallback tests
// ---------------------------------------------------------------------------

func TestRenderError_Fallback(t *testing.T) {
	srv := &Server{tmpl: template.New("root")} // no templates defined
	w := httptest.NewRecorder()
	srv.renderError(w, http.StatusForbidden, "Access Denied", "You are not a member of the required group.", "test-sid")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain fallback, got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected Cache-Control no-store, got %q", cc)
	}
	assertContains(t, w.Body.String(), "You are not a member of the required group.")
}

func TestRenderSuccess_Fallback(t *testing.T) {
	srv := &Server{tmpl: template.New("root")} // no templates defined
	w := httptest.NewRecorder()
	srv.renderSuccess(w, "user@example.com", "test-sid")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain fallback, got %q", ct)
	}
	assertContains(t, w.Body.String(), "authenticated")
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
