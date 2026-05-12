package auth

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/metrics"
	"openvpn-auth-aws/internal/mgmt"
	"openvpn-auth-aws/internal/secrets"
)

type captureSink struct {
	mu        sync.Mutex
	decisions []Decision
}

func (c *captureSink) Send(d Decision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decisions = append(c.decisions, d)
	return nil
}

func (c *captureSink) snapshot() []Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]Decision, len(c.decisions))
	copy(cp, c.decisions)
	return cp
}

func newTestHandler(cfg config.Config) *Handler {
	sessions := NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	return NewHandler(cfg, sessions, nil, signer, m)
}

func TestHandleConnectWithoutWebAuth(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   50 * time.Millisecond,
		AuthTimeout:  50 * time.Millisecond,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env:  map[string]string{},
	}, sink)

	if len(sink.snapshot()) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.snapshot()))
	}
	if sink.snapshot()[0].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.snapshot()[0].Type)
	}
	if sink.snapshot()[0].Reason != "client does not support WebAuth" {
		t.Fatalf("unexpected reason: %q", sink.snapshot()[0].Reason)
	}
}

func TestHandleConnectAcceptsOpenURL(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   50 * time.Millisecond,
		AuthTimeout:  50 * time.Millisecond,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "openurl",
			"common_name": "test@example.com",
		},
	}, sink)

	time.Sleep(5 * time.Millisecond)
	cancel()
	time.Sleep(5 * time.Millisecond)

	if len(sink.snapshot()) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.snapshot()))
	}
	if sink.snapshot()[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", sink.snapshot()[0].Type)
	}
}

func TestHandleConnectAcceptsCSVWebAuth(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   50 * time.Millisecond,
		AuthTimeout:  50 * time.Millisecond,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "openurl,webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	time.Sleep(5 * time.Millisecond)
	cancel()
	time.Sleep(5 * time.Millisecond)

	if len(sink.snapshot()) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.snapshot()))
	}
	if sink.snapshot()[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", sink.snapshot()[0].Type)
	}
}

func TestHandleConnectRejectsCrtext(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   50 * time.Millisecond,
		AuthTimeout:  50 * time.Millisecond,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "crtext",
			"common_name": "test@example.com",
		},
	}, sink)

	if len(sink.snapshot()) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.snapshot()))
	}
	if sink.snapshot()[0].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.snapshot()[0].Type)
	}
}

func TestHandleConnectIgnoresPassword(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   50 * time.Millisecond,
		AuthTimeout:  50 * time.Millisecond,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"password":    "any-password-should-be-ignored",
			"common_name": "test@example.com",
		},
	}, sink)

	// Wait briefly for handleConnect to send DecisionPending
	time.Sleep(5 * time.Millisecond)
	cancel()
	time.Sleep(5 * time.Millisecond)

	if len(sink.snapshot()) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.snapshot()))
	}
	if sink.snapshot()[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending (WebAuth flow), got %d", sink.snapshot()[0].Type)
	}
	if sink.snapshot()[0].URL == "" {
		t.Fatal("expected WebAuth URL, got empty string")
	}
}

func TestHandleConnectStateBlob(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   300 * time.Second,
		AuthTimeout:  300 * time.Second,
		CallbackPort: 9090,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	time.Sleep(5 * time.Millisecond)
	cancel()

	if len(sink.snapshot()) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.snapshot()))
	}
	d := sink.snapshot()[0]
	if d.Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", d.Type)
	}
	// URL should contain state blob (base64.mac format)
	if !strings.Contains(d.URL, "state=") {
		t.Fatalf("URL should contain state= param: %s", d.URL)
	}
	// URL should NOT contain sig= param (old format)
	if strings.Contains(d.URL, "sig=") {
		t.Fatalf("URL should not contain sig= param (old format): %s", d.URL)
	}
}

// TestHandleConnectURLFormat verifies the WEB_AUTH URL is exactly
// {callback-url}?state={blob} with no extra path assembly.
// Requirements: 3.1
func TestHandleConnectURLFormat(t *testing.T) {
	callbackURL := "https://vpn-auth.example.com/callback/01/udp"
	cfg := config.Config{
		CallbackURL:  callbackURL,
		HMACSecret:   "test-secret-key!!",
		HandWindow:   300 * time.Second,
		AuthTimeout:  300 * time.Second,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	time.Sleep(5 * time.Millisecond)
	cancel()

	if len(sink.snapshot()) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.snapshot()))
	}
	d := sink.snapshot()[0]
	if d.Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", d.Type)
	}

	// URL must start with the exact callback URL followed by ?state=
	expectedPrefix := callbackURL + "?state="
	if !strings.HasPrefix(d.URL, expectedPrefix) {
		t.Fatalf("URL must be %q + state blob, got: %s", expectedPrefix, d.URL)
	}

	// The state blob must be non-empty
	stateBlob := strings.TrimPrefix(d.URL, expectedPrefix)
	if stateBlob == "" {
		t.Fatal("state blob must not be empty")
	}

	// State blob must contain a dot separator (base64payload.mac)
	if !strings.Contains(stateBlob, ".") {
		t.Fatalf("state blob must be base64payload.mac format, got: %s", stateBlob)
	}
}

// TestHandleConnectURLTooLong verifies that a callback URL that would produce
// a WEB_AUTH URL exceeding MaxWebAuthURLLen results in a deny with reason
// "auth URL too long". Requirements: 3.3
func TestHandleConnectURLTooLong(t *testing.T) {
	// Construct a callback URL long enough that the full auth URL > MaxWebAuthURLLen.
	// MaxWebAuthURLLen = 229; state blob ~128 bytes.
	// So callback URL of 100 bytes will push total well over 229.
	longCallbackURL := "https://vpn-auth.example.com/callback/" + strings.Repeat("x", 100)
	cfg := config.Config{
		CallbackURL:  longCallbackURL,
		HMACSecret:   "test-secret-key!!",
		HandWindow:   300 * time.Second,
		AuthTimeout:  300 * time.Second,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	if len(sink.snapshot()) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.snapshot()))
	}
	d := sink.snapshot()[0]
	if d.Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", d.Type)
	}
	if d.Reason != "auth URL too long" {
		t.Fatalf("expected reason %q, got %q", "auth URL too long", d.Reason)
	}
}

func TestHandleConnectTimeoutCleanup(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   200 * time.Millisecond,
		AuthTimeout:  20 * time.Millisecond,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	// Wait for timeout goroutine to fire
	time.Sleep(80 * time.Millisecond)

	if len(sink.snapshot()) < 2 {
		t.Fatalf("expected at least 2 decisions (pending + deny), got %d", len(sink.snapshot()))
	}
	if sink.snapshot()[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", sink.snapshot()[0].Type)
	}
	if sink.snapshot()[1].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.snapshot()[1].Type)
	}
	if sink.snapshot()[1].Reason != "auth timeout" {
		t.Fatalf("expected 'auth timeout', got %q", sink.snapshot()[1].Reason)
	}
}

func TestHandleConnectDisconnectCleanup(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   5 * time.Second,
		AuthTimeout:  5 * time.Second,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	time.Sleep(5 * time.Millisecond)

	// Disconnect should cancel timeout and clean up session
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventDisconnect,
		CID:  "1",
	}, sink)

	time.Sleep(5 * time.Millisecond)

	if handler.InFlight() != 0 {
		t.Fatalf("expected 0 in-flight, got %d", handler.InFlight())
	}
}

func TestHandleConnectRejectsMissingCommonName(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   50 * time.Millisecond,
		AuthTimeout:  50 * time.Millisecond,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO": "webauth",
		},
	}, sink)

	if len(sink.snapshot()) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.snapshot()))
	}
	if sink.snapshot()[0].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.snapshot()[0].Type)
	}
	if sink.snapshot()[0].Reason != "missing common name" {
		t.Fatalf("unexpected reason: %q", sink.snapshot()[0].Reason)
	}
}

func TestHandleEstablishedClearsInFlight(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   5 * time.Second,
		AuthTimeout:  5 * time.Second,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	time.Sleep(5 * time.Millisecond)

	if handler.InFlight() != 1 {
		t.Fatalf("expected 1 in-flight after connect, got %d", handler.InFlight())
	}

	// ESTABLISHED should cancel the timeout goroutine and clear inFlight.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished,
		CID:  "1",
	}, sink)

	time.Sleep(5 * time.Millisecond)

	if handler.InFlight() != 0 {
		t.Fatalf("expected 0 in-flight after established, got %d", handler.InFlight())
	}
}

func TestHandleConnectEvictsInFlightSessionOnReconnect(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   5 * time.Second,
		AuthTimeout:  5 * time.Second,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First CONNECT for alice, CID=1 — stays in-flight (no auth yet).
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	if handler.InFlight() != 1 {
		t.Fatalf("expected 1 in-flight after first connect, got %d", handler.InFlight())
	}

	// Second CONNECT for alice, CID=2 — stale in-flight CID=1 must be evicted with client-deny.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "2", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// Only CID=2 should be in-flight now.
	if handler.InFlight() != 1 {
		t.Fatalf("expected 1 in-flight after eviction, got %d", handler.InFlight())
	}

	var pending, deny int
	for _, d := range sink.snapshot() {
		switch d.Type {
		case DecisionPending:
			pending++
		case DecisionDeny:
			if d.CID == "1" {
				deny++
			}
		}
	}
	if pending != 2 {
		t.Fatalf("expected 2 DecisionPending (both connects), got %d", pending)
	}
	if deny != 1 {
		t.Fatalf("expected 1 DecisionDeny for evicted CID=1, got %d", deny)
	}
}

func TestHandleConnectEvictsEstablishedSessionOnReconnect(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   5 * time.Second,
		AuthTimeout:  5 * time.Second,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First CONNECT for alice, CID=1.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// ESTABLISHED — auth done, session active, inFlight cleared.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	if handler.InFlight() != 0 {
		t.Fatalf("expected 0 in-flight after established, got %d", handler.InFlight())
	}

	// Second CONNECT for alice, CID=2 — established CID=1 must be evicted with client-kill.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "2", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	if handler.InFlight() != 1 {
		t.Fatalf("expected 1 in-flight for new session, got %d", handler.InFlight())
	}

	var kill int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionKill && d.CID == "1" {
			if d.KillMode != "HALT" {
				t.Fatalf("expected eviction kill mode HALT, got %q; decision: %+v", d.KillMode, d)
			}
			kill++
		}
	}
	if kill != 1 {
		t.Fatalf("expected 1 DecisionKill for established CID=1, got %d; decisions: %+v", kill, sink.snapshot())
	}
}

// --- Session expiry tests ---

func TestStrayEstablishedDoesNotStartExpiryTimer(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 20 * time.Millisecond,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	// Send ESTABLISHED for a CID that was never in inFlight (stray/duplicate).
	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventEstablished, CID: "99",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.mu.Lock()
	st99 := handler.cids["99"]
	hasExpiry := st99 != nil && st99.expiry != nil
	handler.mu.Unlock()

	if hasExpiry {
		t.Fatal("stray ESTABLISHED must not create an expiry timer")
	}

	// Wait past the would-be expiry to confirm no DecisionKill fires.
	time.Sleep(50 * time.Millisecond)

	for _, d := range sink.snapshot() {
		if d.Type == DecisionKill && d.CID == "99" {
			t.Fatal("stray ESTABLISHED must not produce DecisionKill")
		}
	}
}

func TestEstablishedStartsExpiryTimer(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 5 * time.Second, // long enough not to fire during test
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.mu.Lock()
	st1e := handler.cids["1"]
	hasExpiry := st1e != nil && st1e.expiry != nil
	handler.mu.Unlock()

	if !hasExpiry {
		t.Fatal("expected expiry entry after ESTABLISHED with max-session-duration")
	}
}

func TestExpiryTimerFiresDecisionKill(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 20 * time.Millisecond,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)

	// Wait for expiry timer to fire
	time.Sleep(80 * time.Millisecond)

	var kill int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionKill && d.CID == "1" {
			if d.KillMode != "" {
				t.Fatalf("expected expiry kill mode to be empty, got %q; decision: %+v", d.KillMode, d)
			}
			kill++
		}
	}
	if kill != 1 {
		t.Fatalf("expected 1 DecisionKill from expiry timer, got %d; decisions: %+v", kill, sink.snapshot())
	}
}

func TestDisconnectCancelsExpiryTimer(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 50 * time.Millisecond,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// Disconnect before expiry fires
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventDisconnect, CID: "1",
	}, sink)

	// Wait past what would have been the expiry time
	time.Sleep(80 * time.Millisecond)

	for _, d := range sink.snapshot() {
		if d.Type == DecisionKill {
			t.Fatalf("expected no DecisionKill after disconnect, but got one: %+v", d)
		}
	}
}

func TestEvictionCancelsExpiryTimer(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 100 * time.Millisecond,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect and establish CID=1
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// New connect for same CN evicts CID=1
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "2", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// Count kills — should be exactly 1 from eviction, not 2 (no timer fire)
	time.Sleep(150 * time.Millisecond)

	var kills int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionKill && d.CID == "1" {
			if d.KillMode != "HALT" {
				t.Fatalf("expected eviction kill mode HALT, got %q; decision: %+v", d.KillMode, d)
			}
			kills++
		}
	}
	if kills != 1 {
		t.Fatalf("expected exactly 1 DecisionKill for CID=1 (from eviction), got %d; decisions: %+v", kills, sink.snapshot())
	}
}

func TestReauthBackstopDeniesExpiredSession(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: time.Millisecond, // extremely short to expire immediately
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)

	// Use replaceExpiryState instead of mutating the pointer in-place to
	// respect the production contract: old *sessionExpiry is never modified.
	handler.replaceExpiryState("1", time.Now().Add(-24*time.Hour))

	// Send REAUTH — backstop should deny
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "test@example.com"},
	}, sink)

	handler.WaitReauth()
	time.Sleep(5 * time.Millisecond)

	var deny int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionDeny && d.Reason == "session expired" {
			deny++
		}
	}
	if deny != 1 {
		t.Fatalf("expected 1 DecisionDeny with 'session expired', got %d; decisions: %+v", deny, sink.snapshot())
	}
}

func TestReauthBackstopSkippedWhenDurationZero(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 0, // disabled
		CognitoSkipReauth:  true,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// REAUTH with duration=0 should follow normal flow (skip-reauth allows it)
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "test@example.com"},
	}, sink)

	handler.WaitReauth()
	time.Sleep(5 * time.Millisecond)

	var allow int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionAllowNT {
			allow++
		}
	}
	if allow != 1 {
		t.Fatalf("expected 1 DecisionAllowNT (skip-reauth), got %d; decisions: %+v", allow, sink.snapshot())
	}
}

func TestReauthBackstopFiresBeforeSkipReauth(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: time.Millisecond,
		CognitoSkipReauth:  true,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)

	// Use replaceExpiryState instead of mutating the pointer in-place to
	// respect the production contract: old *sessionExpiry is never modified.
	handler.replaceExpiryState("1", time.Now().Add(-24*time.Hour))

	// REAUTH — backstop should deny even though skip-reauth is enabled
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "test@example.com"},
	}, sink)

	handler.WaitReauth()
	time.Sleep(5 * time.Millisecond)

	var deny int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionDeny && d.Reason == "session expired" {
			deny++
		}
	}
	if deny != 1 {
		t.Fatalf("expected backstop to fire before skip-reauth; got %d denials; decisions: %+v", deny, sink.snapshot())
	}
}

func TestReauthBackstopFiresBeforeCache(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		ReauthTimeout:      time.Millisecond,
		CallbackPort:       8080,
		MaxSessionDuration: time.Millisecond,
		ReauthCache:        true,
		RenegInterval:      time.Hour,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)

	// Populate cache with a valid entry
	handler.cache.Put("test@example.com", IdentityResult{
		Exists: true, Enabled: true, InGroup: true, CheckedAt: time.Now(),
	})

	// Use replaceExpiryState instead of mutating the pointer in-place to
	// respect the production contract: old *sessionExpiry is never modified.
	handler.replaceExpiryState("1", time.Now().Add(-24*time.Hour))

	// REAUTH — backstop should deny despite valid cache entry
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "test@example.com"},
	}, sink)

	handler.WaitReauth()
	time.Sleep(5 * time.Millisecond)

	var deny int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionDeny && d.Reason == "session expired" {
			deny++
		}
	}
	if deny != 1 {
		t.Fatalf("expected backstop to fire before cache lookup; got %d denials; decisions: %+v", deny, sink.snapshot())
	}
}

func TestReauthFailsClosedWhenTrackingMissing(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: time.Hour,
		CognitoSkipReauth:  true,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "test@example.com"},
	}, sink)

	handler.WaitReauth()
	time.Sleep(5 * time.Millisecond)

	var deny int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionDeny && d.Reason == "session revalidation required; reconnect" {
			deny++
		}
	}
	if deny != 1 {
		t.Fatalf("expected reauth to fail closed when tracking is missing; got %d denials; decisions: %+v", deny, sink.snapshot())
	}
}

func TestNoExpiryTimerWhenDurationZero(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 0, // disabled
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.mu.Lock()
	st1z := handler.cids["1"]
	hasExpiry := st1z != nil && st1z.expiry != nil
	handler.mu.Unlock()

	if hasExpiry {
		t.Fatal("expected no expiry entry when MaxSessionDuration=0")
	}
}

func TestMarkAuthenticatedPromotesButDefersExpiry(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 5 * time.Second,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "test@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.MarkAuthenticated("1", "")

	handler.mu.Lock()
	st1m := handler.cids["1"]
	inFlight := st1m != nil && st1m.cancel != nil
	isPromoted := st1m != nil && st1m.promoted
	hasExpiry := st1m != nil && st1m.expiry != nil
	handler.mu.Unlock()

	if inFlight {
		t.Fatal("expected in-flight state to be cleared after callback success promotion")
	}
	if !isPromoted {
		t.Fatal("expected CID to be in promoted set after MarkAuthenticated")
	}
	if hasExpiry {
		t.Fatal("expiry timer must not start until ESTABLISHED arrives")
	}

	// Now send ESTABLISHED — expiry timer should start.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.mu.Lock()
	st1me := handler.cids["1"]
	isPromoted = st1me != nil && st1me.promoted
	var exp *sessionExpiry
	if st1me != nil {
		exp = st1me.expiry
	}
	hasExpiry = exp != nil
	handler.mu.Unlock()

	if isPromoted {
		t.Fatal("expected promoted marker to be cleared after ESTABLISHED")
	}
	if !hasExpiry {
		t.Fatal("expected expiry tracking to start after ESTABLISHED")
	}
}

// TestPromotedCIDSurvivesReconnectBootstrap verifies that a CID promoted via
// MarkAuthenticated (callback success) but not yet ESTABLISHED is preserved
// across a management socket reconnect (RebuildSessionTrackingFromStatus).
func TestPromotedCIDSurvivesReconnectBootstrap(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: time.Hour,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// CONNECT → MarkAuthenticated (callback success before ESTABLISHED).
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)
	handler.MarkAuthenticated("1", "")

	// Simulate management socket reconnect with an empty snapshot
	// (the CID isn't in status 3 yet because ESTABLISHED hasn't fired).
	handler.RebuildSessionTrackingFromStatus(nil)

	handler.mu.Lock()
	var cn string
	isPromoted := false
	if st := handler.cids["1"]; st != nil {
		cn = st.cn
		isPromoted = st.promoted
	}
	activeCID := handler.cnToActiveCID["alice@example.com"]
	handler.mu.Unlock()

	if cn != "alice@example.com" {
		t.Fatalf("expected cn preserved for promoted CID, got %q", cn)
	}
	if activeCID != "1" {
		t.Fatalf("expected cnToActiveCID preserved for promoted CID, got %q", activeCID)
	}
	if !isPromoted {
		t.Fatal("expected promoted marker to survive reconnect bootstrap")
	}

	// Now ESTABLISHED arrives — should start expiry timer normally.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.mu.Lock()
	st1p := handler.cids["1"]
	hasExpiry := st1p != nil && st1p.expiry != nil
	stillPromoted := st1p != nil && st1p.promoted
	handler.mu.Unlock()

	if !hasExpiry {
		t.Fatal("expected expiry timer after ESTABLISHED post-reconnect")
	}
	if stillPromoted {
		t.Fatal("expected promoted marker cleared after ESTABLISHED")
	}
}

func TestRebuildSessionTrackingFromStatusRestoresTracking(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: time.Hour,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	connectedAt := time.Now().Add(-10 * time.Minute)
	handler.RebuildSessionTrackingFromStatus([]mgmt.EstablishedSession{{
		CID:         "7",
		CommonName:  "alice@example.com",
		ConnectedAt: connectedAt,
	}})

	handler.mu.Lock()
	var exp *sessionExpiry
	var cn string
	if st := handler.cids["7"]; st != nil {
		exp = st.expiry
		cn = st.cn
	}
	activeCID := handler.cnToActiveCID["alice@example.com"]
	handler.mu.Unlock()

	if exp == nil {
		t.Fatal("expected expiry tracking to be restored from management snapshot")
	}
	if !exp.connectedAt.Equal(connectedAt) {
		t.Fatalf("connectedAt = %v, want %v", exp.connectedAt, connectedAt)
	}
	if cn != "alice@example.com" {
		t.Fatalf("cn = %q, want alice@example.com", cn)
	}
	if activeCID != "7" {
		t.Fatalf("cnToActiveCID = %q, want 7", activeCID)
	}
}

// TestDuplicateEstablishedAfterBootstrapDoesNotResetExpiry verifies that a
// buffered CLIENT:ESTABLISHED arriving after RebuildSessionTrackingFromStatus
// does not replace the snapshot-anchored expiry timer with time.Now().
func TestDuplicateEstablishedAfterBootstrapDoesNotResetExpiry(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: time.Hour,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	// Simulate reconnect: CID "5" was established 30 minutes ago.
	connectedAt := time.Now().Add(-30 * time.Minute)
	handler.RebuildSessionTrackingFromStatus([]mgmt.EstablishedSession{{
		CID:         "5",
		CommonName:  "bob@example.com",
		ConnectedAt: connectedAt,
	}})

	handler.mu.Lock()
	var expBefore *sessionExpiry
	if st := handler.cids["5"]; st != nil {
		expBefore = st.expiry
	}
	handler.mu.Unlock()
	if expBefore == nil {
		t.Fatal("expected expiry tracking from snapshot")
	}
	if !expBefore.connectedAt.Equal(connectedAt) {
		t.Fatalf("connectedAt = %v, want %v", expBefore.connectedAt, connectedAt)
	}

	// Duplicate ESTABLISHED arrives (buffered by BootstrapStatus).
	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventEstablished, CID: "5",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	handler.mu.Lock()
	var expAfter *sessionExpiry
	if st := handler.cids["5"]; st != nil {
		expAfter = st.expiry
	}
	handler.mu.Unlock()

	if expAfter == nil {
		t.Fatal("expiry tracking must survive duplicate ESTABLISHED")
	}
	if !expAfter.connectedAt.Equal(connectedAt) {
		t.Fatalf("duplicate ESTABLISHED reset connectedAt from %v to %v", connectedAt, expAfter.connectedAt)
	}
}

func TestRebuildSessionTrackingFromStatusKillsAlreadyExpiredSession(t *testing.T) {
	cfg := config.Config{
		CallbackURL:        "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:         "test-secret-key!!",
		HandWindow:         5 * time.Second,
		AuthTimeout:        5 * time.Second,
		CallbackPort:       8080,
		MaxSessionDuration: 10 * time.Millisecond,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}
	handler.SetLiveSink(sink)

	handler.RebuildSessionTrackingFromStatus([]mgmt.EstablishedSession{{
		CID:         "9",
		CommonName:  "expired@example.com",
		ConnectedAt: time.Now().Add(-time.Hour),
	}})
	time.Sleep(10 * time.Millisecond)

	var kills int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionKill && d.CID == "9" {
			kills++
		}
	}
	if kills == 0 {
		t.Fatalf("expected reconnect reconciliation to kill already expired session; decisions: %+v", sink.snapshot())
	}
}

func TestHandleConnectAllowsNewSessionAfterDisconnect(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   5 * time.Second,
		AuthTimeout:  5 * time.Second,
		CallbackPort: 8080,
	}
	handler := newTestHandler(cfg)
	sink := &captureSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First CONNECT, CID=1
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "1", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// Disconnect CID=1
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventDisconnect, CID: "1",
	}, sink)
	time.Sleep(5 * time.Millisecond)

	// Second CONNECT, CID=2 — must be allowed now
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect, CID: "2", KID: "1",
		Env: map[string]string{"IV_SSO": "webauth", "common_name": "alice@example.com"},
	}, sink)
	time.Sleep(5 * time.Millisecond)

	pending := 0
	for _, d := range sink.snapshot() {
		if d.Type == DecisionPending {
			pending++
		}
	}
	if pending != 2 {
		t.Fatalf("expected 2 DecisionPending (one per connect), got %d; decisions: %+v", pending, sink.snapshot())
	}
}

// ---------------------------------------------------------------------------
// Step 9: reauth group-check path (docs/group-claims-debug-plan.md)
// ---------------------------------------------------------------------------

// countingChecker implements IdentityChecker and records every CheckUser call
// so tests can assert that reauth routes through the Cognito Admin API and
// does not silently pick up JWT claims.
type countingChecker struct {
	mu              sync.Mutex
	calls           int
	lastUsername    string
	lastGroup       string
	lastCheckGroups bool
	inGroup         bool
}

func (c *countingChecker) CheckUser(_ context.Context, username, requiredGroup string, checkGroups bool) (IdentityResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.lastUsername = username
	c.lastGroup = requiredGroup
	c.lastCheckGroups = checkGroups
	return IdentityResult{Exists: true, Enabled: true, InGroup: c.inGroup}, nil
}

// TestReauth_UsesCognitoAPI_EvenWhenGroupsSourceIsJWTClaim documents that the
// reauth path always calls IdentityChecker.CheckUser regardless of
// cfg.GroupsSource. Validation forbids combining jwt-claim with
// --check-required-group-on-reauth=true, so this test sets
// CheckRequiredGroupOnReauth=false to match the allowed production config.
// Nonetheless, reauth still hits Cognito for account-status verification —
// this is what the plan means by "reauth uses Cognito API for group checks".
func TestReauth_UsesCognitoAPI_EvenWhenGroupsSourceIsJWTClaim(t *testing.T) {
	cfg := config.Config{
		CallbackURL:                "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:                 "test-secret-key!!",
		HandWindow:                 5 * time.Second,
		AuthTimeout:                5 * time.Second,
		CallbackPort:               8080,
		ReauthTimeout:              time.Second,
		GroupsSource:               config.GroupsSourceJWTClaim,
		GroupsClaim:                "custom:groups",
		RequiredGroup:              "vpn-users",
		CheckRequiredGroupOnReauth: false, // enforced by validator; must be false with jwt-claim
	}
	checker := &countingChecker{inGroup: true}
	sessions := NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	handler := NewHandler(cfg, sessions, checker, signer, m)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "user@example.com"},
	}, sink)
	handler.WaitReauth()

	if checker.calls != 1 {
		t.Fatalf("expected reauth to call IdentityChecker.CheckUser exactly once, got %d", checker.calls)
	}
	if checker.lastUsername != "user@example.com" {
		t.Fatalf("expected username=user@example.com, got %q", checker.lastUsername)
	}
	if checker.lastCheckGroups {
		t.Fatal("expected checkGroups=false on reauth (CheckRequiredGroupOnReauth is false)")
	}

	var allows int
	for _, d := range sink.snapshot() {
		if d.Type == DecisionAllowNT {
			allows++
		}
	}
	if allows != 1 {
		t.Fatalf("expected one AllowNT decision, got decisions=%+v", sink.snapshot())
	}
}

func TestReauth_CognitoAPIGroupCheckDeniesWhenUserNotInGroup(t *testing.T) {
	cfg := config.Config{
		CallbackURL:                "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:                 "test-secret-key!!",
		HandWindow:                 5 * time.Second,
		AuthTimeout:                5 * time.Second,
		CallbackPort:               8080,
		ReauthTimeout:              time.Second,
		GroupsSource:               config.GroupsSourceCognitoAPI,
		RequiredGroup:              "vpn-users",
		CheckRequiredGroupOnReauth: true,
	}
	checker := &countingChecker{inGroup: false}
	sessions := NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	handler := NewHandler(cfg, sessions, checker, signer, m)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "user@example.com"},
	}, sink)
	handler.WaitReauth()

	if checker.calls != 1 {
		t.Fatalf("expected reauth to call IdentityChecker.CheckUser exactly once, got %d", checker.calls)
	}
	if checker.lastUsername != "user@example.com" {
		t.Fatalf("expected username=user@example.com, got %q", checker.lastUsername)
	}
	if checker.lastGroup != "vpn-users" {
		t.Fatalf("expected required group vpn-users, got %q", checker.lastGroup)
	}
	if !checker.lastCheckGroups {
		t.Fatal("expected checkGroups=true on reauth when CheckRequiredGroupOnReauth=true")
	}

	decisions := sink.snapshot()
	if len(decisions) != 1 {
		t.Fatalf("expected one decision, got %+v", decisions)
	}
	if decisions[0].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %+v", decisions[0])
	}
	if decisions[0].Reason != "not in required group: vpn-users" {
		t.Fatalf("expected group denial reason, got %q", decisions[0].Reason)
	}
}

// TestReauth_DoesNotReadJWTClaims verifies that reauth never inspects the
// cfg.GroupsClaim. The countingChecker returns InGroup=false for any call,
// so if reauth somehow short-circuited via a "jwt-claim grants access" code
// path, the decision would be an Allow without a Cognito call — which we
// explicitly guard against here.
func TestReauth_DoesNotReadJWTClaims(t *testing.T) {
	cfg := config.Config{
		CallbackURL:   "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:    "test-secret-key!!",
		HandWindow:    5 * time.Second,
		AuthTimeout:   5 * time.Second,
		CallbackPort:  8080,
		ReauthTimeout: time.Second,
		GroupsSource:  config.GroupsSourceJWTClaim,
		GroupsClaim:   "custom:groups",
		RequiredGroup: "vpn-users",
	}
	checker := &countingChecker{inGroup: false}
	sessions := NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	handler := NewHandler(cfg, sessions, checker, signer, m)
	sink := &captureSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventReauth, CID: "1", KID: "2",
		Env: map[string]string{"common_name": "user@example.com"},
	}, sink)
	handler.WaitReauth()

	if checker.calls != 1 {
		t.Fatalf("expected exactly one Cognito call on reauth, got %d", checker.calls)
	}
}
