package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/metrics"
	"openvpn-auth-aws/internal/mgmt"
	"openvpn-auth-aws/internal/secrets"
)

type captureSink struct {
	decisions []Decision
}

func (c *captureSink) Send(d Decision) {
	c.decisions = append(c.decisions, d)
}

func newTestHandler(cfg config.Config) *Handler {
	sessions := NewSessionStore()
	signer := secrets.NewStaticSigner("secret")
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	return NewHandler(cfg, sessions, nil, signer, m)
}

func TestHandleConnectWithoutWebAuth(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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

	if len(sink.decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.decisions))
	}
	if sink.decisions[0].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.decisions[0].Type)
	}
	if sink.decisions[0].Reason != "client does not support WebAuth" {
		t.Fatalf("unexpected reason: %q", sink.decisions[0].Reason)
	}
}

func TestHandleConnectAcceptsOpenURL(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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

	if len(sink.decisions) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.decisions))
	}
	if sink.decisions[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", sink.decisions[0].Type)
	}
}

func TestHandleConnectAcceptsCSVWebAuth(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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

	if len(sink.decisions) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.decisions))
	}
	if sink.decisions[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", sink.decisions[0].Type)
	}
}

func TestHandleConnectRejectsCrtext(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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

	if len(sink.decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.decisions))
	}
	if sink.decisions[0].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.decisions[0].Type)
	}
}

func TestHandleConnectIgnoresPassword(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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

	if len(sink.decisions) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.decisions))
	}
	if sink.decisions[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending (WebAuth flow), got %d", sink.decisions[0].Type)
	}
	if sink.decisions[0].URL == "" {
		t.Fatal("expected WebAuth URL, got empty string")
	}
}

func TestHandleConnectStateBlob(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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

	if len(sink.decisions) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.decisions))
	}
	d := sink.decisions[0]
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
		HMACSecret:   "secret",
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

	if len(sink.decisions) < 1 {
		t.Fatalf("expected at least 1 decision, got %d", len(sink.decisions))
	}
	d := sink.decisions[0]
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
	// Construct a callback URL long enough that OPEN_URL: + url > MaxWebAuthURLLen.
	// MaxWebAuthURLLen = 229; "OPEN_URL:" = 9 bytes; state blob ~128 bytes.
	// So callback URL of 100 bytes will push total well over 229.
	longCallbackURL := "https://vpn-auth.example.com/callback/" + strings.Repeat("x", 100)
	cfg := config.Config{
		CallbackURL:  longCallbackURL,
		HMACSecret:   "secret",
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

	if len(sink.decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.decisions))
	}
	d := sink.decisions[0]
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
		HMACSecret:   "secret",
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

	if len(sink.decisions) < 2 {
		t.Fatalf("expected at least 2 decisions (pending + deny), got %d", len(sink.decisions))
	}
	if sink.decisions[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", sink.decisions[0].Type)
	}
	if sink.decisions[1].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.decisions[1].Type)
	}
	if sink.decisions[1].Reason != "auth timeout" {
		t.Fatalf("expected 'auth timeout', got %q", sink.decisions[1].Reason)
	}
}

func TestHandleConnectDisconnectCleanup(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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
		HMACSecret:   "secret",
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

	if len(sink.decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(sink.decisions))
	}
	if sink.decisions[0].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.decisions[0].Type)
	}
	if sink.decisions[0].Reason != "missing common name" {
		t.Fatalf("unexpected reason: %q", sink.decisions[0].Reason)
	}
}

func TestHandleEstablishedClearsInFlight(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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
		CallbackURL:          "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:           "secret",
		HandWindow:           5 * time.Second,
		AuthTimeout:          5 * time.Second,
		CallbackPort:         8080,
		SingleSessionPerUser: true,
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
	for _, d := range sink.decisions {
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
		CallbackURL:          "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:           "secret",
		HandWindow:           5 * time.Second,
		AuthTimeout:          5 * time.Second,
		CallbackPort:         8080,
		SingleSessionPerUser: true,
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
	for _, d := range sink.decisions {
		if d.Type == DecisionKill && d.CID == "1" {
			kill++
		}
	}
	if kill != 1 {
		t.Fatalf("expected 1 DecisionKill for established CID=1, got %d; decisions: %+v", kill, sink.decisions)
	}
}

func TestHandleConnectAllowsNewSessionAfterDisconnect(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:   "secret",
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
	for _, d := range sink.decisions {
		if d.Type == DecisionPending {
			pending++
		}
	}
	if pending != 2 {
		t.Fatalf("expected 2 DecisionPending (one per connect), got %d; decisions: %+v", pending, sink.decisions)
	}
}
