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

type fakeStore struct{}

func (fakeStore) PutPending(context.Context, PendingSession) error { return nil }

func (fakeStore) GetStatus(context.Context, string) (StatusResult, error) {
	return StatusResult{Status: StatusPending}, nil
}

func TestHandleConnectWithoutWebAuth(t *testing.T) {
	cfg := config.Config{
		APIGatewayURL: "https://vpn-auth.example.com",
		HMACSecret:    "secret",
		PollInterval:  10 * time.Millisecond,
		HandWindow:    50 * time.Millisecond,
	}
	handler := NewHandler(cfg, fakeStore{}, nil, secrets.NewStaticSigner("secret"), metrics.NewEmitter(&strings.Builder{}, "test"))
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

func TestHandleConnectIgnoresPassword(t *testing.T) {
	cfg := config.Config{
		APIGatewayURL: "https://vpn-auth.example.com",
		HMACSecret:    "secret",
		PollInterval:  10 * time.Millisecond,
		HandWindow:    50 * time.Millisecond,
	}
	handler := NewHandler(cfg, fakeStore{}, nil, secrets.NewStaticSigner("secret"), metrics.NewEmitter(&strings.Builder{}, "test"))
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

	// Cancel context to stop pollSession before timeout
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

func TestPollSessionVerifiesAuthToken(t *testing.T) {
	cfg := config.Config{
		APIGatewayURL: "https://vpn-auth.example.com",
		HMACSecret:    "secret",
		PollInterval:  10 * time.Millisecond,
		HandWindow:    200 * time.Millisecond,
	}

	// Mock store that returns SUCCESS with invalid auth_token
	store := &fakeStoreWithToken{
		status:    StatusSuccess,
		authToken: "invalid-token",
	}

	handler := NewHandler(cfg, store, nil, secrets.NewStaticSigner("secret"), metrics.NewEmitter(&strings.Builder{}, "test"))
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

	// Wait for pollSession to check status and deny due to invalid token
	time.Sleep(50 * time.Millisecond)
	cancel()

	if len(sink.decisions) < 2 {
		t.Fatalf("expected at least 2 decisions (pending + deny), got %d", len(sink.decisions))
	}
	// First decision: DecisionPending
	if sink.decisions[0].Type != DecisionPending {
		t.Fatalf("expected DecisionPending, got %d", sink.decisions[0].Type)
	}
	// Second decision: DecisionDeny due to invalid auth_token
	if sink.decisions[1].Type != DecisionDeny {
		t.Fatalf("expected DecisionDeny, got %d", sink.decisions[1].Type)
	}
	if sink.decisions[1].Reason != "auth verification failed" {
		t.Fatalf("expected 'auth verification failed', got %q", sink.decisions[1].Reason)
	}
}

type fakeStoreWithToken struct {
	status    Status
	authToken string
}

func (s *fakeStoreWithToken) PutPending(context.Context, PendingSession) error { return nil }

func (s *fakeStoreWithToken) GetStatus(context.Context, string) (StatusResult, error) {
	return StatusResult{Status: s.status, AuthToken: s.authToken}, nil
}

func TestHandleConnectRejectsMissingCommonName(t *testing.T) {
	cfg := config.Config{
		APIGatewayURL: "https://vpn-auth.example.com",
		HMACSecret:    "secret",
		PollInterval:  10 * time.Millisecond,
		HandWindow:    50 * time.Millisecond,
	}
	handler := NewHandler(cfg, fakeStore{}, nil, secrets.NewStaticSigner("secret"), metrics.NewEmitter(&strings.Builder{}, "test"))
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
