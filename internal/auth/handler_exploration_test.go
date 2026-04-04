package auth

// BugConditionExploration: L4 and L14
//
// This file contains bug condition exploration tests that are EXPECTED TO FAIL
// on unfixed code. The failures confirm the bugs exist.
//
// L4 Bug: CallbackURL with existing query string produces malformed URL.
//   handleConnect builds authURL as fmt.Sprintf("%s?state=%s", ...).
//   If CallbackURL already contains "?foo=bar", the result is "...?foo=bar?state=..."
//   — an invalid URL with two "?" characters.
//   Counterexample found on unfixed code:
//     BUG L4 CONFIRMED: authURL contains 2 '?' characters, expected exactly 1;
//     URL: "https://example.com/cb?foo=bar?state=eyJzaWQiOiIyVWVSZUlhQ1NEbWxCOFY3TEJPZlNRIiwiaWF0IjoxNzc1MzA4MDA0LCJleHAiOjE3NzUzMDgyNzR9.41GjdN32N9LheanSL2rwbYoxyZalMSzdsToDiBUPTmY"
//
// L14 Bug: Orphan session left in store on URL-too-long deny path.
//   h.sessions.Put(session) is called before the len(authURL) > MaxWebAuthURLLen check.
//   When the URL is too long, a deny is sent but the session remains in the store.
//   Counterexample found on unfixed code:
//     BUG L14 CONFIRMED: sessions.Len()==1 after URL-too-long deny; expected 0
//     (orphan session left in store)

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/metrics"
	"openvpn-auth-aws/internal/mgmt"
	"openvpn-auth-aws/internal/secrets"
)

// captureDecisionSink captures decisions for inspection in exploration tests.
type captureDecisionSink struct {
	mu        sync.Mutex
	decisions []Decision
}

func (c *captureDecisionSink) Send(d Decision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decisions = append(c.decisions, d)
	return nil
}

func (c *captureDecisionSink) snapshot() []Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]Decision, len(c.decisions))
	copy(cp, c.decisions)
	return cp
}

// newExplorationHandler builds a Handler with a fresh SessionStore for exploration tests.
func newExplorationHandler(cfg config.Config) (*Handler, *SessionStore) {
	sessions := NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	h := NewHandler(cfg, sessions, nil, signer, m)
	return h, sessions
}

// TestBugCondition_L4_DoubleQuestionMark demonstrates that handleConnect produces
// a malformed authURL when CallbackURL already contains a query string.
//
// On UNFIXED code: authURL contains two "?" characters — test FAILS (expected outcome).
// On FIXED code:   authURL contains exactly one "?" — test PASSES.
//
// Validates: Requirements 1.12, 2.12
func TestBugCondition_L4_DoubleQuestionMark(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://example.com/cb?foo=bar",
		HMACSecret:   "test-secret-key!!",
		HandWindow:   300 * time.Second,
		AuthTimeout:  270 * time.Second,
		CallbackPort: 8080,
	}
	handler, _ := newExplorationHandler(cfg)
	sink := &captureDecisionSink{}

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

	// Wait briefly for handleConnect to send DecisionPending.
	time.Sleep(5 * time.Millisecond)
	cancel()

	decisions := sink.snapshot()
	if len(decisions) == 0 {
		t.Fatal("expected at least 1 decision, got 0")
	}

	// Find the DecisionPending with the URL.
	var authURL string
	for _, d := range decisions {
		if d.Type == DecisionPending && d.URL != "" {
			authURL = d.URL
			break
		}
	}

	if authURL == "" {
		// If no pending decision was sent, the URL may have been rejected for
		// another reason — skip this check.
		t.Skip("no DecisionPending with URL found; URL may have been rejected for another reason")
	}

	questionMarkCount := strings.Count(authURL, "?")

	// On unfixed code: questionMarkCount=2 — this assertion FAILS (expected).
	// On fixed code:   questionMarkCount=1 — this assertion PASSES.
	if questionMarkCount != 1 {
		t.Errorf("BUG L4 CONFIRMED: authURL contains %d '?' characters, expected exactly 1; URL: %q", questionMarkCount, authURL)
	}
}

// TestBugCondition_L14_OrphanSession demonstrates that handleConnect leaves an
// orphan PendingSession in the store when the authURL exceeds MaxWebAuthURLLen.
//
// On UNFIXED code: sessions.Len()==1 after deny — test FAILS (expected outcome).
// On FIXED code:   sessions.Len()==0 after deny — test PASSES.
//
// Validates: Requirements 1.9, 2.9
func TestBugCondition_L14_OrphanSession(t *testing.T) {
	// Construct a CallbackURL long enough that the full authURL > MaxWebAuthURLLen (229).
	// authURL = callbackURL + "?state=" + stateBlob (~128 chars)
	// So callbackURL of 110 chars pushes total well over 229.
	longCallbackURL := "https://vpn-auth.example.com/callback/" + strings.Repeat("x", 110)

	cfg := config.Config{
		CallbackURL:  longCallbackURL,
		HMACSecret:   "test-secret-key!!",
		HandWindow:   300 * time.Second,
		AuthTimeout:  270 * time.Second,
		CallbackPort: 8080,
	}
	handler, sessions := newExplorationHandler(cfg)
	sink := &captureDecisionSink{}

	handler.HandleEvent(context.Background(), mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "1",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "test@example.com",
		},
	}, sink)

	decisions := sink.snapshot()
	if len(decisions) == 0 {
		t.Fatal("expected at least 1 decision, got 0")
	}

	// Verify the deny was sent for the right reason.
	denied := false
	for _, d := range decisions {
		if d.Type == DecisionDeny && d.Reason == "auth URL too long" {
			denied = true
			break
		}
	}
	if !denied {
		t.Fatalf("expected DecisionDeny with reason 'auth URL too long', got: %+v", decisions)
	}

	// On unfixed code: sessions.Len()==1 — this assertion FAILS (expected).
	// On fixed code:   sessions.Len()==0 — this assertion PASSES.
	if sessions.Len() != 0 {
		t.Errorf("BUG L14 CONFIRMED: sessions.Len()==%d after URL-too-long deny; expected 0 (orphan session left in store)", sessions.Len())
	}
}

// TestBugCondition_F3_ReauthUsesCertificateCN demonstrates that handleReauth
// calls CheckUser with event.CommonName() (the certificate CN / email) instead
// of the stored cognito:username for federated users.
//
// For federated users, the Cognito username is "{ProviderName}_{identifier}"
// (e.g. "Google_1234567890"), not the email. AdminGetUser rejects the email
// for federated accounts, causing reauth to fail with "cognito unavailable".
//
// On UNFIXED code: CheckUser is called with "user@corp.com" (CommonName) →
//
//	the mock returns an error → reauth denied — test FAILS (expected outcome).
//
// On FIXED code:   CheckUser is called with "Google_1234567890" (stored
//
//	cognitoUsername) → success → reauth allowed — test PASSES.
//
// Validates: Requirements 1.3, 2.3
func TestBugCondition_F3_ReauthUsesCertificateCN(t *testing.T) {
	cfg := config.Config{
		CallbackURL:   "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:    "test-secret-key!!",
		HandWindow:    5 * time.Second,
		AuthTimeout:   5 * time.Second,
		CallbackPort:  8080,
		ReauthTimeout: 2 * time.Second,
	}

	sessions := NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	m := metrics.NewEmitter(&strings.Builder{}, "test")

	// federatedChecker: succeeds only when called with the Cognito username,
	// fails (simulating UserNotFoundException) when called with the email CN.
	checker := &federatedReauthChecker{}
	handler := NewHandler(cfg, sessions, checker, signer, m)
	sink := &captureDecisionSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Step 1: CLIENT:CONNECT — puts session in-flight.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  "10",
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": "user@corp.com", // certificate CN (email)
		},
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Step 2: Simulate callback success — MarkAuthenticated is called.
	// On unfixed code: MarkAuthenticated(cid) only takes cid, no cognitoUsername.
	// On fixed code:   MarkAuthenticated(cid, cognitoUsername) stores the username.
	handler.MarkAuthenticated("10", "Google_1234567890")

	// Step 3: CLIENT:ESTABLISHED — promotes session.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished,
		CID:  "10",
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Step 4: CLIENT:REAUTH — this is where the bug manifests.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventReauth,
		CID:  "10",
		KID:  "2",
		Env: map[string]string{
			"common_name": "user@corp.com", // certificate CN
		},
	}, sink)
	handler.WaitReauth()
	time.Sleep(10 * time.Millisecond)

	// On unfixed code: handleReauth uses event.CommonName() = "user@corp.com"
	// → checker.CheckUser("user@corp.com") returns error → DecisionDeny.
	// On fixed code: handleReauth uses stored cognitoUsername "Google_1234567890"
	// → checker.CheckUser("Google_1234567890") returns success → DecisionAllowNT.
	decisions := sink.snapshot()
	var reauthAllow, reauthDeny int
	for _, d := range decisions {
		if d.Type == DecisionAllowNT {
			reauthAllow++
		}
		if d.Type == DecisionDeny && d.CID == "10" {
			// Filter out the auth-timeout deny that may fire if connect was slow.
			if d.Reason != "auth timeout" {
				reauthDeny++
			}
		}
	}

	if reauthDeny > 0 {
		t.Errorf("BUG F3 CONFIRMED: handleReauth denied federated user; CheckUser was called with: %v (expected 'Google_1234567890', not 'user@corp.com')",
			checker.calledWith)
	}
	if reauthAllow == 0 {
		t.Errorf("BUG F3 CONFIRMED: handleReauth did not allow federated user; CheckUser was called with: %v",
			checker.calledWith)
	}
}

// federatedReauthChecker simulates Cognito AdminGetUser behaviour for a federated user:
// - "Google_1234567890" (CognitoUsername) → success
// - "user@corp.com" (certificate CN / email) → error (UserNotFoundException)
type federatedReauthChecker struct {
	calledWith []string
}

func (f *federatedReauthChecker) CheckUser(_ context.Context, username, _ string, _ bool) (IdentityResult, error) {
	f.calledWith = append(f.calledWith, username)
	if username == "Google_1234567890" {
		return IdentityResult{Exists: true, Enabled: true, InGroup: true}, nil
	}
	// Simulate UserNotFoundException for email CN — what Cognito returns for federated users.
	return IdentityResult{}, fmt.Errorf("UserNotFoundException: User does not exist: %s", username)
}
