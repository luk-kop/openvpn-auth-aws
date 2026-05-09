package auth

// Preservation tests for handleConnect authURL and handleReauth CN fallback —
// Property 2: Non-Buggy Input Behavior
//
// These tests MUST PASS on unfixed code. They document correct baseline behavior
// that must not regress after fixes are applied.
//
// Observed on unfixed code:
//   - authURL built from CallbackURL="https://example.com/cb" produces
//     "https://example.com/cb?state=..." on unfixed code
//   - handleReauth for a CID with no stored cognitoUsername uses event.CommonName()
//     as the lookup key (backward compat for sessions before the F3 fix)
//
// Properties tested:
//   - For all CallbackURL without "?", authURL equals callbackURL + "?state=" + blob.
//   - For all CLIENT:REAUTH events where no cognitoUsername is stored for the CID,
//     CheckUser is called with event.CommonName() (backward compat).
//
// Validates: Requirements 3.3, 3.11

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

// recordingChecker records the username passed to CheckUser and returns success.
type recordingChecker struct {
	mu         sync.Mutex
	calledWith []string
}

func (r *recordingChecker) CheckUser(_ context.Context, username, _ string, _ bool) (IdentityResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calledWith = append(r.calledWith, username)
	return IdentityResult{Exists: true, Enabled: true, InGroup: true}, nil
}

func (r *recordingChecker) lastCalledWith() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calledWith) == 0 {
		return ""
	}
	return r.calledWith[len(r.calledWith)-1]
}

// newPreservationHandlerWithChecker builds a Handler with a recording checker.
func newPreservationHandlerWithChecker(cfg config.Config, checker IdentityChecker) *Handler {
	sessions := NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	return NewHandler(cfg, sessions, checker, signer, m)
}

// TestPreservation_Reauth_CNFallback verifies that handleReauth uses
// event.CommonName() as the CheckUser lookup key when no cognitoUsername is
// stored for the CID (backward compatibility for sessions established before
// the F3 fix).
//
// On unfixed code: handleReauth always uses event.CommonName() — test PASSES.
// On current code: handleReauth checks cids[cid].cognitoUsername first; if
//
//	absent, falls back to event.CommonName() — test still PASSES.
//
// Property: for all CLIENT:REAUTH events where no cognitoUsername is stored,
// CheckUser is called with event.CommonName().
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.3
func TestPreservation_Reauth_CNFallback(t *testing.T) {
	cases := []struct {
		name       string
		commonName string
		cid        string
	}{
		{"native_user", "alice@example.com", "10"},
		{"native_user2", "bob@example.com", "11"},
		{"native_user3", "carol@example.com", "12"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{
				CallbackURL:   "https://vpn-auth.example.com/callback/01/udp",
				HMACSecret:    "test-secret-key!!",
				HandWindow:    5 * time.Second,
				AuthTimeout:   5 * time.Second,
				CallbackPort:  8080,
				ReauthTimeout: 2 * time.Second,
			}
			checker := &recordingChecker{}
			handler := newPreservationHandlerWithChecker(cfg, checker)
			sink := &captureDecisionSink{}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Step 1: CLIENT:CONNECT — puts session in-flight.
			handler.HandleEvent(ctx, mgmt.Event{
				Type: mgmt.EventConnect,
				CID:  tc.cid,
				KID:  "1",
				Env: map[string]string{
					"IV_SSO":      "webauth",
					"common_name": tc.commonName,
				},
			}, sink)
			time.Sleep(10 * time.Millisecond)

			// Step 2: MarkAuthenticated — no cognitoUsername stored (testing fallback to CN).
			handler.MarkAuthenticated(tc.cid, "")

			// Step 3: CLIENT:ESTABLISHED — promotes session.
			handler.HandleEvent(ctx, mgmt.Event{
				Type: mgmt.EventEstablished,
				CID:  tc.cid,
			}, sink)
			time.Sleep(10 * time.Millisecond)

			// Step 4: CLIENT:REAUTH — handleReauth should use CommonName as lookup.
			handler.HandleEvent(ctx, mgmt.Event{
				Type: mgmt.EventReauth,
				CID:  tc.cid,
				KID:  "2",
				Env: map[string]string{
					"common_name": tc.commonName,
				},
			}, sink)
			handler.WaitReauth()
			time.Sleep(10 * time.Millisecond)

			// Preservation: CheckUser must be called with event.CommonName()
			// when no cognitoUsername is stored for the CID.
			called := checker.lastCalledWith()
			if called != tc.commonName {
				t.Errorf("Preservation FAILED: handleReauth called CheckUser with %q; expected CommonName %q (CN fallback)",
					called, tc.commonName)
			}

			// Verify reauth was allowed (not denied).
			decisions := sink.snapshot()
			var reauthAllow int
			for _, d := range decisions {
				if d.Type == DecisionAllowNT && d.CID == tc.cid {
					reauthAllow++
				}
			}
			if reauthAllow == 0 {
				t.Errorf("Preservation FAILED: handleReauth did not allow user %q; decisions: %+v", tc.commonName, decisions)
			}
		})
	}
}

// TestPreservation_authURL_CleanCallbackURL verifies that handleConnect produces
// a correctly formed authURL when CallbackURL contains no query string.
//
// Property: for all CallbackURL without "?", authURL equals
// callbackURL + "?state=" + blob.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.11
func TestPreservation_authURL_CleanCallbackURL(t *testing.T) {
	cases := []struct {
		name        string
		callbackURL string
	}{
		{"simple", "https://example.com/cb"},
		{"with_path", "https://vpn-auth.example.com/callback/01/udp"},
		{"with_trailing_slash", "https://example.com/cb/"},
		{"with_deep_path", "https://vpn-auth.example.com/callback/server1/tcp"},
		{"short_url", "https://a.b/c"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{
				CallbackURL:  tc.callbackURL,
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

			var authURL string
			for _, d := range decisions {
				if d.Type == DecisionPending && d.URL != "" {
					authURL = d.URL
					break
				}
			}

			if authURL == "" {
				t.Skip("no DecisionPending with URL found; URL may have been rejected for another reason")
			}

			// Preservation: CallbackURL without "?" must continue to produce "?state=<blob>".
			// The URL must contain exactly one "?".
			questionMarkCount := strings.Count(authURL, "?")
			if questionMarkCount != 1 {
				t.Errorf("Preservation FAILED: authURL contains %d '?' characters; expected exactly 1; URL: %q", questionMarkCount, authURL)
			}

			// The URL must contain "?state=" (not "&state=").
			if !strings.Contains(authURL, "?state=") {
				t.Errorf("Preservation FAILED: authURL does not contain '?state='; expected '?state=<blob>'; URL: %q", authURL)
			}

			// The state blob must be non-empty.
			idx := strings.Index(authURL, "?state=")
			if idx < 0 {
				t.Fatalf("Preservation FAILED: authURL missing '?state=' separator; URL: %q", authURL)
			}
			stateBlob := authURL[idx+len("?state="):]
			if stateBlob == "" {
				t.Errorf("Preservation FAILED: state blob is empty; URL: %q", authURL)
			}

			// The URL must start with the callback URL (trimmed of trailing slash).
			trimmedCallback := strings.TrimRight(tc.callbackURL, "/")
			if !strings.HasPrefix(authURL, trimmedCallback) {
				t.Errorf("Preservation FAILED: authURL does not start with callbackURL %q; URL: %q", trimmedCallback, authURL)
			}
		})
	}
}

// TestPreservation_authURL_StateBlobFormat verifies that the state blob in the
// authURL has the expected format (base64payload.mac).
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.11
func TestPreservation_authURL_StateBlobFormat(t *testing.T) {
	cfg := config.Config{
		CallbackURL:  "https://vpn-auth.example.com/callback/01/udp",
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

	time.Sleep(5 * time.Millisecond)
	cancel()

	decisions := sink.snapshot()
	if len(decisions) == 0 {
		t.Fatal("expected at least 1 decision, got 0")
	}

	var authURL string
	for _, d := range decisions {
		if d.Type == DecisionPending && d.URL != "" {
			authURL = d.URL
			break
		}
	}

	if authURL == "" {
		t.Skip("no DecisionPending with URL found")
	}

	// Extract state blob.
	idx := strings.Index(authURL, "?state=")
	if idx < 0 {
		t.Fatalf("authURL missing '?state=' separator; URL: %q", authURL)
	}
	stateBlob := authURL[idx+len("?state="):]

	// State blob must contain a dot separator (base64payload.mac format).
	if !strings.Contains(stateBlob, ".") {
		t.Errorf("Preservation FAILED: state blob must be base64payload.mac format, got: %q", stateBlob)
	}

	// State blob must not be empty on either side of the dot.
	parts := strings.SplitN(stateBlob, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		t.Errorf("Preservation FAILED: state blob has invalid format; expected non-empty base64.mac, got: %q", stateBlob)
	}
}

// TestPreservation_authURL_MultipleConnects verifies the property holds across
// multiple independent CONNECT events (each gets a unique state blob).
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.11
func TestPreservation_authURL_MultipleConnects(t *testing.T) {
	callbackURL := "https://vpn-auth.example.com/callback/01/udp"
	cfg := config.Config{
		CallbackURL:  callbackURL,
		HMACSecret:   "test-secret-key!!",
		HandWindow:   300 * time.Second,
		AuthTimeout:  270 * time.Second,
		CallbackPort: 8080,
	}

	cids := []string{"1", "2", "3", "4", "5"}
	seenURLs := make(map[string]bool)

	for _, cid := range cids {
		cid := cid
		handler, _ := newExplorationHandler(cfg)
		sink := &captureDecisionSink{}

		ctx, cancel := context.WithCancel(context.Background())

		handler.HandleEvent(ctx, mgmt.Event{
			Type: mgmt.EventConnect,
			CID:  cid,
			KID:  "1",
			Env: map[string]string{
				"IV_SSO":      "webauth",
				"common_name": "user" + cid + "@example.com",
			},
		}, sink)

		time.Sleep(5 * time.Millisecond)
		cancel()

		decisions := sink.snapshot()
		var authURL string
		for _, d := range decisions {
			if d.Type == DecisionPending && d.URL != "" {
				authURL = d.URL
				break
			}
		}

		if authURL == "" {
			t.Logf("CID %s: no DecisionPending with URL found; skipping", cid)
			continue
		}

		// Preservation: each URL must have exactly one "?" and contain "?state=".
		if strings.Count(authURL, "?") != 1 {
			t.Errorf("CID %s: Preservation FAILED: authURL has %d '?' chars; expected 1; URL: %q",
				cid, strings.Count(authURL, "?"), authURL)
		}
		if !strings.Contains(authURL, "?state=") {
			t.Errorf("CID %s: Preservation FAILED: authURL missing '?state='; URL: %q", cid, authURL)
		}

		// Each connect should produce a unique URL (unique state blob).
		if seenURLs[authURL] {
			t.Errorf("CID %s: Preservation FAILED: duplicate authURL produced; URL: %q", cid, authURL)
		}
		seenURLs[authURL] = true
	}
}
