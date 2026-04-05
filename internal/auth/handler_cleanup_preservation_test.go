//go:build post_fix

package auth

// Cleanup preservation tests for cidToCognitoUsername — Property 2: Session Cleanup
//
// These tests MUST PASS on FIXED code. They verify that the new cidToCognitoUsername
// map introduced by the F3 fix is cleaned up correctly on disconnect and eviction,
// with no memory leaks.
//
// Build tag: post_fix — these tests reference Handler.cidToCognitoUsername which
// does not exist on unfixed code. They are compiled and run after the fix is applied
// (task 3.3). Run with: go test -tags post_fix ./internal/auth/...
//
// Properties tested:
//   - After MarkAuthenticated(cid, cognitoUsername) then CLIENT:DISCONNECT,
//     cidToCognitoUsername[cid] is deleted (no leak).
//   - After MarkAuthenticated(cid, cognitoUsername) then evictSession(cid),
//     cidToCognitoUsername[cid] is deleted (no leak).
//
// Validates: Requirements 3.6

import (
	"context"
	"testing"
	"time"

	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/mgmt"
)

// TestPreservation_SessionCleanup_Disconnect verifies that handleDisconnect
// deletes the cidToCognitoUsername entry for the CID, preventing memory leaks.
//
// Property: after MarkAuthenticated(cid, cognitoUsername) then CLIENT:DISCONNECT,
// cidToCognitoUsername[cid] must be absent.
//
// EXPECTED OUTCOME: PASSES on fixed code.
//
// Validates: Requirements 3.6
func TestPreservation_SessionCleanup_Disconnect(t *testing.T) {
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

	cid := "20"
	cognitoUsername := "Google_1234567890"
	commonName := "user@corp.com"

	// Step 1: CLIENT:CONNECT.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  cid,
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": commonName,
		},
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Step 2: MarkAuthenticated with cognitoUsername (fixed code signature).
	handler.MarkAuthenticated(cid, cognitoUsername)

	// Step 3: CLIENT:ESTABLISHED.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished,
		CID:  cid,
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Verify the entry was stored.
	handler.mu.Lock()
	stored, exists := handler.cidToCognitoUsername[cid]
	handler.mu.Unlock()
	if !exists || stored != cognitoUsername {
		t.Fatalf("Setup FAILED: cidToCognitoUsername[%q] = %q (exists=%v); expected %q",
			cid, stored, exists, cognitoUsername)
	}

	// Step 4: CLIENT:DISCONNECT — should clean up cidToCognitoUsername.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventDisconnect,
		CID:  cid,
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Preservation: cidToCognitoUsername[cid] must be deleted after disconnect.
	handler.mu.Lock()
	_, stillExists := handler.cidToCognitoUsername[cid]
	handler.mu.Unlock()
	if stillExists {
		t.Errorf("Preservation FAILED: cidToCognitoUsername[%q] still exists after CLIENT:DISCONNECT; expected deletion (memory leak)", cid)
	}
}

// TestPreservation_SessionCleanup_Eviction verifies that evictSession deletes
// the cidToCognitoUsername entry for the CID, preventing memory leaks.
//
// Property: after MarkAuthenticated(cid, cognitoUsername) then evictSession(cid),
// cidToCognitoUsername[cid] must be absent.
//
// EXPECTED OUTCOME: PASSES on fixed code.
//
// Validates: Requirements 3.6
func TestPreservation_SessionCleanup_Eviction(t *testing.T) {
	cfg := config.Config{
		CallbackURL:          "https://vpn-auth.example.com/callback/01/udp",
		HMACSecret:           "test-secret-key!!",
		HandWindow:           5 * time.Second,
		AuthTimeout:          5 * time.Second,
		CallbackPort:         8080,
		ReauthTimeout:        2 * time.Second,
		SingleSessionPerUser: true,
	}
	checker := &recordingChecker{}
	handler := newPreservationHandlerWithChecker(cfg, checker)
	sink := &captureDecisionSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cid := "21"
	cognitoUsername := "Google_9876543210"
	commonName := "federated@corp.com"

	// Step 1: CLIENT:CONNECT.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventConnect,
		CID:  cid,
		KID:  "1",
		Env: map[string]string{
			"IV_SSO":      "webauth",
			"common_name": commonName,
		},
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Step 2: MarkAuthenticated with cognitoUsername (fixed code signature).
	handler.MarkAuthenticated(cid, cognitoUsername)

	// Step 3: CLIENT:ESTABLISHED.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished,
		CID:  cid,
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Verify the entry was stored.
	handler.mu.Lock()
	stored, exists := handler.cidToCognitoUsername[cid]
	handler.mu.Unlock()
	if !exists || stored != cognitoUsername {
		t.Fatalf("Setup FAILED: cidToCognitoUsername[%q] = %q (exists=%v); expected %q",
			cid, stored, exists, cognitoUsername)
	}

	// Step 4: evictSession — should clean up cidToCognitoUsername.
	_, evicted := handler.evictSession(cid)
	if !evicted {
		t.Fatalf("Setup FAILED: evictSession(%q) returned evicted=false; expected true", cid)
	}

	// Preservation: cidToCognitoUsername[cid] must be deleted after eviction.
	handler.mu.Lock()
	_, stillExists := handler.cidToCognitoUsername[cid]
	handler.mu.Unlock()
	if stillExists {
		t.Errorf("Preservation FAILED: cidToCognitoUsername[%q] still exists after evictSession; expected deletion (memory leak)", cid)
	}
}
