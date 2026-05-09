package auth

// Cleanup preservation tests for cognitoUsername — Property 2: Session Cleanup
//
// These tests verify that the cognitoUsername field in cidState is cleaned up
// correctly on disconnect and eviction, with no memory leaks.
//
// Properties tested:
//   - After MarkAuthenticated(cid, cognitoUsername) then CLIENT:DISCONNECT,
//     cids[cid].cognitoUsername is gone (entry deleted).
//   - After MarkAuthenticated(cid, cognitoUsername) then evictSession(cid),
//     cids[cid] is gone entirely.
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
// removes the cidState entry (including cognitoUsername) for the CID,
// preventing memory leaks.
//
// Property: after MarkAuthenticated(cid, cognitoUsername) then CLIENT:DISCONNECT,
// cids[cid] must be absent.
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

	// Step 2: MarkAuthenticated with cognitoUsername.
	handler.MarkAuthenticated(cid, cognitoUsername)

	// Step 3: CLIENT:ESTABLISHED.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished,
		CID:  cid,
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Verify cognitoUsername was stored.
	handler.mu.Lock()
	st := handler.cids[cid]
	var stored string
	if st != nil {
		stored = st.cognitoUsername
	}
	handler.mu.Unlock()
	if stored != cognitoUsername {
		t.Fatalf("Setup FAILED: cids[%q].cognitoUsername = %q; expected %q",
			cid, stored, cognitoUsername)
	}

	// Step 4: CLIENT:DISCONNECT — should remove cids entry entirely.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventDisconnect,
		CID:  cid,
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Preservation: cids[cid] must be deleted after disconnect (no memory leak).
	handler.mu.Lock()
	_, stillExists := handler.cids[cid]
	handler.mu.Unlock()
	if stillExists {
		t.Errorf("Preservation FAILED: cids[%q] still exists after CLIENT:DISCONNECT; expected deletion (memory leak)", cid)
	}
}

// TestPreservation_SessionCleanup_Eviction verifies that evictSession removes
// the cidState entry (including cognitoUsername) for the CID, preventing
// memory leaks.
//
// Property: after MarkAuthenticated(cid, cognitoUsername) then evictSession(cid),
// cids[cid] must be absent.
//
// Validates: Requirements 3.6
func TestPreservation_SessionCleanup_Eviction(t *testing.T) {
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

	// Step 2: MarkAuthenticated with cognitoUsername.
	handler.MarkAuthenticated(cid, cognitoUsername)

	// Step 3: CLIENT:ESTABLISHED.
	handler.HandleEvent(ctx, mgmt.Event{
		Type: mgmt.EventEstablished,
		CID:  cid,
	}, sink)
	time.Sleep(10 * time.Millisecond)

	// Verify cognitoUsername was stored.
	handler.mu.Lock()
	st := handler.cids[cid]
	var stored string
	if st != nil {
		stored = st.cognitoUsername
	}
	handler.mu.Unlock()
	if stored != cognitoUsername {
		t.Fatalf("Setup FAILED: cids[%q].cognitoUsername = %q; expected %q",
			cid, stored, cognitoUsername)
	}

	// Step 4: evictSession — should remove cids entry entirely.
	_, evicted := handler.evictSession(cid)
	if !evicted {
		t.Fatalf("Setup FAILED: evictSession(%q) returned evicted=false; expected true", cid)
	}

	// Preservation: cids[cid] must be deleted after eviction (no memory leak).
	handler.mu.Lock()
	_, stillExists := handler.cids[cid]
	handler.mu.Unlock()
	if stillExists {
		t.Errorf("Preservation FAILED: cids[%q] still exists after evictSession; expected deletion (memory leak)", cid)
	}
}
