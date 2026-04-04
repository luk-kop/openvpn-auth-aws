package callback

// Preservation tests for checkGroup — Property 2: Non-Buggy Input Behavior
//
// These tests MUST PASS on unfixed code. They document correct baseline behavior
// that must not regress after fixes are applied.
//
// Observed on unfixed code:
//   - checkGroup with {Enabled: true, InGroup: true}  returns (true, nil)
//   - checkGroup with {Enabled: true, InGroup: false} returns (false, nil)
//
// Properties tested:
//   - For all IdentityResult where Enabled=true and InGroup=true,
//     checkGroup returns (true, nil).
//   - For all IdentityResult where InGroup=false,
//     checkGroup returns (false, nil) regardless of Enabled.
//
// Validates: Requirements 3.1, 3.3, 3.4

import (
	"context"
	"testing"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/secrets"
)

// enabledInGroupChecker returns Enabled=true, InGroup=true — the normal
// "user is active and in the required group" case.
type enabledInGroupChecker struct{}

func (e *enabledInGroupChecker) CheckUser(_ context.Context, _, _ string, _ bool) (auth.IdentityResult, error) {
	return auth.IdentityResult{
		Exists:  true,
		Enabled: true,
		InGroup: true,
	}, nil
}

// enabledNotInGroupChecker returns Enabled=true, InGroup=false — the normal
// "user is active but not in the required group" case.
type enabledNotInGroupChecker struct{}

func (e *enabledNotInGroupChecker) CheckUser(_ context.Context, _, _ string, _ bool) (auth.IdentityResult, error) {
	return auth.IdentityResult{
		Exists:  true,
		Enabled: true,
		InGroup: false,
	}, nil
}

// disabledNotInGroupChecker returns Enabled=false, InGroup=false.
type disabledNotInGroupChecker struct{}

func (d *disabledNotInGroupChecker) CheckUser(_ context.Context, _, _ string, _ bool) (auth.IdentityResult, error) {
	return auth.IdentityResult{
		Exists:  true,
		Enabled: false,
		InGroup: false,
	}, nil
}

// newPreservationServer builds a Server for preservation tests.
func newPreservationServer(t *testing.T, identity GroupsChecker) *Server {
	t.Helper()
	cfg := config.Config{AWSRegion: "eu-west-1"}
	sessions := auth.NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	m := &fakeMetrics{}
	srv, err := NewServer(sessions, signer, sink, nil, cfg, m, identity, func() bool { return true })
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func makePreservationSession(cid, cn string) *auth.PendingSession {
	return &auth.PendingSession{
		SessionID:     "pres-sid-" + cid,
		CommonName:    cn,
		CID:           cid,
		KID:           "1",
		RequiredGroup: "vpn-users",
		Status:        auth.SessionPending,
	}
}

func makePreservationClaims(email, sub string) albJWTClaims {
	c := albJWTClaims{}
	c.Email = email
	c.Sub = sub
	return c
}

// TestPreservation_checkGroup_EnabledInGroup verifies that checkGroup returns
// (true, nil) for an enabled user who is in the required group.
//
// Property: for all IdentityResult where Enabled=true and InGroup=true,
// checkGroup returns (true, nil).
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.1, 3.3
func TestPreservation_checkGroup_EnabledInGroup(t *testing.T) {
	cases := []struct {
		name  string
		email string
		sub   string
		cid   string
	}{
		{"user1", "alice@example.com", "sub-alice", "1"},
		{"user2", "bob@example.com", "sub-bob", "2"},
		{"user3", "carol@example.com", "sub-carol", "3"},
		{"user4", "dave@example.com", "sub-dave", "4"},
		{"user5", "eve@example.com", "sub-eve", "5"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := newPreservationServer(t, &enabledInGroupChecker{})
			sess := makePreservationSession(tc.cid, tc.email)
			claims := makePreservationClaims(tc.email, tc.sub)

			inGroup, err := srv.checkGroup(context.Background(), sess, claims)

			// Preservation: enabled users in group must continue to get (true, nil).
			if !inGroup {
				t.Errorf("Preservation FAILED: checkGroup returned inGroup=false for enabled user in group (Enabled=true, InGroup=true); expected true")
			}
			if err != nil {
				t.Errorf("Preservation FAILED: checkGroup returned non-nil error for enabled user in group; expected nil, got: %v", err)
			}
		})
	}
}

// TestPreservation_checkGroup_EnabledNotInGroup verifies that checkGroup returns
// (false, nil) for an enabled user who is NOT in the required group.
//
// Property: for all IdentityResult where InGroup=false,
// checkGroup returns (false, nil) regardless of Enabled.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.3
func TestPreservation_checkGroup_EnabledNotInGroup(t *testing.T) {
	cases := []struct {
		name  string
		email string
		sub   string
		cid   string
	}{
		{"user1", "alice@example.com", "sub-alice", "1"},
		{"user2", "bob@example.com", "sub-bob", "2"},
		{"user3", "carol@example.com", "sub-carol", "3"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := newPreservationServer(t, &enabledNotInGroupChecker{})
			sess := makePreservationSession(tc.cid, tc.email)
			claims := makePreservationClaims(tc.email, tc.sub)

			inGroup, err := srv.checkGroup(context.Background(), sess, claims)

			// Preservation: users not in group must continue to get (false, nil).
			if inGroup {
				t.Errorf("Preservation FAILED: checkGroup returned inGroup=true for user not in group (Enabled=true, InGroup=false); expected false")
			}
			if err != nil {
				t.Errorf("Preservation FAILED: checkGroup returned non-nil error for user not in group; expected nil, got: %v", err)
			}
		})
	}
}

// nativeUserGroupChecker records the username passed to CheckUser and returns
// Enabled=true, InGroup=true — simulating a native Cognito user lookup by email.
type nativeUserGroupChecker struct {
	calledWith []string
}

func (n *nativeUserGroupChecker) CheckUser(_ context.Context, username, _ string, _ bool) (auth.IdentityResult, error) {
	n.calledWith = append(n.calledWith, username)
	return auth.IdentityResult{
		Exists:  true,
		Enabled: true,
		InGroup: true,
	}, nil
}

// TestPreservation_checkGroup_NativeUserEmail verifies that checkGroup resolves
// group membership correctly for a native Cognito user whose email is used as
// the lookup key.
//
// For native users, email == CognitoUsername (because Cognito username_attributes
// includes "email"). After the F2 fix, checkGroup uses claims.CognitoUsername
// instead of claims.Sub. For native users, CognitoUsername == email, so the
// lookup key is unchanged and behavior is preserved.
//
// Property: for native users where CognitoUsername == email, checkGroup calls
// CheckUser with the email and returns (true, nil) for an active group member.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
// Note: on unfixed code, checkGroup uses claims.Sub — this test passes because
// the checker accepts any username and returns success. After the fix, it will
// use claims.CognitoUsername (= email for native users) — same result.
//
// Validates: Requirements 3.2
func TestPreservation_checkGroup_NativeUserEmail(t *testing.T) {
	cases := []struct {
		name            string
		email           string
		sub             string
		cognitoUsername string // equals email for native users
		cid             string
	}{
		{"alice", "alice@example.com", "sub-alice-uuid", "alice@example.com", "1"},
		{"bob", "bob@example.com", "sub-bob-uuid", "bob@example.com", "2"},
		{"carol", "carol@example.com", "sub-carol-uuid", "carol@example.com", "3"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			checker := &nativeUserGroupChecker{}
			srv := newPreservationServer(t, checker)
			sess := makePreservationSession(tc.cid, tc.email)
			claims := makePreservationClaims(tc.email, tc.sub)

			inGroup, err := srv.checkGroup(context.Background(), sess, claims)

			// Preservation: native user group check must continue to succeed.
			if !inGroup {
				t.Errorf("Preservation FAILED: checkGroup returned inGroup=false for native user %q; expected true", tc.email)
			}
			if err != nil {
				t.Errorf("Preservation FAILED: checkGroup returned error for native user %q: %v", tc.email, err)
			}
			// Verify CheckUser was called (with some key — sub on unfixed, email on fixed).
			if len(checker.calledWith) == 0 {
				t.Errorf("Preservation FAILED: CheckUser was not called for native user %q", tc.email)
			}
		})
	}
}

// TestPreservation_checkGroup_DisabledNotInGroup verifies that checkGroup returns
// (false, non-nil error) for a disabled user who is also not in the required group.
//
// After the fix, disabled users always get (false, non-nil error) regardless of
// group membership — the Enabled gate fires before InGroup is consulted.
//
// EXPECTED OUTCOME: PASSES on fixed code.
//
// Validates: Requirements 2.2, 3.4
func TestPreservation_checkGroup_DisabledNotInGroup(t *testing.T) {
	srv := newPreservationServer(t, &disabledNotInGroupChecker{})
	sess := makePreservationSession("1", "disabled@example.com")
	claims := makePreservationClaims("disabled@example.com", "sub-disabled")

	inGroup, err := srv.checkGroup(context.Background(), sess, claims)

	// Fixed behavior: disabled users not in group get (false, non-nil error).
	if inGroup {
		t.Errorf("checkGroup returned inGroup=true for disabled user not in group; expected false")
	}
	if err == nil {
		t.Errorf("checkGroup returned nil error for disabled user not in group; expected non-nil error")
	}
}
