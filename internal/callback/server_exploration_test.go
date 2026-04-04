package callback

// BugConditionExploration: M10-callback and F2
//
// This file contains bug condition exploration tests that are EXPECTED TO FAIL
// on unfixed code. The failures confirm the bugs exist.
//
// M10-callback Bug: checkGroup calls identity.CheckUser but only returns result.InGroup,
// ignoring result.Enabled. A disabled user who is still a group member gets
// VPN access (returns true, nil) instead of being denied (false, non-nil error).
//
// Counterexample found on unfixed code (actual test output):
//   BUG M10-callback CONFIRMED: checkGroup returned inGroup=true for a disabled
//   user (Enabled=false, InGroup=true); expected false
//   BUG M10-callback CONFIRMED: checkGroup returned nil error for a disabled
//   user; expected non-nil error
//
// Root cause: checkGroup returns result.InGroup directly without first checking
// result.Enabled. The Enabled gate only exists on the reauth path (finishReauth).
//
// F2 Bug: checkGroup calls CheckUser with claims.Sub (a UUID) instead of
// claims.CognitoUsername (the actual Cognito username). For federated users,
// AdminGetUser does not accept sub as a Username — it requires the Cognito
// username (e.g. "Google_1234567890"). This causes UserNotFoundException and
// the callback fails with "group check error".
//
// Counterexample found on unfixed code (actual test output):
//   BUG F2 CONFIRMED: checkGroup called CheckUser with sub UUID instead of
//   CognitoUsername; got "group check error" for an active federated user

import (
	"context"
	"errors"
	"testing"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/secrets"
)

// disabledButInGroupChecker returns Enabled=false, InGroup=true — the exact
// bug condition for M10-callback.
type disabledButInGroupChecker struct{}

func (d *disabledButInGroupChecker) CheckUser(_ context.Context, _, _ string, _ bool) (auth.IdentityResult, error) {
	return auth.IdentityResult{
		Exists:  true,
		Enabled: false,
		InGroup: true,
	}, nil
}

// TestBugCondition_M10_callback demonstrates that checkGroup grants access to a
// disabled user who is still a group member.
//
// On UNFIXED code: returns (true, nil) — test FAILS (expected outcome).
// On FIXED code:   returns (false, non-nil error) — test PASSES.
//
// Validates: Requirements 1.1, 2.2
func TestBugCondition_M10_callback(t *testing.T) {
	cfg := config.Config{
		AWSRegion: "eu-west-1",
	}
	sessions := auth.NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	m := &fakeMetrics{}

	srv, err := NewServer(sessions, signer, sink, nil, cfg, m, &disabledButInGroupChecker{}, func() bool { return true })
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sess := &auth.PendingSession{
		SessionID:     "test-sid",
		CommonName:    "disabled-user@example.com",
		CID:           "1",
		KID:           "1",
		RequiredGroup: "vpn-users",
		Status:        auth.SessionPending,
	}

	claims := albJWTClaims{}
	claims.Email = "disabled-user@example.com"
	claims.Sub = "sub-disabled-user"

	inGroup, err := srv.checkGroup(context.Background(), sess, claims)

	// On unfixed code: inGroup=true, err=nil — this assertion FAILS (expected).
	// On fixed code:   inGroup=false, err!=nil — this assertion PASSES.
	if inGroup {
		t.Errorf("BUG M10-callback CONFIRMED: checkGroup returned inGroup=true for a disabled user (Enabled=false, InGroup=true); expected false")
	}
	if err == nil {
		t.Errorf("BUG M10-callback CONFIRMED: checkGroup returned nil error for a disabled user; expected non-nil error")
	}
}

// federatedUserNotFoundException simulates AdminGetUser returning UserNotFoundException
// when called with a UUID sub — which is what happens on unfixed code for federated users.
// When called with the correct CognitoUsername ("Google_1234567890"), it returns success.
type federatedGroupChecker struct {
	calledWith []string
}

var errUserNotFound = errors.New("UserNotFoundException: User does not exist")

func (f *federatedGroupChecker) CheckUser(_ context.Context, username, _ string, _ bool) (auth.IdentityResult, error) {
	f.calledWith = append(f.calledWith, username)
	// Simulate Cognito: sub UUID fails, CognitoUsername succeeds.
	if username == "abc-uuid-1234-5678" {
		// This is what unfixed code passes — AdminGetUser rejects it for federated users.
		return auth.IdentityResult{}, errUserNotFound
	}
	// CognitoUsername "Google_1234567890" works correctly.
	return auth.IdentityResult{Exists: true, Enabled: true, InGroup: true}, nil
}

// TestBugCondition_F2_FederatedGroupCheckUsesSub demonstrates that checkGroup
// calls CheckUser with claims.Sub (UUID) instead of claims.CognitoUsername for
// federated users, causing UserNotFoundException and a "group check error".
//
// On UNFIXED code: CheckUser is called with the sub UUID → UserNotFoundException
//
//	→ checkGroup returns error — test FAILS (expected outcome).
//
// On FIXED code:   CheckUser is called with CognitoUsername "Google_1234567890"
//
//	→ success, inGroup=true — test PASSES.
//
// Validates: Requirements 1.2, 2.2
func TestBugCondition_F2_FederatedGroupCheckUsesSub(t *testing.T) {
	cfg := config.Config{
		AWSRegion: "eu-west-1",
	}
	sessions := auth.NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	m := &fakeMetrics{}
	checker := &federatedGroupChecker{}

	srv, err := NewServer(sessions, signer, sink, nil, cfg, m, checker, func() bool { return true })
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sess := &auth.PendingSession{
		SessionID:     "fed-sid",
		CommonName:    "user@corp.com",
		CID:           "1",
		KID:           "1",
		RequiredGroup: "vpn-users",
		Status:        auth.SessionPending,
	}

	// Federated user: sub is a UUID, CognitoUsername is "Google_1234567890".
	// ALBClaims.CognitoUsername is not yet a field on unfixed code — the test
	// exercises the bug by showing that checkGroup uses claims.Sub.
	claims := albJWTClaims{}
	claims.Sub = "abc-uuid-1234-5678"
	claims.Email = "user@corp.com"
	// CognitoUsername field does not exist yet on ALBClaims (unfixed code).
	// The fix will add it and use it in checkGroup.

	inGroup, err := srv.checkGroup(context.Background(), sess, claims)

	// On unfixed code: CheckUser is called with "abc-uuid-1234-5678" (sub),
	// which returns UserNotFoundException → err != nil, inGroup=false.
	// The test FAILS here because we assert no error and inGroup=true.
	//
	// On fixed code: CheckUser is called with "Google_1234567890" (CognitoUsername)
	// → success, inGroup=true, err=nil → test PASSES.
	if err != nil {
		t.Errorf("BUG F2 CONFIRMED: checkGroup returned error for active federated user: %v", err)
		t.Logf("  CheckUser was called with: %v", checker.calledWith)
		t.Logf("  Expected call with CognitoUsername='Google_1234567890', got sub='abc-uuid-1234-5678'")
	}
	if !inGroup {
		t.Errorf("BUG F2 CONFIRMED: checkGroup returned inGroup=false for active federated user in required group")
	}
	// Verify the lookup key used — on fixed code it must be CognitoUsername, not Sub.
	if len(checker.calledWith) > 0 && checker.calledWith[0] == "abc-uuid-1234-5678" {
		t.Errorf("BUG F2 CONFIRMED: CheckUser called with sub UUID %q instead of CognitoUsername", checker.calledWith[0])
	}
}
