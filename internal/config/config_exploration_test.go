package config

// BugConditionExploration: M11 and L7
//
// This file contains bug condition exploration tests that are EXPECTED TO FAIL
// on unfixed code. The failures confirm the bugs exist.
//
// M11 Bug: getBool silently swallows invalid env var values.
//   When an env var is set to an unrecognised value like "maybe", getBool returns
//   the fallback without collecting any error, unlike getDurationOrCollect and
//   getIntOrCollect which surface parse errors.
//   Counterexample found on unfixed code:
//     BUG M11 CONFIRMED: getBool returned fallback for unrecognised value "maybe"
//     without collecting an error; expected a descriptive error (consistent with
//     getDurationOrCollect/getIntOrCollect)
//
// L7 Bug: CallbackPort has no range validation.
//   config.Validate() does not check that CallbackPort is in [1, 65535].
//   Values like 0 or 99999 are accepted silently and only fail later at net.Listen.
//   Counterexample found on unfixed code:
//     BUG L7 CONFIRMED: Validate() returned nil for CallbackPort=0; expected non-nil error
//     BUG L7 CONFIRMED: Validate() returned nil for CallbackPort=99999; expected non-nil error

import (
	"strings"
	"testing"
	"time"
)

// TestBugCondition_M11 demonstrates that getBool silently swallows an
// unrecognised env var value ("maybe") without collecting an error.
//
// The test calls getBool directly (same package) and verifies that the
// returned value is the fallback — which is correct — but also verifies
// that the function SHOULD have collected an error for the invalid value.
//
// Since the unfixed getBool has no errs parameter, we test the observable
// behavior: set the env var to "maybe", call getBool, and assert that the
// value "maybe" is NOT a recognised bool string. The test then asserts that
// an error SHOULD have been collected (demonstrating the missing behavior).
//
// On UNFIXED code: getBool returns fallback silently, no error path exists
//
//	→ the test fails because it asserts the invalid value should produce an error.
//
// On FIXED code:   getBoolOrCollect collects an error → test PASSES.
//
// Validates: Requirements 1.5, 2.5
func TestBugCondition_M11(t *testing.T) {
	const envKey = "VPN_AUTH_TEST_BOOL_EXPLORATION_M11"
	const invalidValue = "maybe"

	t.Setenv(envKey, invalidValue)

	// Call getBoolOrCollect with an errs slice — on fixed code this collects an error.
	var collectedErrors []string
	result := getBoolOrCollect(envKey, true, &collectedErrors)

	// The result is the fallback (true) — that part is expected.
	if result != true {
		t.Fatalf("getBoolOrCollect returned %v for %q, expected fallback true", result, invalidValue)
	}

	// The bug: getBool has no error collection mechanism.
	// We verify the bug by checking whether the value is a recognised bool string.
	// If it's not recognised, an error SHOULD have been collected.
	knownValues := []string{"1", "true", "yes", "on", "0", "false", "no", "off"}
	isKnown := false
	for _, known := range knownValues {
		if strings.ToLower(invalidValue) == known {
			isKnown = true
			break
		}
	}

	if isKnown {
		t.Fatalf("test setup error: %q is a recognised bool value, choose a different invalid value", invalidValue)
	}

	// Assert: an error SHOULD have been collected for the invalid value.
	// On unfixed code: collectedErrors is empty → test FAILS (confirms bug).
	// On fixed code:   getBoolOrCollect populates collectedErrors → test PASSES.
	if len(collectedErrors) == 0 {
		t.Errorf("BUG M11 CONFIRMED: getBoolOrCollect returned fallback for unrecognised value %q without collecting an error; expected a descriptive error (consistent with getDurationOrCollect/getIntOrCollect)", invalidValue)
	}
}

// TestBugCondition_L7_PortZero demonstrates that config.Validate() accepts
// CallbackPort=0 without returning an error.
//
// On UNFIXED code: Validate() returns nil — test FAILS (expected outcome).
// On FIXED code:   Validate() returns non-nil error — test PASSES.
//
// Validates: Requirements 1.10, 2.10
func TestBugCondition_L7_PortZero(t *testing.T) {
	cfg := baseValidConfigWithPort(0)

	err := cfg.Validate()

	// On unfixed code: err=nil — this assertion FAILS (expected).
	// On fixed code:   err!=nil — this assertion PASSES.
	if err == nil {
		t.Errorf("BUG L7 CONFIRMED: Validate() returned nil for CallbackPort=0; expected non-nil error (port 0 is not a valid TCP port)")
	}
}

// TestBugCondition_L7_PortTooHigh demonstrates that config.Validate() accepts
// CallbackPort=99999 without returning an error.
//
// On UNFIXED code: Validate() returns nil — test FAILS (expected outcome).
// On FIXED code:   Validate() returns non-nil error — test PASSES.
//
// Validates: Requirements 1.10, 2.10
func TestBugCondition_L7_PortTooHigh(t *testing.T) {
	cfg := baseValidConfigWithPort(99999)

	err := cfg.Validate()

	// On unfixed code: err=nil — this assertion FAILS (expected).
	// On fixed code:   err!=nil — this assertion PASSES.
	if err == nil {
		t.Errorf("BUG L7 CONFIRMED: Validate() returned nil for CallbackPort=99999; expected non-nil error (port 99999 exceeds valid range 1-65535)")
	}
}

// baseValidConfigWithPort returns a Config with all required fields set and a
// specific CallbackPort, used to isolate port validation from other checks.
func baseValidConfigWithPort(port int) Config {
	return Config{
		ManagementSocket:       "/run/openvpn/management.sock",
		ManagementPasswordFile: "/etc/openvpn/management-pw",
		HMACSecret:             "test-secret-key!!",
		CallbackURL:            "https://vpn-auth.example.com/callback/01/udp",
		CognitoUserPoolID:      "eu-west-1_TestPool",
		CognitoIssuerURL:       "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TestPool",
		HandWindow:             300 * time.Second,
		ReconnectMaxInterval:   5 * time.Second,
		LogFormat:              "text",
		CallbackPort:           port,
	}
}
