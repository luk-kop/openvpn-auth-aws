package config

// Preservation tests for getBool and Validate — Property 2: Non-Buggy Input Behavior
//
// These tests MUST PASS on unfixed code. They document correct baseline behavior
// that must not regress after fixes are applied.
//
// Observed on unfixed code:
//   - getBool with "true", "1", "yes", "on", "false", "0", "no", "off" parses correctly
//   - config.Validate() with CallbackPort=8080 returns nil
//
// Properties tested:
//   - For all recognised bool strings (1/true/yes/on/0/false/no/off),
//     getBool parses correctly with no error.
//   - For all CallbackPort in [1, 65535], Validate() does not error on this field.
//
// Validates: Requirements 3.6, 3.7, 3.10

import (
	"testing"
)

// TestPreservation_getBool_RecognisedTrueValues verifies that getBool correctly
// parses all recognised "true" values without error.
//
// Property: for all recognised bool strings in the "true" set
// (1, true, yes, on — case-insensitive), getBool returns true.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.6
func TestPreservation_getBool_RecognisedTrueValues(t *testing.T) {
	trueValues := []string{
		"1", "true", "yes", "on",
		"TRUE", "YES", "ON",
		"True", "Yes", "On",
	}

	for _, v := range trueValues {
		v := v
		t.Run(v, func(t *testing.T) {
			const envKey = "VPN_AUTH_TEST_BOOL_PRESERVATION_TRUE"
			t.Setenv(envKey, v)

			result := getBoolOrCollect(envKey, false, &[]string{}) // fallback=false so we can detect parsing

			// Preservation: recognised "true" values must continue to parse as true.
			if !result {
				t.Errorf("Preservation FAILED: getBool(%q) returned false; expected true (recognised true value)", v)
			}
		})
	}
}

// TestPreservation_getBool_RecognisedFalseValues verifies that getBool correctly
// parses all recognised "false" values without error.
//
// Property: for all recognised bool strings in the "false" set
// (0, false, no, off — case-insensitive), getBool returns false.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.6
func TestPreservation_getBool_RecognisedFalseValues(t *testing.T) {
	falseValues := []string{
		"0", "false", "no", "off",
		"FALSE", "NO", "OFF",
		"False", "No", "Off",
	}

	for _, v := range falseValues {
		v := v
		t.Run(v, func(t *testing.T) {
			const envKey = "VPN_AUTH_TEST_BOOL_PRESERVATION_FALSE"
			t.Setenv(envKey, v)

			result := getBoolOrCollect(envKey, true, &[]string{}) // fallback=true so we can detect parsing

			// Preservation: recognised "false" values must continue to parse as false.
			if result {
				t.Errorf("Preservation FAILED: getBool(%q) returned true; expected false (recognised false value)", v)
			}
		})
	}
}

// TestPreservation_getBool_UnsetUseFallback verifies that getBool returns the
// fallback value when the env var is unset.
//
// Property: when a boolean env var is unset, getBool returns the fallback.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.7
func TestPreservation_getBool_UnsetUseFallback(t *testing.T) {
	cases := []struct {
		name     string
		fallback bool
	}{
		{"fallback_true", true},
		{"fallback_false", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			const envKey = "VPN_AUTH_TEST_BOOL_PRESERVATION_UNSET"
			// Ensure the env var is not set.
			t.Setenv(envKey, "")

			result := getBoolOrCollect(envKey, tc.fallback, &[]string{})

			// Preservation: unset env vars must continue to use the fallback.
			if result != tc.fallback {
				t.Errorf("Preservation FAILED: getBool with unset env var returned %v; expected fallback %v", result, tc.fallback)
			}
		})
	}
}

// TestPreservation_Validate_ValidCallbackPort verifies that Validate() accepts
// all valid CallbackPort values in [1, 65535] without error.
//
// Property: for all CallbackPort in [1, 65535], Validate() does not error on this field.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.10
func TestPreservation_Validate_ValidCallbackPort(t *testing.T) {
	validPorts := []int{
		1,     // minimum valid port
		80,    // HTTP
		443,   // HTTPS
		1024,  // first non-privileged port
		8080,  // common dev port
		8443,  // common HTTPS dev port
		9090,  // another common port
		65535, // maximum valid port
	}

	for _, port := range validPorts {
		port := port
		t.Run("port_"+itoa(port), func(t *testing.T) {
			cfg := baseValidConfigWithPort(port)

			err := cfg.Validate()

			// Preservation: valid ports must continue to be accepted without error.
			if err != nil {
				t.Errorf("Preservation FAILED: Validate() returned error for valid CallbackPort=%d; expected nil, got: %v", port, err)
			}
		})
	}
}

// TestPreservation_Validate_ValidCallbackPort_Range verifies the property holds
// across a wider range of valid ports using a table-driven approach.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.10
func TestPreservation_Validate_ValidCallbackPort_Range(t *testing.T) {
	// Sample ports across the valid range to simulate property-based testing.
	samplePorts := []int{
		1, 2, 100, 1000, 1024, 2000, 3000, 4000, 5000,
		6000, 7000, 8000, 8080, 9000, 10000, 20000,
		30000, 40000, 50000, 60000, 65000, 65534, 65535,
	}

	for _, port := range samplePorts {
		port := port
		t.Run("port_"+itoa(port), func(t *testing.T) {
			cfg := baseValidConfigWithPort(port)

			err := cfg.Validate()

			// Preservation: valid ports must continue to be accepted without error.
			if err != nil {
				t.Errorf("Preservation FAILED: Validate() returned error for valid CallbackPort=%d; expected nil, got: %v", port, err)
			}
		})
	}
}

// itoa converts an int to a string for use in test names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
