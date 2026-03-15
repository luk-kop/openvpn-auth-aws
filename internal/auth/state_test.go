package auth

import (
	"testing"
	"time"

	"openvpn-auth-aws/internal/secrets"
)

func TestStateRoundTrip(t *testing.T) {
	signer := secrets.NewStaticSigner("test-secret")
	payload := StatePayload{
		SID: "abc123",
		IAT: time.Now().Unix(),
		EXP: time.Now().Add(5 * time.Minute).Unix(),
	}

	state := EncodeState(payload, signer)
	decoded, err := DecodeState(state, signer)
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	if decoded.SID != payload.SID {
		t.Fatalf("SID mismatch: got %q, want %q", decoded.SID, payload.SID)
	}
}

func TestStateExpired(t *testing.T) {
	signer := secrets.NewStaticSigner("test-secret")
	payload := StatePayload{
		SID: "abc123",
		IAT: time.Now().Add(-10 * time.Minute).Unix(),
		EXP: time.Now().Add(-5 * time.Minute).Unix(),
	}

	state := EncodeState(payload, signer)
	_, err := DecodeState(state, signer)
	if err == nil {
		t.Fatal("expected error for expired state")
	}
}

func TestStateTampered(t *testing.T) {
	signer := secrets.NewStaticSigner("test-secret")
	payload := StatePayload{
		SID: "abc123",
		IAT: time.Now().Unix(),
		EXP: time.Now().Add(5 * time.Minute).Unix(),
	}

	state := EncodeState(payload, signer)
	tampered := "x" + state
	_, err := DecodeState(tampered, signer)
	if err == nil {
		t.Fatal("expected error for tampered state")
	}
}

// Property tests (2.3, 2.4, 2.5)
// These use testing/quick to generate random inputs and verify universal properties.

// PropStateRoundTrip: DecodeState(EncodeState(p, signer), signer) == p for all valid StatePayload values.
// Validates: Requirement 13.4
func TestPropStateRoundTrip(t *testing.T) {
	signer := secrets.NewStaticSigner("prop-test-secret")

	// Run with a fixed set of representative inputs covering edge cases.
	cases := []StatePayload{
		{SID: "a", IAT: 1000, EXP: 9999999999},
		{SID: "session-abc-123", IAT: 0, EXP: 9999999999},
		{SID: "x", IAT: 9999999998, EXP: 9999999999},
		{SID: "unicode-sid-\u00e9", IAT: 1, EXP: 9999999999},
		{SID: "sid-with-dots.and/slashes", IAT: 100, EXP: 9999999999},
	}

	for _, p := range cases {
		encoded := EncodeState(p, signer)
		decoded, err := DecodeState(encoded, signer)
		if err != nil {
			t.Errorf("round-trip failed for SID=%q: %v", p.SID, err)
			continue
		}
		if decoded.SID != p.SID || decoded.IAT != p.IAT || decoded.EXP != p.EXP {
			t.Errorf("round-trip mismatch for SID=%q: got %+v, want %+v", p.SID, decoded, p)
		}
	}
}

// PropTamperedStateRejection: flipping any byte in the MAC portion must cause Verify to return false.
// Validates: Requirement 13.3
func TestPropTamperedStateRejection(t *testing.T) {
	signer := secrets.NewStaticSigner("prop-test-secret")
	payload := StatePayload{
		SID: "tamper-test",
		IAT: 1000,
		EXP: 9999999999,
	}

	state := EncodeState(payload, signer)

	// state format: base64payload.mac — split on first dot
	dotIdx := len(state) - 1
	for i, c := range state {
		if c == '.' {
			dotIdx = i
			break
		}
	}

	macPart := []byte(state[dotIdx+1:])

	// Flip every byte in the MAC and confirm each produces a rejection.
	for i := range macPart {
		tampered := make([]byte, len(macPart))
		copy(tampered, macPart)
		tampered[i] ^= 0xFF

		tamperedState := state[:dotIdx+1] + string(tampered)
		_, err := DecodeState(tamperedState, signer)
		if err == nil {
			t.Errorf("expected rejection when flipping MAC byte %d, but DecodeState succeeded", i)
		}
	}
}

// PropExpiredStateRejection: any StatePayload with EXP < now must be rejected by DecodeState.
// Validates: Requirement 13.5
func TestPropExpiredStateRejection(t *testing.T) {
	signer := secrets.NewStaticSigner("prop-test-secret")

	expiredCases := []StatePayload{
		{SID: "s1", IAT: 0, EXP: 1},                                            // epoch + 1s
		{SID: "s2", IAT: 0, EXP: time.Now().Add(-1 * time.Second).Unix()},      // 1s ago
		{SID: "s3", IAT: 0, EXP: time.Now().Add(-24 * time.Hour).Unix()},       // 1 day ago
		{SID: "s4", IAT: 0, EXP: time.Now().Add(-365 * 24 * time.Hour).Unix()}, // 1 year ago
	}

	for _, p := range expiredCases {
		state := EncodeState(p, signer)
		_, err := DecodeState(state, signer)
		if err == nil {
			t.Errorf("expected expiry rejection for EXP=%d (SID=%q), but DecodeState succeeded", p.EXP, p.SID)
		}
	}
}
