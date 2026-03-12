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
		IP:  "10.0.0.1:8080",
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
	if decoded.IP != payload.IP {
		t.Fatalf("IP mismatch: got %q, want %q", decoded.IP, payload.IP)
	}
}

func TestStateExpired(t *testing.T) {
	signer := secrets.NewStaticSigner("test-secret")
	payload := StatePayload{
		SID: "abc123",
		IP:  "10.0.0.1:8080",
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
		IP:  "10.0.0.1:8080",
		IAT: time.Now().Unix(),
		EXP: time.Now().Add(5 * time.Minute).Unix(),
	}

	state := EncodeState(payload, signer)
	// Tamper with the payload
	tampered := "x" + state
	_, err := DecodeState(tampered, signer)
	if err == nil {
		t.Fatal("expected error for tampered state")
	}
}
