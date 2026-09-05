package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"openvpn-auth-aws/internal/secrets"
)

func FuzzDecodeState(f *testing.F) {
	signer, err := secrets.NewStaticSigner("fuzz-test-secret!!")
	if err != nil {
		f.Fatalf("NewStaticSigner: %v", err)
	}

	validPayload := []byte(`{"sid":"session-1","iat":1,"exp":9999999999}`)
	validEncoded := base64.RawURLEncoding.EncodeToString(validPayload)
	validState := validEncoded + "." + signer.Sign(validEncoded)

	f.Add([]byte(validState), validPayload)
	f.Add([]byte("not-a-state"), []byte(`{"sid":"unicode-é","exp":9999999999}`))
	f.Add([]byte("."), []byte("not-json"))
	f.Add([]byte{0xff, 0x00, '.'}, []byte{})

	f.Fuzz(func(t *testing.T, rawState, signedPayload []byte) {
		// Arbitrary untrusted state must always be rejected or decoded without
		// panicking.
		_, _ = DecodeState(string(rawState), signer)

		// Re-sign every mutated payload so fuzzing reaches base64/JSON parsing
		// instead of stopping at HMAC verification.
		encoded := base64.RawURLEncoding.EncodeToString(signedPayload)
		state := encoded + "." + signer.Sign(encoded)
		got, err := DecodeState(state, signer)
		if err != nil {
			return
		}

		var want StatePayload
		if err := json.Unmarshal(signedPayload, &want); err != nil {
			t.Fatalf("DecodeState accepted invalid JSON %q: %v", signedPayload, err)
		}
		if got != want {
			t.Fatalf("DecodeState() = %+v, want %+v", got, want)
		}
	})
}
