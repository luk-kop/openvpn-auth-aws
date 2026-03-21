package secrets

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// MinSecretLen is the minimum accepted length for a user-provided HMAC secret.
const MinSecretLen = 16

// StaticSigner signs and verifies HMAC-SHA256 MACs using a static secret.
type StaticSigner struct {
	secret []byte
}

func NewStaticSigner(secret string) (*StaticSigner, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("hmac secret must be at least %d bytes, got %d", MinSecretLen, len(secret))
	}
	return &StaticSigner{secret: []byte(secret)}, nil
}

// NewRandomSigner creates a StaticSigner with a cryptographically random 32-byte key.
func NewRandomSigner() *StaticSigner {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return &StaticSigner{secret: key}
}

func (s *StaticSigner) Sign(data string) string {
	sum := hmac.New(sha256.New, s.secret)
	sum.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))
}

func (s *StaticSigner) Verify(data, mac string) bool {
	expected := s.Sign(data)
	return hmac.Equal([]byte(expected), []byte(mac))
}
