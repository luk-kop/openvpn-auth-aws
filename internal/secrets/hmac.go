package secrets

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// StaticSigner signs and verifies HMAC-SHA256 MACs using a static secret.
type StaticSigner struct {
	secret []byte
}

func NewStaticSigner(secret string) *StaticSigner {
	return &StaticSigner{secret: []byte(secret)}
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
