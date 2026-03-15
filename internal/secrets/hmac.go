package secrets

import (
	"crypto/hmac"
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

func (s *StaticSigner) Sign(data string) string {
	sum := hmac.New(sha256.New, s.secret)
	sum.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))
}

func (s *StaticSigner) Verify(data, mac string) bool {
	expected := s.Sign(data)
	return hmac.Equal([]byte(expected), []byte(mac))
}
