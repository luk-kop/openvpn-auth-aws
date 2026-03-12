package cognito

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestExchangeHappyPath(t *testing.T) {
	// Generate RSA key pair for signing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	kid := "test-kid-1"

	// Create JWKS endpoint
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"n":   base64urlEncodeBigInt(privKey.N),
				"e":   base64urlEncodeBigInt(big.NewInt(int64(privKey.E))),
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	// Create a signed JWT
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            jwksServer.URL,
		"aud":            "test-client-id",
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"email":          "user@example.com",
		"nonce":          "test-nonce",
		"cognito:groups": []string{"vpn-users"},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	// Create token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("wrong content type: %s", r.Header.Get("Content-Type"))
		}
		resp := map[string]string{"id_token": signedToken}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	exchanger := NewExchanger(tokenServer.URL, "test-client-id", jwksServer.URL)
	result, err := exchanger.Exchange(context.Background(), "auth-code", "code-verifier", "https://example.com/callback")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if result.Email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", result.Email)
	}
	if result.Nonce != "test-nonce" {
		t.Errorf("nonce = %q, want test-nonce", result.Nonce)
	}
	if len(result.Groups) != 1 || result.Groups[0] != "vpn-users" {
		t.Errorf("groups = %v, want [vpn-users]", result.Groups)
	}
}

func TestExchangeTokenEndpointError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	exchanger := NewExchanger(tokenServer.URL, "test-client-id", "https://example.com")
	_, err := exchanger.Exchange(context.Background(), "auth-code", "code-verifier", "https://example.com/callback")
	if err == nil {
		t.Fatal("expected error for bad token response")
	}
}

func base64urlEncodeBigInt(n *big.Int) string {
	b := n.Bytes()
	return jwtBase64Encode(b)
}

func jwtBase64Encode(b []byte) string {
	const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(b)*8+5)/6)
	var val uint
	var bits int
	for _, byt := range b {
		val = val<<8 | uint(byt)
		bits += 8
		for bits >= 6 {
			bits -= 6
			result = append(result, encodeURL[(val>>bits)&0x3f])
		}
	}
	if bits > 0 {
		result = append(result, encodeURL[(val<<(6-bits))&0x3f])
	}
	return string(result)
}
