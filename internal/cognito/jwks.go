package cognito

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

type JWKSCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	jwksURL   string
	issuerURL string
}

func NewJWKSCache(issuerURL string) *JWKSCache {
	return &JWKSCache{
		keys:      make(map[string]*rsa.PublicKey),
		jwksURL:   strings.TrimRight(issuerURL, "/") + "/.well-known/jwks.json",
		issuerURL: issuerURL,
	}
}

func (c *JWKSCache) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return key, nil
	}

	// Refresh from JWKS endpoint
	if err := c.refresh(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}
	return key, nil
}

func (c *JWKSCache) refresh() error {
	resp, err := http.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read JWKS: %w", err)
	}

	var jwks struct {
		Keys []struct {
			KID string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("unmarshal JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAKey(k.N, k.E)
		if err != nil {
			continue
		}
		newKeys[k.KID] = pub
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = newKeys
	return nil
}

func parseRSAKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// IDTokenClaims holds parsed claims from a Cognito ID token.
// Retained for JWKS validation; TokenExchanger removed in v2.
type IDTokenClaims struct {
	Email  string
	Nonce  string
	Groups []string
}

func (c *JWKSCache) ValidateIDToken(tokenString, issuer, audience string) (*IDTokenClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
	)

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		return c.getKey(kid)
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	result := &IDTokenClaims{}
	if email, ok := claims["email"].(string); ok {
		result.Email = email
	}
	if nonce, ok := claims["nonce"].(string); ok {
		result.Nonce = nonce
	}
	if groups, ok := claims["cognito:groups"].([]any); ok {
		for _, g := range groups {
			if gs, ok := g.(string); ok {
				result.Groups = append(result.Groups, gs)
			}
		}
	}

	return result, nil
}
