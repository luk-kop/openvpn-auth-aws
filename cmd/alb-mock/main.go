// alb-mock simulates ALB + Cognito authenticate action for local development.
// It verifies the HMAC state blob, builds an unsigned x-amzn-oidc-data JWT
// with configurable test identity, and forwards the request to the daemon's
// callback port.
//
// Usage (via docker compose or standalone):
//
//	VPN_AUTH_HMAC_SECRET=test-secret
//	MOCK_EMAIL=test@example.com
//	MOCK_SUB=test-sub-123
//	MOCK_GROUPS=vpn-users
//	DAEMON_ADDR=localhost:8080
//	LISTEN_ADDR=:8080
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	hmacSecret := mustEnv("VPN_AUTH_HMAC_SECRET")
	daemonAddr := mustEnv("DAEMON_ADDR")
	mockEmail := getenv("MOCK_EMAIL", "test@example.com")
	mockSub := getenv("MOCK_SUB", "test-sub-123")
	mockGroups := getenv("MOCK_GROUPS", "")
	listenAddr := getenv("LISTEN_ADDR", ":8080")

	cfg := &mockConfig{
		hmacSecret: hmacSecret,
		daemonAddr: daemonAddr,
		email:      mockEmail,
		sub:        mockSub,
		groups:     splitGroups(mockGroups),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /callback/{path...}", handleCallback(cfg))

	slog.Info("alb-mock listening", "addr", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

type mockConfig struct {
	hmacSecret string
	daemonAddr string
	email      string
	sub        string
	groups     []string
}

func handleCallback(cfg *mockConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stateBlob := r.URL.Query().Get("state")
		if stateBlob == "" {
			http.Error(w, "missing state", http.StatusBadRequest)
			return
		}

		// Verify HMAC on state blob (format: base64payload.mac).
		if !verifyStateHMAC(cfg.hmacSecret, stateBlob) {
			slog.Warn("alb-mock: invalid state HMAC")
			http.Error(w, "invalid state signature", http.StatusForbidden)
			return
		}

		// Build unsigned x-amzn-oidc-data JWT.
		oidcData, err := buildUnsignedJWT(cfg.email, cfg.sub, cfg.groups)
		if err != nil {
			slog.Error("alb-mock: build JWT failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Forward GET to daemon with oidc headers.
		path := r.PathValue("path")
		daemonURL := fmt.Sprintf("http://%s/callback/%s?state=%s",
			cfg.daemonAddr, path, stateBlob)

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, daemonURL, nil)
		if err != nil {
			slog.Error("alb-mock: build daemon request failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		req.Header.Set("x-amzn-oidc-data", oidcData)
		req.Header.Set("x-amzn-oidc-identity", cfg.sub)
		req.Header.Set("x-amzn-oidc-accesstoken", "mock-access-token")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Error("alb-mock: daemon request failed", "error", err)
			http.Error(w, "daemon unreachable", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		slog.Info("alb-mock: forwarded to daemon", "status", resp.StatusCode, "path", path)

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}
}

// verifyStateHMAC checks the HMAC signature on a state blob (format: base64payload.mac).
func verifyStateHMAC(secret, stateBlob string) bool {
	parts := strings.SplitN(stateBlob, ".", 2)
	if len(parts) != 2 {
		return false
	}
	encoded, mac := parts[0], parts[1]
	expected := signHMAC(secret, encoded)
	return hmac.Equal([]byte(expected), []byte(mac))
}

// signHMAC computes HMAC-SHA256 of data using secret, returning base64url encoding.
func signHMAC(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// buildUnsignedJWT constructs an unsigned JWT (header.claims.) with the given identity.
// The daemon in dev mode (no --alb-arn) skips signature verification.
func buildUnsignedJWT(email, sub string, groups []string) (string, error) {
	header := map[string]string{
		"alg": "none",
		"typ": "JWT",
		"kid": "mock-kid",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	now := time.Now().Unix()
	claims := map[string]interface{}{
		"sub":            sub,
		"email":          email,
		"exp":            now + 3600,
		"iss":            "mock-issuer",
		"cognito:groups": groups,
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	c := base64.RawURLEncoding.EncodeToString(claimsJSON)
	// Unsigned JWT: header.claims. (empty signature)
	return h + "." + c + ".", nil
}

// splitGroups splits a comma-separated groups string into a slice.
func splitGroups(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
