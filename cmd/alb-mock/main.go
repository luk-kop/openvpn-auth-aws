// alb-mock simulates ALB + Cognito authenticate action for local development.
// It builds an unsigned x-amzn-oidc-data JWT with configurable test identity
// and forwards all requests to the daemon's callback port — just like a real
// ALB, which does not inspect or validate the application state parameter.
//
// Usage (via docker compose or standalone):
//
//	MOCK_EMAIL=test@example.com
//	MOCK_SUB=test-sub-123
//	MOCK_GROUPS=vpn-users
//	DAEMON_ADDR=localhost:8080
//	LISTEN_ADDR=:8080
package main

import (
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
	daemonAddr := mustEnv("DAEMON_ADDR")
	mockEmail := getenv("MOCK_EMAIL", "test@example.com")
	mockSub := getenv("MOCK_SUB", "test-sub-123")
	mockGroups := getenv("MOCK_GROUPS", "")
	listenAddr := getenv("LISTEN_ADDR", ":8080")

	cfg := &mockConfig{
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
	daemonAddr string
	email      string
	sub        string
	groups     []string
}

func handleCallback(cfg *mockConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stateBlob := r.URL.Query().Get("state")

		// Build unsigned x-amzn-oidc-data JWT.
		oidcData, err := buildUnsignedJWT(cfg.email, cfg.sub, cfg.groups)
		if err != nil {
			slog.Error("alb-mock: build JWT failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Forward GET to daemon with oidc headers.
		// State validation (HMAC, expiry) is the daemon's responsibility,
		// just like a real ALB forwards all requests without inspecting state.
		path := r.PathValue("path")
		query := "state=" + stateBlob
		if stateBlob == "" {
			query = ""
		}
		daemonURL := fmt.Sprintf("http://%s/callback/%s", cfg.daemonAddr, path)
		if query != "" {
			daemonURL += "?" + query
		}

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
	claims := map[string]any{
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
