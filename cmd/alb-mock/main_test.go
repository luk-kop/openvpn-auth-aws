package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// buildValidState creates a valid HMAC-signed state blob for testing.
func buildValidState(t *testing.T, secret string) string {
	t.Helper()
	payload := map[string]any{
		"sid": "test-session-id",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	data, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig
}

func TestHandleCallback_InvalidHMAC_ForwardsToDaemon(t *testing.T) {
	// With the ALB-like behavior, alb-mock forwards all requests to daemon
	// regardless of HMAC validity. The daemon is responsible for validation.
	daemonCalled := false
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		daemonCalled = true
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<html><body>Session Error</body></html>"))
	}))
	defer daemon.Close()

	cfg := &mockConfig{
		daemonAddr: strings.TrimPrefix(daemon.URL, "http://"),
		email:      "test@example.com",
		sub:        "test-sub",
		groups:     []string{"vpn-users"},
	}

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state=invalid.signature", nil)
	req.SetPathValue("path", "01/udp")
	w := httptest.NewRecorder()

	handleCallback(cfg)(w, req)

	if !daemonCalled {
		t.Error("daemon should be called — alb-mock forwards all requests like a real ALB")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (daemon error response), got %d", w.Code)
	}
}

func TestHandleCallback_MissingState_ForwardsToDaemon(t *testing.T) {
	daemonCalled := false
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		daemonCalled = true
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<html><body>Session Error</body></html>"))
	}))
	defer daemon.Close()

	cfg := &mockConfig{
		daemonAddr: strings.TrimPrefix(daemon.URL, "http://"),
		email:      "test@example.com",
		sub:        "test-sub",
		groups:     []string{},
	}

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp", nil)
	req.SetPathValue("path", "01/udp")
	w := httptest.NewRecorder()

	handleCallback(cfg)(w, req)

	if !daemonCalled {
		t.Error("daemon should be called — alb-mock forwards all requests like a real ALB")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (daemon error response), got %d", w.Code)
	}
}

func TestHandleCallback_ValidState_ForwardsOIDCHeaders(t *testing.T) {
	secret := "test-secret"
	stateBlob := buildValidState(t, secret)

	var capturedOIDCData, capturedOIDCIdentity, capturedOIDCToken string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedOIDCData = r.Header.Get("x-amzn-oidc-data")
		capturedOIDCIdentity = r.Header.Get("x-amzn-oidc-identity")
		capturedOIDCToken = r.Header.Get("x-amzn-oidc-accesstoken")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authenticated"))
	}))
	defer daemon.Close()

	cfg := &mockConfig{
		daemonAddr: strings.TrimPrefix(daemon.URL, "http://"),
		email:      "user@example.com",
		sub:        "sub-abc",
		groups:     []string{"vpn-users"},
	}

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+stateBlob, nil)
	req.SetPathValue("path", "01/udp")
	w := httptest.NewRecorder()

	handleCallback(cfg)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedOIDCData == "" {
		t.Error("x-amzn-oidc-data header not forwarded to daemon")
	}
	if capturedOIDCIdentity != "sub-abc" {
		t.Errorf("x-amzn-oidc-identity = %q, want %q", capturedOIDCIdentity, "sub-abc")
	}
	if capturedOIDCToken != "mock-access-token" {
		t.Errorf("x-amzn-oidc-accesstoken = %q, want %q", capturedOIDCToken, "mock-access-token")
	}

	// Verify the JWT contains the expected email and sub.
	parts := strings.Split(capturedOIDCData, ".")
	if len(parts) != 3 {
		t.Fatalf("oidc-data JWT has %d parts, want 3", len(parts))
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	if claims["email"] != "user@example.com" {
		t.Errorf("JWT email = %v, want user@example.com", claims["email"])
	}
	if claims["sub"] != "sub-abc" {
		t.Errorf("JWT sub = %v, want sub-abc", claims["sub"])
	}
}

func TestHandleCallback_DaemonResponsePassedThrough(t *testing.T) {
	secret := "test-secret"
	stateBlob := buildValidState(t, secret)

	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("not in required group"))
	}))
	defer daemon.Close()

	cfg := &mockConfig{
		daemonAddr: strings.TrimPrefix(daemon.URL, "http://"),
		email:      "user@example.com",
		sub:        "sub-abc",
		groups:     []string{},
	}

	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp?state="+stateBlob, nil)
	req.SetPathValue("path", "01/udp")
	w := httptest.NewRecorder()

	handleCallback(cfg)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 from daemon passthrough, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not in required group") {
		t.Errorf("expected daemon body in response, got: %s", w.Body.String())
	}
}

func TestBuildUnsignedJWT(t *testing.T) {
	groups := []string{"vpn-users", "admins"}
	token, err := buildUnsignedJWT("user@example.com", "sub-123", groups)
	if err != nil {
		t.Fatalf("buildUnsignedJWT: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	// Unsigned JWT has empty signature.
	if parts[2] != "" {
		t.Errorf("expected empty signature, got %q", parts[2])
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	if claims["email"] != "user@example.com" {
		t.Errorf("email = %v, want user@example.com", claims["email"])
	}
	if claims["sub"] != "sub-123" {
		t.Errorf("sub = %v, want sub-123", claims["sub"])
	}
	rawGroups, ok := claims["cognito:groups"].([]any)
	if !ok || len(rawGroups) != 2 {
		t.Errorf("cognito:groups = %v, want 2 entries", claims["cognito:groups"])
	}
}

func TestSplitGroups(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", []string{}},
		{"vpn-users", []string{"vpn-users"}},
		{"vpn-users,admins", []string{"vpn-users", "admins"}},
		{"vpn-users, admins", []string{"vpn-users", "admins"}},
	}
	for _, tc := range tests {
		got := splitGroups(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitGroups(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitGroups(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}
