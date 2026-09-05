package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

func TestMain(m *testing.M) {
	// Set required env vars before init() runs — but init() already ran
	// when this package was loaded. We re-initialize globals for tests.
	os.Setenv("VPC_CIDR", "10.0.0.0/16")           //nolint:errcheck // test setup
	os.Setenv("DAEMON_PORT_UDP", "8080")           //nolint:errcheck // test setup
	os.Setenv("DAEMON_PORT_TCP", "8081")           //nolint:errcheck // test setup
	os.Setenv("UPSTREAM_TIMEOUT", "2s")            //nolint:errcheck // test setup
	os.Setenv("UPSTREAM_CONNECT_TIMEOUT", "100ms") //nolint:errcheck // test setup

	_, parsed, _ := net.ParseCIDR("10.0.0.0/16")
	vpcCIDR = parsed
	portMap = map[string]string{"udp": "8080", "tcp": "8081"}
	httpClient = newHTTPClient(2*time.Second, 100*time.Millisecond)
	oidcHeaders, _ = parseOIDCHeaders(defaultOIDCHeadersJSON)

	os.Exit(m.Run())
}

// --- parsePath tests ---

func TestParsePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantIP    string
		wantProto string
		wantErr   bool
	}{
		{"valid udp", "/callback/10.0.1.42/udp", "10.0.1.42", "udp", false},
		{"valid tcp", "/callback/10.0.2.100/tcp", "10.0.2.100", "tcp", false},
		{"valid edge IP", "/callback/255.255.255.255/udp", "255.255.255.255", "udp", false},
		{"valid min IP", "/callback/0.0.0.0/tcp", "0.0.0.0", "tcp", false},
		{"invalid IP octets", "/callback/999.999.999.999/udp", "", "", true},
		{"missing proto", "/callback/10.0.1.42", "", "", true},
		{"extra segments", "/callback/10.0.1.42/udp/extra", "", "", true},
		{"empty path", "", "", "", true},
		{"root path", "/", "", "", true},
		{"no callback prefix", "/other/10.0.1.42/udp", "", "", true},
		{"ipv6 in path", "/callback/::1/udp", "", "", true},
		{"invalid proto", "/callback/10.0.1.42/http", "", "", true},
		{"trailing slash", "/callback/10.0.1.42/udp/", "", "", true},
		{"uppercase proto", "/callback/10.0.1.42/UDP", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, proto, err := parsePath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ip=%v proto=%q", ip, proto)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ip.String() != tt.wantIP {
				t.Errorf("IP = %q, want %q", ip.String(), tt.wantIP)
			}
			if proto != tt.wantProto {
				t.Errorf("proto = %q, want %q", proto, tt.wantProto)
			}
		})
	}
}

// --- validateIP tests ---

func TestValidateIP(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/16")

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"in CIDR", "10.0.1.42", false},
		{"in CIDR boundary low", "10.0.0.1", false},
		{"in CIDR boundary high", "10.0.255.254", false},
		{"network address", "10.0.0.0", false}, // net.Contains returns true for network addr
		{"broadcast", "10.0.255.255", false},   // net.Contains returns true for broadcast
		{"outside CIDR", "192.168.1.1", true},
		{"outside CIDR loopback", "127.0.0.1", true},
		{"ipv6 rejected", "::1", true},
		{"ipv6 full rejected", "2001:db8::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse test IP: %s", tt.ip)
			}
			err := validateIP(ip, cidr)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- errorPage tests ---

func TestErrorPage(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		title      string
		message    string
	}{
		{"400 bad request", 400, "Bad Request", "Invalid callback path."},
		{"403 forbidden", 403, "Forbidden", "Invalid target."},
		{"503 service unavailable", 503, "Service Unavailable",
			"VPN server is temporarily unavailable. Please try reconnecting."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := errorPage(tt.statusCode, tt.title, tt.message, "")

			if resp.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.statusCode)
			}
			if ct := resp.Headers["content-type"]; ct != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
			}
			if got := resp.Headers["cache-control"]; got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := resp.Headers["pragma"]; got != "no-cache" {
				t.Errorf("Pragma = %q, want no-cache", got)
			}
			if !strings.Contains(resp.Body, tt.title) {
				t.Error("body does not contain title")
			}
			if !strings.Contains(resp.Body, tt.message) {
				t.Error("body does not contain message")
			}
			if !strings.Contains(resp.Body, "<!DOCTYPE html>") {
				t.Error("body is not valid HTML")
			}
		})
	}
}

func TestErrorPage503NoInfoLeak(t *testing.T) {
	resp := errorPage(503, "Service Unavailable",
		"VPN connection is no longer available. Do not refresh this page. Disconnect the VPN client, connect again, and complete authentication using the new link.",
		"a1b2c3d4e5f6")

	if !strings.Contains(resp.Body, "Reference a1b2c3d4e5f6") {
		t.Error("503 page does not contain callback reference ID")
	}

	leaks := []string{
		"10.0.", "192.168.", "172.16.",
		":8080", ":8081",
		"/16", "/24", "/8",
		"CIDR",
	}
	for _, leak := range leaks {
		if strings.Contains(resp.Body, leak) {
			t.Errorf("503 page leaks infrastructure detail: %q", leak)
		}
	}
}

func TestWithConnectTimeout(t *testing.T) {
	dial := withConnectTimeout(20*time.Millisecond, func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	started := time.Now()
	_, err := dial(context.Background(), "tcp", "example.invalid:443")
	if err == nil {
		t.Fatal("expected connect timeout")
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("connect timeout took %s, want less than 200ms", elapsed)
	}
	if got := classifyUpstreamError(err); got != "connect_timeout" {
		t.Errorf("reason = %q, want connect_timeout", got)
	}
}

func TestClassifyUpstreamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"connection refused", &upstreamConnectError{err: syscall.ECONNREFUSED}, "connection_refused"},
		{"connect network error", &upstreamConnectError{err: errors.New("no route")}, "network_error"},
		{"request deadline", context.DeadlineExceeded, "request_timeout"},
		{"other request error", errors.New("broken response"), "network_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyUpstreamError(tt.err); got != tt.want {
				t.Errorf("classifyUpstreamError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewReferenceID(t *testing.T) {
	got := newReferenceID()
	if len(got) != 12 {
		t.Fatalf("reference ID length = %d, want 12: %q", len(got), got)
	}
	for _, r := range got {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("reference ID is not lowercase hex: %q", got)
		}
	}
}

func TestParseOIDCHeaders(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{
			name: "safe default",
			raw:  defaultOIDCHeadersJSON,
			want: []string{"x-amzn-oidc-data"},
		},
		{
			name: "legacy diagnostic opt-in",
			raw:  `["x-amzn-oidc-data","x-amzn-oidc-accesstoken","x-amzn-oidc-identity"]`,
			want: []string{"x-amzn-oidc-data", "x-amzn-oidc-accesstoken", "x-amzn-oidc-identity"},
		},
		{
			name: "case normalized",
			raw:  `["X-Amzn-Oidc-Data"]`,
			want: []string{"x-amzn-oidc-data"},
		},
		{name: "invalid JSON", raw: `x-amzn-oidc-data`, wantErr: true},
		{name: "missing required data header", raw: `["x-amzn-oidc-identity"]`, wantErr: true},
		{name: "unsupported header", raw: `["x-amzn-oidc-data","authorization"]`, wantErr: true},
		{name: "duplicate header", raw: `["x-amzn-oidc-data","X-Amzn-Oidc-Data"]`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOIDCHeaders(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseOIDCHeaders(%q) returned no error", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOIDCHeaders(%q): %v", tt.raw, err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("parseOIDCHeaders(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// --- handler tests (with httptest mock upstream) ---

func TestHandlerValidCallbackUDP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the signed claims header is forwarded by default.
		if r.Header.Get("x-amzn-oidc-data") != "jwt-token" {
			t.Error("missing x-amzn-oidc-data header")
		}
		if r.Header.Get("x-amzn-oidc-accesstoken") != "" {
			t.Error("x-amzn-oidc-accesstoken should not be forwarded by default")
		}
		if r.Header.Get("x-amzn-oidc-identity") != "" {
			t.Error("x-amzn-oidc-identity should not be forwarded by default")
		}
		// Verify state param
		if r.URL.Query().Get("state") != "abc123" {
			t.Errorf("state = %q, want %q", r.URL.Query().Get("state"), "abc123")
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		fmt.Fprint(w, "<html>success</html>") //nolint:errcheck // test handler
	}))
	defer upstream.Close()

	// Extract host:port from test server to set as port map
	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	// Set VPC CIDR to include 127.0.0.1
	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/udp", host),
		QueryStringParameters: map[string]string{"state": "abc123"},
		Headers: map[string]string{
			"x-amzn-oidc-data":        "jwt-token",
			"x-amzn-oidc-accesstoken": "access-token",
			"x-amzn-oidc-identity":    "user@example.com",
		},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "success") {
		t.Error("body does not contain upstream response")
	}
}

func TestHandlerValidCallbackTCP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok-tcp") //nolint:errcheck // test handler
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/tcp", host),
		QueryStringParameters: map[string]string{"state": "xyz"},
		Headers:               map[string]string{},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestHandlerInvalidPath(t *testing.T) {
	req := events.ALBTargetGroupRequest{
		Path: "/not-a-callback",
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerIPOutsideVPC(t *testing.T) {
	// Default vpcCIDR is 10.0.0.0/16, so 192.168.1.1 is outside
	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("10.0.0.0/16")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	req := events.ALBTargetGroupRequest{
		Path: "/callback/192.168.1.1/udp",
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", resp.StatusCode)
	}
}

func TestHandlerUpstreamConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve unused port: %v", err)
	}
	_, unusedPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("parse unused port: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("release unused port: %v", err)
	}

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	oldPortMap := portMap
	portMap = map[string]string{"udp": unusedPort, "tcp": unusedPort}
	defer func() { portMap = oldPortMap }()

	var logOutput bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logOutput, nil)))
	defer slog.SetDefault(oldLogger)

	req := events.ALBTargetGroupRequest{
		Path:                  "/callback/127.0.0.1/udp",
		QueryStringParameters: map[string]string{"state": "secret-state-must-not-leak"},
		Headers:               map[string]string{},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 503 {
		t.Errorf("StatusCode = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "Do not refresh this page") ||
		!strings.Contains(resp.Body, "Disconnect the VPN client") {
		t.Error("503 page does not contain reconnect instructions")
	}
	if got := resp.Headers["cache-control"]; got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Headers["pragma"]; got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}

	var logEntry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logOutput.Bytes()), &logEntry); err != nil {
		t.Fatalf("parse structured log: %v; log=%q", err, logOutput.String())
	}
	if got := logEntry["event"]; got != "callback_upstream_unavailable" {
		t.Errorf("event = %v, want callback_upstream_unavailable", got)
	}
	if got := logEntry["protocol"]; got != "udp" {
		t.Errorf("protocol = %v, want udp", got)
	}
	if got := logEntry["reason"]; got != "connection_refused" {
		t.Errorf("reason = %v, want connection_refused", got)
	}
	referenceID, ok := logEntry["reference_id"].(string)
	if !ok || referenceID == "" {
		t.Fatalf("missing reference_id in log: %v", logEntry)
	}
	if !strings.Contains(resp.Body, "Reference "+referenceID) {
		t.Errorf("page and log do not share reference ID %q", referenceID)
	}
	if strings.Contains(logOutput.String(), "secret-state-must-not-leak") {
		t.Error("structured log leaks signed state")
	}
}

func TestHandlerUpstreamTimeout(t *testing.T) {
	// Slow server that exceeds the overall request timeout after connecting.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	oldHTTPClient := httpClient
	httpClient = newHTTPClient(50*time.Millisecond, 20*time.Millisecond)
	defer func() { httpClient = oldHTTPClient }()

	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/udp", host),
		QueryStringParameters: map[string]string{"state": "s"},
		Headers:               map[string]string{},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 503 {
		t.Errorf("StatusCode = %d, want 503", resp.StatusCode)
	}
}

func TestHandlerSlowReachableUpstreamUsesOverallTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(75 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("slow success"))
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	oldHTTPClient := httpClient
	httpClient = newHTTPClient(500*time.Millisecond, 20*time.Millisecond)
	defer func() { httpClient = oldHTTPClient }()

	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/udp", host),
		QueryStringParameters: map[string]string{"state": "s"},
		Headers:               map[string]string{},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "slow success") {
		t.Error("body does not contain slow upstream response")
	}
}

func TestHandlerDefaultOIDCHeaderFiltering(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/udp", host),
		QueryStringParameters: map[string]string{"state": "s"},
		Headers: map[string]string{
			"x-amzn-oidc-data":        "data-val",
			"x-amzn-oidc-accesstoken": "token-val",
			"x-amzn-oidc-identity":    "id-val",
			"x-other-header":          "should-not-forward",
		},
	}

	_, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if receivedHeaders.Get("X-Amzn-Oidc-Data") == "" {
		t.Error("x-amzn-oidc-data was not forwarded")
	}
	for _, h := range []string{"X-Amzn-Oidc-Accesstoken", "X-Amzn-Oidc-Identity"} {
		if receivedHeaders.Get(h) != "" {
			t.Errorf("OIDC header %q should not be forwarded by default", h)
		}
	}
	// Verify non-OIDC headers were NOT forwarded
	if receivedHeaders.Get("X-Other-Header") != "" {
		t.Error("non-OIDC header was forwarded")
	}
}

func TestHandlerOIDCHeadersCaseInsensitive(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	// Simulate ALB event with mixed-case header keys
	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/udp", host),
		QueryStringParameters: map[string]string{"state": "s"},
		Headers: map[string]string{
			"X-Amzn-Oidc-Data":        "data-val",
			"X-Amzn-Oidc-Accesstoken": "token-val",
			"X-Amzn-Oidc-Identity":    "id-val",
		},
	}

	_, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if receivedHeaders.Get("X-Amzn-Oidc-Data") == "" {
		t.Error("x-amzn-oidc-data was not forwarded (mixed-case input)")
	}
	for _, h := range []string{"X-Amzn-Oidc-Accesstoken", "X-Amzn-Oidc-Identity"} {
		if receivedHeaders.Get(h) != "" {
			t.Errorf("OIDC header %q should not be forwarded by default", h)
		}
	}
}

func TestOIDCHeadersEnvOverride(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	// Explicitly opt in to forwarding the legacy unsigned headers.
	oldHeaders := oidcHeaders
	os.Setenv("OIDC_HEADERS", `["x-amzn-oidc-data","x-amzn-oidc-accesstoken","x-amzn-oidc-identity"]`) //nolint:errcheck // test setup
	configure()
	defer func() {
		os.Unsetenv("OIDC_HEADERS") //nolint:errcheck // test cleanup
		oidcHeaders = oldHeaders
	}()

	// Set overrides after configure() since it resets all globals
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/udp", host),
		QueryStringParameters: map[string]string{"state": "s"},
		Headers: map[string]string{
			"x-amzn-oidc-data":        "data-val",
			"x-amzn-oidc-accesstoken": "token-val",
			"x-amzn-oidc-identity":    "id-val",
		},
	}

	_, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if receivedHeaders.Get("X-Amzn-Oidc-Data") == "" {
		t.Error("x-amzn-oidc-data should be forwarded")
	}
	if receivedHeaders.Get("X-Amzn-Oidc-Accesstoken") == "" {
		t.Error("x-amzn-oidc-accesstoken should be forwarded when explicitly configured")
	}
	if receivedHeaders.Get("X-Amzn-Oidc-Identity") == "" {
		t.Error("x-amzn-oidc-identity should be forwarded when explicitly configured")
	}
}

func TestHandlerAlwaysReturnsNilError(t *testing.T) {
	// Test various error scenarios — handler should never return a non-nil error
	cases := []events.ALBTargetGroupRequest{
		{Path: ""},
		{Path: "/bad"},
		{Path: "/callback/192.168.1.1/udp"},
		{Path: "/callback/10.0.1.42/udp", QueryStringParameters: map[string]string{"state": "s"}, Headers: map[string]string{}},
	}

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("10.0.0.0/16")
	vpcCIDR = cidr
	oldPortMap := portMap
	portMap = map[string]string{"udp": "19999", "tcp": "19999"}
	defer func() {
		vpcCIDR = oldCIDR
		portMap = oldPortMap
	}()

	for i, req := range cases {
		_, err := handler(context.Background(), req)
		if err != nil {
			t.Errorf("case %d: handler returned non-nil error: %v", i, err)
		}
	}
}

func TestHandlerMissingState(t *testing.T) {
	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	req := events.ALBTargetGroupRequest{
		Path:                  "/callback/127.0.0.1/udp",
		QueryStringParameters: map[string]string{},
		Headers:               map[string]string{},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", resp.StatusCode)
	}
}

func TestHandlerStateSpecialCharsEncoded(t *testing.T) {
	// state with base64 and special URL chars — upstream must receive them decoded correctly
	specialState := "abc+def=ghi&jkl#mno"

	var receivedState string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedState = r.URL.Query().Get("state")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	oldPortMap := portMap
	portMap = map[string]string{"udp": port, "tcp": port}
	defer func() { portMap = oldPortMap }()

	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	req := events.ALBTargetGroupRequest{
		Path:                  fmt.Sprintf("/callback/%s/udp", host),
		QueryStringParameters: map[string]string{"state": specialState},
		Headers:               map[string]string{},
	}

	resp, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if receivedState != specialState {
		t.Errorf("upstream received state = %q, want %q", receivedState, specialState)
	}
}

// --- getenv tests ---

func TestGetenv(t *testing.T) {
	const key = "TEST_GETENV_KEY"
	t.Cleanup(func() { _ = os.Unsetenv(key) })

	tests := []struct {
		name     string
		envValue string // empty string means unset
		def      string
		want     string
	}{
		{"returns env value when set", "fromenv", "default", "fromenv"},
		{"returns default when unset", "", "default", "default"},
		{"returns default when empty string", "", "fallback", "fallback"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Unsetenv(key) //nolint:errcheck // test setup
			if tc.envValue != "" {
				os.Setenv(key, tc.envValue) //nolint:errcheck // test setup
			}
			if got := getenv(key, tc.def); got != tc.want {
				t.Errorf("getenv(%q, %q) = %q, want %q", key, tc.def, got, tc.want)
			}
		})
	}
}
