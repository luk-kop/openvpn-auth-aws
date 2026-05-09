package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

func TestMain(m *testing.M) {
	// Set required env vars before init() runs — but init() already ran
	// when this package was loaded. We re-initialize globals for tests.
	os.Setenv("VPC_CIDR", "10.0.0.0/16") //nolint:errcheck // test setup
	os.Setenv("DAEMON_PORT_UDP", "8080") //nolint:errcheck // test setup
	os.Setenv("DAEMON_PORT_TCP", "8081") //nolint:errcheck // test setup
	os.Setenv("UPSTREAM_TIMEOUT", "2s")  //nolint:errcheck // test setup

	_, parsed, _ := net.ParseCIDR("10.0.0.0/16")
	vpcCIDR = parsed
	portMap = map[string]string{"udp": "8080", "tcp": "8081"}
	httpClient = &http.Client{Timeout: 2 * time.Second}
	oidcHeaders = []string{"x-amzn-oidc-data", "x-amzn-oidc-accesstoken", "x-amzn-oidc-identity"}

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
			resp := errorPage(tt.statusCode, tt.title, tt.message)

			if resp.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.statusCode)
			}
			if ct := resp.Headers["content-type"]; ct != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
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
		"VPN server is temporarily unavailable. Please try reconnecting.")

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

// --- handler tests (with httptest mock upstream) ---

func TestHandlerValidCallbackUDP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify OIDC headers are forwarded
		if r.Header.Get("x-amzn-oidc-data") != "jwt-token" {
			t.Error("missing x-amzn-oidc-data header")
		}
		if r.Header.Get("x-amzn-oidc-accesstoken") != "access-token" {
			t.Error("missing x-amzn-oidc-accesstoken header")
		}
		if r.Header.Get("x-amzn-oidc-identity") != "user@example.com" {
			t.Error("missing x-amzn-oidc-identity header")
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
	// Use a port that nothing is listening on
	oldCIDR := vpcCIDR
	_, cidr, _ := net.ParseCIDR("127.0.0.0/8")
	vpcCIDR = cidr
	defer func() { vpcCIDR = oldCIDR }()

	oldPortMap := portMap
	portMap = map[string]string{"udp": "19999", "tcp": "19999"}
	defer func() { portMap = oldPortMap }()

	req := events.ALBTargetGroupRequest{
		Path:                  "/callback/127.0.0.1/udp",
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

func TestHandlerUpstreamTimeout(t *testing.T) {
	// Slow server that exceeds the 2s test timeout
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
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

func TestHandlerOIDCHeadersForwarded(t *testing.T) {
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

	// Verify OIDC headers were forwarded
	for _, h := range []string{"X-Amzn-Oidc-Data", "X-Amzn-Oidc-Accesstoken", "X-Amzn-Oidc-Identity"} {
		if receivedHeaders.Get(h) == "" {
			t.Errorf("OIDC header %q was not forwarded", h)
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

	for _, h := range []string{"X-Amzn-Oidc-Data", "X-Amzn-Oidc-Accesstoken", "X-Amzn-Oidc-Identity"} {
		if receivedHeaders.Get(h) == "" {
			t.Errorf("OIDC header %q was not forwarded (mixed-case input)", h)
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

	// Override to forward only x-amzn-oidc-data
	oldHeaders := oidcHeaders
	os.Setenv("OIDC_HEADERS", `["x-amzn-oidc-data"]`) //nolint:errcheck // test setup
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
	if receivedHeaders.Get("X-Amzn-Oidc-Accesstoken") != "" {
		t.Error("x-amzn-oidc-accesstoken should NOT be forwarded when overridden")
	}
	if receivedHeaders.Get("X-Amzn-Oidc-Identity") != "" {
		t.Error("x-amzn-oidc-identity should NOT be forwarded when overridden")
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
