package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

//go:embed templates/error.html
var templateFS embed.FS

var errorTmpl *template.Template

func init() {
	var err error
	errorTmpl, err = template.ParseFS(templateFS, "templates/error.html")
	if err != nil {
		panic(fmt.Sprintf("parse error template: %s", err))
	}
}

var (
	// pathRegex matches /callback/<ipv4>/(udp|tcp)
	pathRegex = regexp.MustCompile(`^/callback/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(udp|tcp)$`)

	// oidcHeaders are forwarded from ALB to upstream daemon.
	// Populated in configure() from OIDC_HEADERS env var (JSON array) or defaults.
	oidcHeaders []string

	// Populated in configure() from environment variables.
	vpcCIDR    *net.IPNet
	portMap    map[string]string
	httpClient *http.Client
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type upstreamConnectError struct {
	err error
}

var allowedOIDCHeaders = map[string]struct{}{
	"x-amzn-oidc-data":        {},
	"x-amzn-oidc-accesstoken": {},
	"x-amzn-oidc-identity":    {},
}

const defaultOIDCHeadersJSON = `["x-amzn-oidc-data"]`

func (e *upstreamConnectError) Error() string { return "connect upstream: " + e.err.Error() }
func (e *upstreamConnectError) Unwrap() error { return e.err }

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseOIDCHeaders(raw string) ([]string, error) {
	var headers []string
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return nil, fmt.Errorf("not a valid JSON array: %w", err)
	}

	seen := make(map[string]struct{}, len(headers))
	hasData := false
	for i, header := range headers {
		header = strings.ToLower(header)
		if _, ok := allowedOIDCHeaders[header]; !ok {
			return nil, fmt.Errorf("unsupported header %q", headers[i])
		}
		if _, ok := seen[header]; ok {
			return nil, fmt.Errorf("duplicate header %q", headers[i])
		}
		seen[header] = struct{}{}
		headers[i] = header
		hasData = hasData || header == "x-amzn-oidc-data"
	}
	if !hasData {
		return nil, errors.New("x-amzn-oidc-data is required")
	}
	return headers, nil
}

// configure parses environment variables and sets package-level globals.
// Panics on invalid or missing required configuration (fail fast).
func configure() {
	// LOG_LEVEL — optional (debug, info, warn, error; default: info)
	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(getenv("LOG_LEVEL", "info"))); err != nil {
		panic(fmt.Sprintf("LOG_LEVEL is not valid: %s", err))
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	// VPC_CIDR — required
	cidrStr := os.Getenv("VPC_CIDR")
	if cidrStr == "" {
		panic("VPC_CIDR environment variable is required")
	}
	_, parsed, err := net.ParseCIDR(cidrStr)
	if err != nil {
		panic(fmt.Sprintf("VPC_CIDR is not a valid CIDR: %s", err))
	}
	vpcCIDR = parsed

	portMap = map[string]string{
		"udp": getenv("DAEMON_PORT_UDP", "8080"),
		"tcp": getenv("DAEMON_PORT_TCP", "8081"),
	}

	timeout, err := time.ParseDuration(getenv("UPSTREAM_TIMEOUT", "10s"))
	if err != nil {
		panic(fmt.Sprintf("UPSTREAM_TIMEOUT is not a valid duration: %s", err))
	}
	if timeout <= 0 {
		panic("UPSTREAM_TIMEOUT must be greater than zero")
	}

	connectTimeout, err := time.ParseDuration(getenv("UPSTREAM_CONNECT_TIMEOUT", "3s"))
	if err != nil {
		panic(fmt.Sprintf("UPSTREAM_CONNECT_TIMEOUT is not a valid duration: %s", err))
	}
	if connectTimeout <= 0 {
		panic("UPSTREAM_CONNECT_TIMEOUT must be greater than zero")
	}
	if connectTimeout >= timeout {
		panic("UPSTREAM_CONNECT_TIMEOUT must be less than UPSTREAM_TIMEOUT")
	}

	httpClient = newHTTPClient(timeout, connectTimeout)

	// OIDC_HEADERS — optional JSON array override
	headersJSON := getenv("OIDC_HEADERS", defaultOIDCHeadersJSON)
	oidcHeaders, err = parseOIDCHeaders(headersJSON)
	if err != nil {
		panic(fmt.Sprintf("OIDC_HEADERS is invalid: %s", err))
	}

	slog.Info("cold start",
		"vpc_cidr", vpcCIDR.String(),
		"ports", portMap,
		"timeout", httpClient.Timeout.String(),
		"connect_timeout", connectTimeout.String(),
		"oidc_headers", oidcHeaders,
	)
}

func newHTTPClient(timeout, connectTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = withConnectTimeout(connectTimeout, dialer.DialContext)
	return &http.Client{Transport: transport, Timeout: timeout}
}

func withConnectTimeout(timeout time.Duration, dial dialContextFunc) dialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		connectCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := dial(connectCtx, network, address)
		if err != nil {
			return nil, &upstreamConnectError{err: err}
		}
		return conn, nil
	}
}

func classifyUpstreamError(err error) string {
	var connectErr *upstreamConnectError
	if errors.As(err, &connectErr) {
		if errors.Is(connectErr, syscall.ECONNREFUSED) {
			return "connection_refused"
		}
		var netErr net.Error
		if errors.As(connectErr, &netErr) && netErr.Timeout() {
			return "connect_timeout"
		}
		return "network_error"
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return "request_timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "request_timeout"
	}
	return "network_error"
}

func newReferenceID() string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		slog.Error("generate callback reference ID failed", "error", err)
		return "unavailable"
	}
	return hex.EncodeToString(raw[:])
}

func parsePath(path string) (net.IP, string, error) {
	matches := pathRegex.FindStringSubmatch(path)
	if matches == nil {
		return nil, "", fmt.Errorf("path does not match /callback/<ip>/(udp|tcp): %q", path)
	}

	ip := net.ParseIP(matches[1])
	if ip == nil {
		return nil, "", fmt.Errorf("invalid IP address: %q", matches[1])
	}

	return ip, matches[2], nil
}

func validateIP(ip net.IP, cidr *net.IPNet) error {
	if ip.To4() == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}
	if !cidr.Contains(ip) {
		return fmt.Errorf("IP %s is outside VPC CIDR %s", ip, cidr)
	}
	return nil
}

func proxyToUpstream(ctx context.Context, upstreamURL string, headers map[string]string) (events.ALBTargetGroupResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		return events.ALBTargetGroupResponse{}, fmt.Errorf("build request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Unwrap *url.Error to avoid logging the full URL (contains state parameter).
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return events.ALBTargetGroupResponse{}, fmt.Errorf("upstream request: %w", urlErr.Err)
		}
		return events.ALBTargetGroupResponse{}, fmt.Errorf("upstream request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return events.ALBTargetGroupResponse{}, fmt.Errorf("read upstream body: %w", err)
	}

	respHeaders := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	return events.ALBTargetGroupResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       string(body),
	}, nil
}

type errorPageData struct {
	Title       string
	Message     string
	StatusCode  int
	ReferenceID string
}

func errorPage(statusCode int, title, message, referenceID string) events.ALBTargetGroupResponse {
	headers := map[string]string{
		"content-type":  "text/html; charset=utf-8",
		"cache-control": "no-store",
		"pragma":        "no-cache",
	}
	var buf bytes.Buffer
	if err := errorTmpl.ExecuteTemplate(&buf, "error.html", errorPageData{
		Title:       title,
		Message:     message,
		StatusCode:  statusCode,
		ReferenceID: referenceID,
	}); err != nil {
		slog.Error("render error template failed", "error", err)
		headers["content-type"] = "text/plain; charset=utf-8"
		return events.ALBTargetGroupResponse{
			StatusCode: statusCode,
			Headers:    headers,
			Body:       message,
		}
	}
	return events.ALBTargetGroupResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       buf.String(),
	}
}

func handler(ctx context.Context, req events.ALBTargetGroupRequest) (events.ALBTargetGroupResponse, error) {
	slog.Debug("request received", "path", req.Path)

	// Step 1: Parse path
	ip, proto, err := parsePath(req.Path)
	if err != nil {
		slog.Error("invalid path", "path", req.Path, "error", err)
		return errorPage(http.StatusBadRequest, "Bad Request", "Invalid callback path.", ""), nil
	}

	// Step 2: Validate IP in VPC CIDR
	if err := validateIP(ip, vpcCIDR); err != nil {
		slog.Error("IP outside VPC CIDR", "ip", ip.String(), "cidr", vpcCIDR.String(), "error", err)
		return errorPage(http.StatusForbidden, "Forbidden", "Invalid target.", ""), nil
	}

	// Step 3: Map proto → port
	port := portMap[proto]

	// Step 4: Build upstream URL
	state := req.QueryStringParameters["state"]
	if state == "" {
		slog.Error("missing state parameter", "path", req.Path)
		return errorPage(http.StatusBadRequest, "Bad Request", "Missing state parameter.", ""), nil
	}
	// Trailing slash is required: the daemon registers GET /callback/{path...},
	// and Go's ServeMux redirects /callback → /callback/ (307), adding a needless roundtrip.
	upstreamURL := fmt.Sprintf("http://%s:%s/callback/?state=%s", ip, port, url.QueryEscape(state))

	// Step 5: Collect OIDC headers to forward
	// Build lowercase lookup map — ALB Lambda integration lowercases headers,
	// but we normalize defensively in case casing varies.
	lowerHeaders := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		lowerHeaders[strings.ToLower(k)] = v
	}
	forwardHeaders := make(map[string]string, len(oidcHeaders))
	var present, missing []string
	for _, h := range oidcHeaders {
		if v, ok := lowerHeaders[strings.ToLower(h)]; ok {
			forwardHeaders[h] = v
			present = append(present, h)
		} else {
			missing = append(missing, h)
		}
	}
	slog.Debug("oidc headers", "present", strings.Join(present, ","), "missing", strings.Join(missing, ","))

	// Step 6: Proxy to upstream
	start := time.Now()
	resp, err := proxyToUpstream(ctx, upstreamURL, forwardHeaders)
	duration := time.Since(start)
	if err != nil {
		referenceID := newReferenceID()
		reason := classifyUpstreamError(err)
		slog.Error("callback upstream unavailable",
			"event", "callback_upstream_unavailable",
			"protocol", proto,
			"reason", reason,
			"reference_id", referenceID,
			"duration", duration.String(),
			"error", err,
		)
		return errorPage(http.StatusServiceUnavailable, "Service Unavailable",
			"VPN connection is no longer available. Do not refresh this page. Disconnect the VPN client, connect again, and complete authentication using the new link.",
			referenceID), nil
	}

	slog.Info("proxied", "ip", ip.String(), "proto", proto, "port", port, "status", resp.StatusCode, "duration", duration.String())
	return resp, nil
}

func main() {
	configure()
	lambda.Start(handler)
}
