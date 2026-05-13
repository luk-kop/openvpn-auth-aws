package callback

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/secrets"
	"strings"
	"testing"
)

// newCaptureLogger returns a slog.Logger that writes JSON records to buf at
// DEBUG level so tests can assert on individual key/value pairs without
// relying on free-form text matching.
func newCaptureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// parseLogRecords decodes the NDJSON log output into a slice of maps so tests
// can look up fields by name. Returns nil for empty input so range works.
func parseLogRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// findRecord returns the first record whose "msg" field matches name.
func findRecord(records []map[string]any, name string) map[string]any {
	for _, r := range records {
		if r["msg"] == name {
			return r
		}
	}
	return nil
}

// buildJWT produces a minimal base64url-encoded JWT with the given header and
// payload and a fake signature segment. Tests use this to avoid pulling in the
// JWT library for pure logging tests.
func buildJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	hBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hBytes) + "." + enc.EncodeToString(pBytes) + ".signaturenotused"
}

// withLogger swaps slog's default logger, runs fn, and restores the prior
// default. Returns the captured JSON output.
func withLogger(t *testing.T, fn func()) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(newCaptureLogger(&buf))
	defer slog.SetDefault(prev)
	fn()
	return &buf
}

// requestWithHeaders builds an HTTP request with the given ALB-forwarded
// headers. Missing values become empty headers (still useful to test presence
// reporting).
func requestWithHeaders(oidcData, accessToken, identity string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/callback/01/udp", nil)
	if oidcData != "" {
		req.Header.Set("x-amzn-oidc-data", oidcData)
	}
	if accessToken != "" {
		req.Header.Set("x-amzn-oidc-accesstoken", accessToken)
	}
	if identity != "" {
		req.Header.Set("x-amzn-oidc-identity", identity)
	}
	return req
}

func claimInfoMap(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	raw, ok := rec["claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected claims map in record %+v", rec)
	}
	return raw
}

func claimInfo(t *testing.T, claims map[string]any, name string) map[string]any {
	t.Helper()
	raw, ok := claims[name]
	if !ok {
		t.Fatalf("expected claim %q in claims map %+v", name, claims)
	}
	info, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("expected claim %q info map, got %T", name, raw)
	}
	return info
}

// ---------------------------------------------------------------------------
// newOIDCDebugLogger
// ---------------------------------------------------------------------------

func TestNewOIDCDebugLogger_Disabled_ReturnsNil(t *testing.T) {
	l, err := newOIDCDebugLogger(false, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l != nil {
		t.Fatalf("expected nil logger when disabled, got %+v", l)
	}
	// Nil receiver calls must be no-ops.
	l.Log(requestWithHeaders("", "", ""), "")
}

func TestNewOIDCDebugLogger_Enabled_SaltIsRandomAnd32Bytes(t *testing.T) {
	l1, err := newOIDCDebugLogger(true, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l1 == nil {
		t.Fatal("expected non-nil logger")
	}
	if len(l1.salt) != 32 {
		t.Fatalf("expected 32-byte salt, got %d", len(l1.salt))
	}

	l2, err := newOIDCDebugLogger(true, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(l1.salt, l2.salt) {
		t.Fatal("expected different salts across logger instances")
	}
}

// ---------------------------------------------------------------------------
// hashIdentity
// ---------------------------------------------------------------------------

func TestHashIdentity_EmptyReturnsEmpty(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	if got := l.hashIdentity(""); got != "" {
		t.Fatalf("expected empty hash for empty identity, got %q", got)
	}
}

func TestHashIdentity_16HexChars(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	got := l.hashIdentity("user-identity")
	if len(got) != 16 {
		t.Fatalf("expected 16 hex chars, got %d (%q)", len(got), got)
	}
	for _, ch := range got {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			t.Fatalf("expected lowercase hex, got %q", got)
		}
	}
}

func TestHashIdentity_SaltChangesHash(t *testing.T) {
	l1, _ := newOIDCDebugLogger(true, "json")
	l2, _ := newOIDCDebugLogger(true, "json")
	id := "same-identity"
	if l1.hashIdentity(id) == l2.hashIdentity(id) {
		t.Fatal("expected different hashes across instances with different salts")
	}
}

func TestHashIdentity_SameSaltSameInputIsStable(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	id := "stable-identity"
	first := l.hashIdentity(id)
	second := l.hashIdentity(id)
	if first != second {
		t.Fatalf("expected stable hash within a single logger instance, got %q then %q", first, second)
	}
}

// ---------------------------------------------------------------------------
// Log: header presence + identity hash
// ---------------------------------------------------------------------------

func TestLog_HeadersEvent_ReportsPresenceAndLengths(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256"}, map[string]any{"email": "u@example.com"}),
		"",
		"identity-value",
	)
	buf := withLogger(t, func() {
		l.Log(req, "sid-1")
	})
	rec := findRecord(parseLogRecords(t, buf), "oidc_debug_headers")
	if rec == nil {
		t.Fatal("expected oidc_debug_headers record")
	}
	if rec["sid"] != "sid-1" {
		t.Errorf("expected sid=sid-1, got %v", rec["sid"])
	}
	if rec["oidc_data_present"] != true {
		t.Errorf("expected oidc_data_present=true, got %v", rec["oidc_data_present"])
	}
	if rec["accesstoken_present"] != false {
		t.Errorf("expected accesstoken_present=false, got %v", rec["accesstoken_present"])
	}
	if rec["identity_present"] != true {
		t.Errorf("expected identity_present=true, got %v", rec["identity_present"])
	}
	if hash, _ := rec["identity_hash"].(string); len(hash) != 16 {
		t.Errorf("expected 16-char identity_hash, got %q", hash)
	}
}

func TestLog_AggregatedRecordCount_WithDataAndAccessToken(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256"}, map[string]any{"email": "u@example.com"}),
		buildJWT(t, map[string]any{"alg": "RS256"}, map[string]any{"scope": "openid"}),
		"identity-value",
	)
	buf := withLogger(t, func() {
		l.Log(req, "sid-count")
	})
	records := parseLogRecords(t, buf)
	if len(records) != 3 {
		t.Fatalf("expected exactly 3 debug records, got %d: %+v", len(records), records)
	}
	for _, msg := range []string{"oidc_debug_headers", "oidc_debug_data", "oidc_debug_accesstoken"} {
		if findRecord(records, msg) == nil {
			t.Fatalf("expected %s record in %+v", msg, records)
		}
	}
}

func TestLog_AggregatedRecordCount_WithoutAccessToken(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256"}, map[string]any{"email": "u@example.com"}),
		"",
		"identity-value",
	)
	buf := withLogger(t, func() {
		l.Log(req, "sid-count")
	})
	records := parseLogRecords(t, buf)
	if len(records) != 2 {
		t.Fatalf("expected exactly 2 debug records, got %d: %+v", len(records), records)
	}
	if findRecord(records, "oidc_debug_headers") == nil || findRecord(records, "oidc_debug_data") == nil {
		t.Fatalf("expected headers and data records, got %+v", records)
	}
	if findRecord(records, "oidc_debug_accesstoken") != nil {
		t.Fatalf("did not expect access-token record, got %+v", records)
	}
}

// ---------------------------------------------------------------------------
// Log: claim value logging rules
// ---------------------------------------------------------------------------

func TestLog_LogsAllClaimValuesForDataAndAccessToken(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	oidcPayload := map[string]any{
		"email":         "u@example.com",
		"sub":           "abc-123",
		"custom:groups": []string{"vpn-admin"},
	}
	accessPayload := map[string]any{
		"cognito:groups": []string{"vpn-users"},
		"scope":          "openid profile",
	}
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256", "kid": "k1", "signer": "arn", "typ": "JWT"}, oidcPayload),
		buildJWT(t, map[string]any{"alg": "RS256"}, accessPayload),
		"",
	)

	buf := withLogger(t, func() {
		l.Log(req, "sid-values")
	})
	records := parseLogRecords(t, buf)
	dataRec := findRecord(records, "oidc_debug_data")
	if dataRec == nil {
		t.Fatal("expected oidc_debug_data record")
	}
	accessRec := findRecord(records, "oidc_debug_accesstoken")
	if accessRec == nil {
		t.Fatal("expected oidc_debug_accesstoken record")
	}

	dataClaims := claimInfoMap(t, dataRec)
	if len(dataClaims) != len(oidcPayload) {
		t.Fatalf("expected %d oidc-data claims, got %d", len(oidcPayload), len(dataClaims))
	}
	for name := range oidcPayload {
		if _, ok := claimInfo(t, dataClaims, name)["value"]; !ok {
			t.Errorf("expected oidc-data value for claim %q", name)
		}
	}
	accessClaims := claimInfoMap(t, accessRec)
	if len(accessClaims) != len(accessPayload) {
		t.Fatalf("expected %d access-token claims, got %d", len(accessPayload), len(accessClaims))
	}
	for name := range accessPayload {
		if _, ok := claimInfo(t, accessClaims, name)["value"]; !ok {
			t.Errorf("expected access-token value for claim %q", name)
		}
	}
}

func TestLog_TextFormatEmitsFlatClaimRecords(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "text")
	req := requestWithHeaders(
		buildJWT(t,
			map[string]any{"alg": "ES256", "kid": "k1", "signer": "arn", "typ": "JWT"},
			map[string]any{
				"email":         "u@example.com",
				"sub":           "abc-123",
				"custom:groups": "[g1, g2]",
			}),
		"",
		"",
	)

	buf := withLogger(t, func() {
		l.Log(req, "sid-flat")
	})
	records := parseLogRecords(t, buf)
	if findRecord(records, "oidc_debug_data") != nil {
		t.Fatalf("text format must not emit aggregate claims record: %+v", records)
	}
	header := findRecord(records, "oidc_debug_data_header")
	if header == nil {
		t.Fatalf("expected flat header record, got %+v", records)
	}
	if header["header_alg"] != "ES256" || header["header_kid"] != "k1" || header["header_typ"] != "JWT" {
		t.Fatalf("unexpected flat header fields: %+v", header)
	}
	claim := findClaimRecord(records, "custom:groups")
	if claim == nil {
		t.Fatalf("expected flat custom:groups claim record, got %+v", records)
	}
	if claim["type"] != "string" || claim["len"] != float64(10) || claim["value"] != "\"[g1, g2]\"" {
		t.Fatalf("unexpected flat claim fields: %+v", claim)
	}
	for _, rec := range records {
		if _, ok := rec["claims"]; ok {
			t.Fatalf("text format emitted nested claims field: %+v", rec)
		}
	}
}

func findClaimRecord(records []map[string]any, name string) map[string]any {
	for _, r := range records {
		msg, _ := r["msg"].(string)
		if strings.HasSuffix(msg, "_claim") && r["name"] == name {
			return r
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Log: raw tokens must not be emitted
// ---------------------------------------------------------------------------

func TestLog_RawTokensNeverLogged(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	oidcData := buildJWT(t,
		map[string]any{"alg": "ES256", "kid": "k1"},
		map[string]any{"email": "u@example.com", "cognito:groups": []string{"g1", "g2"}},
	)
	accessToken := buildJWT(t,
		map[string]any{"alg": "RS256"},
		map[string]any{"scope": "openid", "username": "u"},
	)
	req := requestWithHeaders(oidcData, accessToken, "opaque-identity-string")
	buf := withLogger(t, func() {
		l.Log(req, "sid-raw")
	})
	output := buf.String()
	if strings.Contains(output, oidcData) {
		t.Fatal("raw x-amzn-oidc-data token was emitted in log output")
	}
	if strings.Contains(output, accessToken) {
		t.Fatal("raw x-amzn-oidc-accesstoken token was emitted in log output")
	}
	if strings.Contains(output, "opaque-identity-string") {
		t.Fatal("raw x-amzn-oidc-identity was emitted in log output")
	}
}

// ---------------------------------------------------------------------------
// Log: malformed inputs
// ---------------------------------------------------------------------------

func TestLog_MalformedJWT_DoesNotPanic(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	req := requestWithHeaders("this.is.not-a-valid-jwt", "also.bad", "id")
	buf := withLogger(t, func() {
		l.Log(req, "sid-bad")
	})
	// We only need to confirm it produced some diagnostic without crashing.
	if buf.Len() == 0 {
		t.Fatal("expected at least one record for a malformed JWT")
	}
}

func TestLog_NoJWTSegments_EmitsMalformedEvent(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	req := requestWithHeaders("one-segment", "", "")
	buf := withLogger(t, func() {
		l.Log(req, "sid-short")
	})
	rec := findRecord(parseLogRecords(t, buf), "oidc_debug_data")
	if rec == nil {
		t.Fatal("expected oidc_debug_data record")
	}
	if val, ok := rec["token_error"].(string); !ok || val == "" {
		t.Fatalf("expected token_error in malformed token record, got %+v", rec)
	}
}

func TestLog_MalformedPayload_EmitsSingleDataRecordWithError(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"k1"}`))
	req := requestWithHeaders(header+".not-valid-base64.", "", "")
	buf := withLogger(t, func() {
		l.Log(req, "sid-bad-payload")
	})
	records := parseLogRecords(t, buf)
	if len(records) != 2 {
		t.Fatalf("expected headers + data records, got %d: %+v", len(records), records)
	}
	rec := findRecord(records, "oidc_debug_data")
	if rec == nil {
		t.Fatal("expected oidc_debug_data record")
	}
	if val, ok := rec["payload_error"].(string); !ok || val == "" {
		t.Fatalf("expected payload_error in data record, got %+v", rec)
	}
	if _, ok := rec["header"].(map[string]any); !ok {
		t.Fatalf("expected decoded header in data record, got %+v", rec)
	}
}

// ---------------------------------------------------------------------------
// capPayload + truncationSuffix
// ---------------------------------------------------------------------------

func TestCapPayload_BelowCap_NotTruncated(t *testing.T) {
	emitted, truncated, total := capPayload(json.RawMessage(`"abc"`), 10)
	if truncated {
		t.Fatal("expected truncated=false")
	}
	if total != 5 {
		t.Fatalf("expected total=5, got %d", total)
	}
	if string(emitted) != `"abc"` {
		t.Fatalf("unexpected emitted bytes: %q", emitted)
	}
}

func TestCapPayload_AtBoundary_NotTruncated(t *testing.T) {
	raw := json.RawMessage(strings.Repeat("x", 2048))
	emitted, truncated, total := capPayload(raw, oidcDebugValueCap)
	if truncated {
		t.Fatal("expected truncated=false at exactly the cap")
	}
	if total != 2048 || len(emitted) != 2048 {
		t.Fatalf("expected total=2048 and emitted=2048, got total=%d emitted=%d", total, len(emitted))
	}
}

func TestCapPayload_AboveCap_TruncatedAndTotalReflectsOriginal(t *testing.T) {
	raw := json.RawMessage(strings.Repeat("y", oidcDebugValueCap+500))
	emitted, truncated, total := capPayload(raw, oidcDebugValueCap)
	if !truncated {
		t.Fatal("expected truncated=true")
	}
	if total != oidcDebugValueCap+500 {
		t.Fatalf("expected total=%d, got %d", oidcDebugValueCap+500, total)
	}
	if len(emitted) != oidcDebugValueCap {
		t.Fatalf("expected emitted=%d, got %d", oidcDebugValueCap, len(emitted))
	}
}

func TestTruncationSuffix_Format(t *testing.T) {
	got := truncationSuffix(4242)
	if got != "<truncated,total_bytes=4242>" {
		t.Fatalf("unexpected suffix: %q", got)
	}
}

func TestLog_LargeGroupValueIsCappedWithSuffix(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, "json")
	bigGroup := strings.Repeat("g", oidcDebugValueCap+100)
	payload := map[string]any{"cognito:groups": bigGroup}
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256"}, payload),
		"",
		"",
	)
	buf := withLogger(t, func() {
		l.Log(req, "sid-big")
	})
	records := parseLogRecords(t, buf)
	rec := findRecord(records, "oidc_debug_data")
	if rec == nil {
		t.Fatal("expected oidc_debug_data record")
	}
	claims := claimInfoMap(t, rec)
	info := claimInfo(t, claims, "cognito:groups")
	value, _ := info["value"].(string)
	// Per plan: the cap applies to the original payload bytes and the suffix is
	// appended inline after truncation, so the emitted string exceeds the cap
	// by the suffix length.
	expectedSuffix := truncationSuffix(len(bigGroup) + 2) // +2 for JSON quotes around the string
	if !strings.HasSuffix(value, expectedSuffix) {
		t.Fatalf("expected value to end with %q, got tail %q", expectedSuffix, value[max(0, len(value)-len(expectedSuffix)):])
	}
	if len(value) != oidcDebugValueCap+len(expectedSuffix) {
		t.Fatalf("expected value length %d (cap %d + suffix %d), got %d",
			oidcDebugValueCap+len(expectedSuffix), oidcDebugValueCap, len(expectedSuffix), len(value))
	}
	if _, ok := info["truncated_suffix"]; ok {
		t.Fatalf("expected no separate truncated_suffix field; suffix is appended inline to value")
	}
}

// ---------------------------------------------------------------------------
// describeJSONValue
// ---------------------------------------------------------------------------

func TestDescribeJSONValue_KnownTypes(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`"abc"`, "string"},
		{`42`, "number"},
		{`-3.14`, "number"},
		{`true`, "bool"},
		{`false`, "bool"},
		{`null`, "null"},
		{`{"a":1}`, "object"},
		{`["a","b"]`, "array"},
		{" \t\"x\"\n", "string"}, // leading/trailing JSON whitespace is trimmed
		{"", "empty"},
	}
	for _, c := range cases {
		got, _ := describeJSONValue(json.RawMessage(c.raw))
		if got != c.want {
			t.Errorf("describeJSONValue(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// No-op nil receiver
// ---------------------------------------------------------------------------

func TestNilReceiver_LogIsNoOp(t *testing.T) {
	var l *oidcDebugLogger
	// Must not panic and must not emit anything.
	buf := withLogger(t, func() {
		l.Log(requestWithHeaders("x.y.z", "", ""), "sid")
	})
	if buf.Len() != 0 {
		t.Fatalf("expected no log output for nil logger, got %q", buf.String())
	}
}

// ---------------------------------------------------------------------------
// Context-free: ensure logging uses slog default without requiring context.
// ---------------------------------------------------------------------------

var _ = context.Background // keep context import stable for future extensions

func TestNewServer_ConstructsOIDCDebugLogger(t *testing.T) {
	cfg := defaultCfg()
	cfg.OIDCDebugClaims = true
	cfg.LogFormat = "json"
	cfg.GroupsSource = config.GroupsSourceJWTClaim
	cfg.GroupsClaim = "custom:groups"

	sessions := auth.NewSessionStore()
	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sink := &captureSink{}
	m := &fakeMetrics{}
	srv, err := NewServer(sessions, signer, sink, nil, cfg, m, nil, func() bool { return true })
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.oidcDebug == nil {
		t.Fatal("expected oidc debug logger to be constructed")
	}

	payload := map[string]any{
		"email":         "u@example.com",
		"custom:groups": []string{"vpn-users"},
	}
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256"}, payload),
		"",
		"",
	)
	buf := withLogger(t, func() {
		srv.oidcDebug.Log(req, "sid-wire")
	})
	rec := findRecord(parseLogRecords(t, buf), "oidc_debug_data")
	if rec == nil {
		t.Fatal("expected oidc_debug_data record")
	}
	claims := claimInfoMap(t, rec)
	for name := range payload {
		if _, ok := claimInfo(t, claims, name)["value"]; !ok {
			t.Fatalf("expected value for claim %q", name)
		}
	}
}
