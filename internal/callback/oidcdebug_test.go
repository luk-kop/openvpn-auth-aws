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

// findAllClaimRecords returns all claim events for the given event prefix.
func findAllClaimRecords(records []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, r := range records {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
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

// ---------------------------------------------------------------------------
// newOIDCDebugLogger
// ---------------------------------------------------------------------------

func TestNewOIDCDebugLogger_Disabled_ReturnsNil(t *testing.T) {
	l, err := newOIDCDebugLogger(false, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l != nil {
		t.Fatalf("expected nil logger when disabled, got %+v", l)
	}
	// Nil receiver calls must be no-ops.
	l.Log(requestWithHeaders("", "", ""), "")
}

// Defense-in-depth: unsafe implies enabled inside newOIDCDebugLogger itself,
// not only through config.Parse normalization. Callers that build Config
// directly (tests, embedders) must still get a working unsafe-mode logger.
func TestNewOIDCDebugLogger_UnsafeImpliesEnabled(t *testing.T) {
	l, err := newOIDCDebugLogger(false, true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil logger when unsafe mode is set even with enabled=false")
	}
	if !l.unsafeMode {
		t.Fatal("expected unsafeMode=true")
	}
}

func TestNewOIDCDebugLogger_Enabled_SaltIsRandomAnd32Bytes(t *testing.T) {
	l1, err := newOIDCDebugLogger(true, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l1 == nil {
		t.Fatal("expected non-nil logger")
	}
	if len(l1.salt) != 32 {
		t.Fatalf("expected 32-byte salt, got %d", len(l1.salt))
	}

	l2, err := newOIDCDebugLogger(true, false, "")
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
	l, _ := newOIDCDebugLogger(true, false, "")
	if got := l.hashIdentity(""); got != "" {
		t.Fatalf("expected empty hash for empty identity, got %q", got)
	}
}

func TestHashIdentity_16HexChars(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, false, "")
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
	l1, _ := newOIDCDebugLogger(true, false, "")
	l2, _ := newOIDCDebugLogger(true, false, "")
	id := "same-identity"
	if l1.hashIdentity(id) == l2.hashIdentity(id) {
		t.Fatal("expected different hashes across instances with different salts")
	}
}

func TestHashIdentity_SameSaltSameInputIsStable(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, false, "")
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
	l, _ := newOIDCDebugLogger(true, false, "")
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

// ---------------------------------------------------------------------------
// Log: x-amzn-oidc-data value logging rules
// ---------------------------------------------------------------------------

func TestLog_SafeMode_LogsOnlyAllowlistAndConfiguredClaimValues(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, false, "custom:groups")
	payload := map[string]any{
		"email":          "u@example.com",
		"sub":            "abc-123",
		"cognito:groups": []string{"vpn-users"},
		"groups":         "members",
		"roles":          []string{"reader"},
		"custom:groups":  []string{"vpn-admin"},
		"extra":          "hidden-value",
	}
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256", "kid": "k1", "signer": "arn", "typ": "JWT"}, payload),
		"",
		"",
	)

	buf := withLogger(t, func() {
		l.Log(req, "sid-allow")
	})
	records := parseLogRecords(t, buf)
	claims := findAllClaimRecords(records, "oidc_debug_data_claim")
	if len(claims) != len(payload) {
		t.Fatalf("expected %d claim records, got %d", len(payload), len(claims))
	}

	withValue := map[string]bool{}
	withoutValue := map[string]bool{}
	for _, r := range claims {
		name, _ := r["name"].(string)
		if _, ok := r["value"]; ok {
			withValue[name] = true
		} else {
			withoutValue[name] = true
		}
	}

	for _, name := range []string{"cognito:groups", "groups", "roles", "custom:groups"} {
		if !withValue[name] {
			t.Errorf("expected value to be logged for %q", name)
		}
	}
	for _, name := range []string{"email", "sub", "extra"} {
		if withValue[name] {
			t.Errorf("safe mode must not log value for %q", name)
		}
		if !withoutValue[name] {
			t.Errorf("expected claim record for %q without value", name)
		}
	}
}

func TestLog_UnsafeMode_LogsAllClaimValues(t *testing.T) {
	l, _ := newOIDCDebugLogger(true, true, "")
	payload := map[string]any{
		"email": "u@example.com",
		"sub":   "abc-123",
	}
	req := requestWithHeaders(
		buildJWT(t, map[string]any{"alg": "ES256"}, payload),
		"",
		"",
	)
	buf := withLogger(t, func() {
		l.Log(req, "sid-unsafe")
	})
	claims := findAllClaimRecords(parseLogRecords(t, buf), "oidc_debug_data_claim")
	if len(claims) != len(payload) {
		t.Fatalf("expected %d claim records, got %d", len(payload), len(claims))
	}
	for _, r := range claims {
		if _, ok := r["value"]; !ok {
			t.Errorf("unsafe mode: expected value for claim %v", r["name"])
		}
	}
}

// ---------------------------------------------------------------------------
// Log: x-amzn-oidc-accesstoken
// ---------------------------------------------------------------------------

func TestLog_SafeMode_AccessTokenValuesNeverLogged_EvenForGroupLikeNames(t *testing.T) {
	// Configure --groups-claim so the name appears in both allowlists and the
	// configured-claim union. Access-token path must still suppress values.
	l, _ := newOIDCDebugLogger(true, false, "groups")
	payload := map[string]any{
		"groups":         []string{"vpn-users"},
		"cognito:groups": []string{"admin"},
		"roles":          []string{"reader"},
		"custom:claim":   "value-that-must-not-appear",
	}
	req := requestWithHeaders(
		"", // no oidc-data
		buildJWT(t, map[string]any{"alg": "RS256"}, payload),
		"",
	)
	buf := withLogger(t, func() {
		l.Log(req, "sid-at")
	})
	claims := findAllClaimRecords(parseLogRecords(t, buf), "oidc_debug_accesstoken_claim")
	if len(claims) == 0 {
		t.Fatal("expected access-token claim records")
	}
	for _, r := range claims {
		if _, ok := r["value"]; ok {
			t.Errorf("safe mode must not emit access-token values; got value for %v", r["name"])
		}
	}
}

// ---------------------------------------------------------------------------
// Log: raw tokens must not be emitted
// ---------------------------------------------------------------------------

func TestLog_RawTokensNeverLogged_SafeMode(t *testing.T) {
	assertNoRawTokens(t, false)
}

func TestLog_RawTokensNeverLogged_UnsafeMode(t *testing.T) {
	assertNoRawTokens(t, true)
}

func assertNoRawTokens(t *testing.T, unsafeMode bool) {
	t.Helper()
	l, _ := newOIDCDebugLogger(true, unsafeMode, "")
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
	l, _ := newOIDCDebugLogger(true, false, "")
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
	l, _ := newOIDCDebugLogger(true, false, "")
	req := requestWithHeaders("one-segment", "", "")
	buf := withLogger(t, func() {
		l.Log(req, "sid-short")
	})
	if rec := findRecord(parseLogRecords(t, buf), "oidc_debug_data_malformed"); rec == nil {
		t.Fatal("expected oidc_debug_data_malformed record")
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
	l, _ := newOIDCDebugLogger(true, false, "")
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
	claims := findAllClaimRecords(records, "oidc_debug_data_claim")
	if len(claims) != 1 {
		t.Fatalf("expected exactly one claim record, got %d", len(claims))
	}
	rec := claims[0]
	value, _ := rec["value"].(string)
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
	if _, ok := rec["truncated_suffix"]; ok {
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

// Regression guard (Step 3 review fix #2): NewServer must forward cfg.GroupsClaim
// into the debug logger so safe mode logs the value of the configured custom
// group claim alongside the hardcoded allowlist.
func TestNewServer_WiresGroupsClaimIntoDebugLogger(t *testing.T) {
	cfg := defaultCfg()
	cfg.OIDCDebugClaims = true
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
	if srv.oidcDebug.configuredGroupsClaim != "custom:groups" {
		t.Fatalf("expected configured groups claim to be wired through, got %q", srv.oidcDebug.configuredGroupsClaim)
	}

	// And prove it actually logs the value of the configured claim in safe mode.
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
	claims := findAllClaimRecords(parseLogRecords(t, buf), "oidc_debug_data_claim")
	var sawCustomValue bool
	for _, r := range claims {
		if r["name"] == "custom:groups" {
			if _, ok := r["value"]; ok {
				sawCustomValue = true
			}
		}
	}
	if !sawCustomValue {
		t.Fatal("expected safe mode to log custom:groups value when it is the configured --groups-claim")
	}
}
