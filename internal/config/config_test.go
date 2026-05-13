package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// baseValidConfig returns a Config with all required fields set to valid values.
func baseValidConfig() Config {
	return Config{
		ManagementSocket:       "/run/openvpn/management.sock",
		ManagementPasswordFile: "/etc/openvpn/management-pw",
		HMACSecret:             "test-secret-key!!",
		CallbackURL:            "https://vpn-auth.example.com/callback/01/udp",
		CognitoUserPoolID:      "eu-west-1_TestPool",
		CognitoIssuerURL:       "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TestPool",
		HandWindow:             300 * time.Second,
		ReconnectMaxInterval:   5 * time.Second,
		LogFormat:              "text",
		CallbackPort:           8080,
	}
}

func TestValidate_CallbackURLRequired(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CallbackURL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when CallbackURL is empty, got nil")
	}
}

func TestValidate_ALBARNAbsent_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.ALBARN = "" // absent = dev mode, skip JWT signature validation
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when ALBARN is absent (dev mode), got: %v", err)
	}
}

func TestValidate_ALBARNPresent_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.ALBARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/vpn-auth/abc123"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when ALBARN is set, got: %v", err)
	}
}

func TestValidate_ManagementSocketRequired(t *testing.T) {
	cfg := baseValidConfig()
	cfg.ManagementSocket = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when ManagementSocket is empty, got nil")
	}
}

func TestValidate_HMACSecretOptional(t *testing.T) {
	cfg := baseValidConfig()
	cfg.HMACSecret = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when HMACSecret is empty (daemon generates random key), got: %v", err)
	}
}

func TestValidate_HMACSecretSecretIDAllowed(t *testing.T) {
	cfg := baseValidConfig()
	cfg.HMACSecret = ""
	cfg.HMACSecretSecretID = "vpn-auth/hmac"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when HMAC secret is sourced from Secrets Manager, got: %v", err)
	}
}

func TestValidate_HMACSecretSourcesMutuallyExclusive(t *testing.T) {
	cfg := baseValidConfig()
	cfg.HMACSecretSecretID = "vpn-auth/hmac"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when both HMAC secret sources are set")
	}
}

func TestValidate_HMACSecretSecretIDWhitespace(t *testing.T) {
	cfg := baseValidConfig()
	cfg.HMACSecret = ""
	cfg.HMACSecretSecretID = " vpn-auth/hmac "
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when HMAC secret secret ID has leading or trailing whitespace")
	}
}

func TestValidate_EmptyCognitoUserPoolID_NoALB_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	// Empty pool ID without ALB ARN is valid — local dev mode
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error with empty CognitoUserPoolID in local dev mode, got: %v", err)
	}
}

func TestValidate_EmptyCognitoUserPoolID_WithALB_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/vpn-auth/abc123"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when CognitoUserPoolID is empty with ALB ARN set")
	}
}

func TestValidate_EmptyCognitoUserPoolID_WithRequiredGroup_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	cfg.RequiredGroup = "vpn-users"
	cfg.GroupsSource = GroupsSourceCognitoAPI
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when required-group is set with groups-source=cognito-api and no cognito-user-pool-id")
	}
}

func TestValidate_EmptyCognitoUserPoolID_WithRequiredGroup_ClaimsMode_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	cfg.RequiredGroup = "vpn-users"
	cfg.GroupsSource = GroupsSourceJWTClaim
	cfg.GroupsClaim = "cognito:groups"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when using groups-source=jwt-claim without pool ID, got: %v", err)
	}
}

func TestValidate_EmptyCognitoUserPoolID_WithRequiredGroupClaimsModeAndReauthGroupCheck_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	cfg.RequiredGroup = "vpn-users"
	cfg.GroupsSource = GroupsSourceJWTClaim
	cfg.GroupsClaim = "cognito:groups"
	cfg.CheckRequiredGroupOnReauth = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when groups-source=jwt-claim is combined with check-required-group-on-reauth=true")
	}
}

func TestValidate_MissingIssuerURL_WithALB_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.ALBARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/vpn-auth/abc123"
	cfg.CognitoIssuerURL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when CognitoIssuerURL is empty with ALB ARN set")
	}
}

func TestValidate_CallbackURL_HTTPWithALB_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CallbackURL = "http://vpn-auth.example.com/callback"
	cfg.ALBARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/vpn-auth/abc123"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when CallbackURL uses http:// with ALB ARN set")
	}
}

func TestValidate_CallbackURL_HTTPWithoutALB_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CallbackURL = "http://localhost:8080/callback"
	cfg.ALBARN = ""
	cfg.CognitoUserPoolID = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when CallbackURL uses http:// in dev mode, got: %v", err)
	}
}

func TestValidate_InvalidLogFormat(t *testing.T) {
	cfg := baseValidConfig()
	cfg.LogFormat = "yaml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid log-format, got nil")
	}
}

func TestValidate_MaxSessionDuration_Zero_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.MaxSessionDuration = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when MaxSessionDuration is 0 (disabled), got: %v", err)
	}
}

func TestValidate_MaxSessionDuration_BelowMinimum_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.MaxSessionDuration = 30 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when MaxSessionDuration < 1m, got nil")
	}
}

func TestValidate_MaxSessionDuration_Valid(t *testing.T) {
	for _, d := range []time.Duration{time.Minute, 8 * time.Hour, 12 * time.Hour} {
		cfg := baseValidConfig()
		cfg.MaxSessionDuration = d
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected no error for MaxSessionDuration=%v, got: %v", d, err)
		}
	}
}

func TestValidate_MaxSessionDurationShorterThanReneg_Warns(t *testing.T) {
	cfg := baseValidConfig()
	cfg.MaxSessionDuration = 5 * time.Minute
	cfg.RenegInterval = time.Hour
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error (warning only), got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OIDC debug flags
// ---------------------------------------------------------------------------

func TestValidate_OIDCDebugClaims_Disabled_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.OIDCDebugClaims = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error with OIDC debug flags off, got: %v", err)
	}
}

func TestValidate_OIDCDebugClaims_Enabled_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.OIDCDebugClaims = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error with OIDC debug mode, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Groups source / groups claim
// ---------------------------------------------------------------------------

func TestValidate_GroupsSource_DefaultIsCognitoAPI(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = ""
	// Validate() defaults an empty GroupsSource to cognito-api. baseValidConfig
	// provides a pool ID so the Cognito-API path validates cleanly.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error with empty GroupsSource (defaults to cognito-api), got: %v", err)
	}
}

func TestValidate_GroupsSource_CognitoAPI_IgnoresGroupsClaim(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = GroupsSourceCognitoAPI
	cfg.GroupsClaim = "cognito:groups" // accepted and ignored in cognito-api mode
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error: groups-source=cognito-api should accept groups-claim, got: %v", err)
	}
}

func TestValidate_GroupsSource_JWTClaim_RequiresGroupsClaim(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = GroupsSourceJWTClaim
	cfg.GroupsClaim = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when groups-source=jwt-claim is set without groups-claim")
	}
}

func TestValidate_GroupsSource_JWTClaim_WithGroupsClaim_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = GroupsSourceJWTClaim
	cfg.GroupsClaim = "custom:groups"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error with groups-source=jwt-claim and groups-claim set, got: %v", err)
	}
}

func TestValidate_GroupsSource_JWTClaim_RejectsReauthGroupCheck(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = GroupsSourceJWTClaim
	cfg.GroupsClaim = "cognito:groups"
	cfg.RequiredGroup = "vpn-users"
	cfg.CheckRequiredGroupOnReauth = true
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when groups-source=jwt-claim is combined with check-required-group-on-reauth=true")
	}
	// Error should be actionable — the plan's prescribed fix is to switch to
	// cognito-api mode for reauth-time group revocation.
	if !strings.Contains(err.Error(), "groups-source=cognito-api") {
		t.Errorf("expected error message to mention the recommended fix, got: %v", err)
	}
}

func TestValidate_GroupsSource_UnknownValue_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = "ldap"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unknown groups-source value")
	}
	// Unknown-value errors must mention the flag and allowed values so operators
	// can fix their config without reading source.
	for _, needle := range []string{"groups-source", "cognito-api", "jwt-claim"} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("expected error to mention %q, got: %v", needle, err)
		}
	}
}

func TestValidate_GroupsSource_JWTClaim_DoesNotRequirePoolID(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	cfg.CognitoIssuerURL = ""
	cfg.GroupsSource = GroupsSourceJWTClaim
	cfg.GroupsClaim = "cognito:groups"
	cfg.RequiredGroup = "vpn-users"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error: groups-source=jwt-claim should not require cognito-user-pool-id for callback/connect, got: %v", err)
	}
}

// Regression guard (Step 3 review fix #1): the pool-ID check for cognito-api
// must still fire when GroupsSource is left empty by direct struct construction.
// Validate() defaults an empty GroupsSource to cognito-api BEFORE any dependent
// rule runs; a defaults-too-late bug would silently accept this combination.
func TestValidate_EmptyGroupsSource_TriggersPoolIDCheck(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = ""
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	cfg.RequiredGroup = "vpn-users"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: empty GroupsSource must default to cognito-api before the pool-ID check runs")
	}
}

// ---------------------------------------------------------------------------
// Removed environment variables
// ---------------------------------------------------------------------------

func TestParse_RemovedCognitoGroupsFromClaimsEnv_FailsLoudly(t *testing.T) {
	t.Setenv("VPN_AUTH_COGNITO_GROUPS_FROM_CLAIMS", "true")
	t.Setenv("VPN_AUTH_CALLBACK_URL", "https://vpn-auth.example.com/callback/01/udp")

	resetCommandLine(t, "openvpn-auth-daemon")

	_, err := Parse()
	if err == nil {
		t.Fatal("expected Parse to fail when removed VPN_AUTH_COGNITO_GROUPS_FROM_CLAIMS is set")
	}
	for _, needle := range []string{
		"VPN_AUTH_COGNITO_GROUPS_FROM_CLAIMS is no longer supported",
		"VPN_AUTH_GROUPS_SOURCE=jwt-claim",
		"VPN_AUTH_GROUPS_CLAIM=<verified x-amzn-oidc-data claim>",
	} {
		if !strings.Contains(err.Error(), needle) {
			t.Fatalf("expected error to contain %q, got: %v", needle, err)
		}
	}
}

func TestParse_VersionFlagBypassesRuntimeValidation(t *testing.T) {
	resetCommandLine(t, "openvpn-auth-daemon", "--version")

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.ShowVersion {
		t.Fatal("expected ShowVersion=true")
	}
}

func TestParse_OIDCDebugClaimsEnv_EnablesDebug(t *testing.T) {
	t.Setenv("VPN_AUTH_CALLBACK_URL", "https://vpn-auth.example.com/callback/01/udp")
	t.Setenv("VPN_AUTH_OIDC_DEBUG_CLAIMS", "true")
	resetCommandLine(t, "openvpn-auth-daemon")

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.OIDCDebugClaims {
		t.Fatal("expected OIDCDebugClaims=true")
	}
}

func TestParse_OIDCDebugClaimsFlag_EnablesDebug(t *testing.T) {
	t.Setenv("VPN_AUTH_CALLBACK_URL", "https://vpn-auth.example.com/callback/01/udp")
	resetCommandLine(t, "openvpn-auth-daemon", "--oidc-debug-claims")

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.OIDCDebugClaims {
		t.Fatal("expected OIDCDebugClaims=true")
	}
}

func resetCommandLine(t *testing.T, args ...string) {
	t.Helper()
	oldCommandLine := flag.CommandLine
	oldArgs := os.Args
	t.Cleanup(func() {
		flag.CommandLine = oldCommandLine
		os.Args = oldArgs
	})
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	os.Args = args
}

// ---------------------------------------------------------------------------
// Step 9: startup notices emitted by LogStartupNotices
// ---------------------------------------------------------------------------

// withCaptureLogger swaps the slog default with a JSON handler writing into
// buf so tests can assert on structured records. Restores the previous
// default when fn returns.
func withCaptureLogger(t *testing.T, fn func()) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)
	fn()
	return &buf
}

// findNoticeRecord decodes NDJSON log output and returns the first record
// whose "event" key matches eventKey.
func findNoticeRecord(t *testing.T, buf *bytes.Buffer, eventKey string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if rec["event"] == eventKey {
			return rec
		}
	}
	return nil
}

func TestLogStartupNotices_OIDCDebugEmitsWarnEvent(t *testing.T) {
	cfg := baseValidConfig()
	cfg.OIDCDebugClaims = true

	buf := withCaptureLogger(t, func() {
		cfg.LogStartupNotices()
	})

	rec := findNoticeRecord(t, buf, "oidc_debug_enabled")
	if rec == nil {
		t.Fatal("expected oidc_debug_enabled notice record")
	}
	if level, _ := rec["level"].(string); level != "WARN" {
		t.Errorf("expected WARN level for OIDC debug mode, got %q", level)
	}
}

func TestLogStartupNotices_DebugDisabled_NoEvent(t *testing.T) {
	cfg := baseValidConfig()
	cfg.OIDCDebugClaims = false

	buf := withCaptureLogger(t, func() {
		cfg.LogStartupNotices()
	})

	if findNoticeRecord(t, buf, "oidc_debug_enabled") != nil {
		t.Error("unexpected oidc_debug_enabled record when OIDC debug is disabled")
	}
}

func TestLogStartupNotices_GroupsSourceConfigured_JWTClaim(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = GroupsSourceJWTClaim
	cfg.GroupsClaim = "custom:groups"
	cfg.CheckRequiredGroupOnReauth = false

	buf := withCaptureLogger(t, func() {
		cfg.LogStartupNotices()
	})

	rec := findMessageRecord(t, buf, "groups source configured")
	if rec == nil {
		t.Fatal("expected groups source configured startup record")
	}
	if rec["source"] != GroupsSourceJWTClaim {
		t.Fatalf("expected source=%q, got %v", GroupsSourceJWTClaim, rec["source"])
	}
	if rec["claim"] != "custom:groups" {
		t.Fatalf("expected claim=custom:groups, got %v", rec["claim"])
	}
	if rec["reauth_group_check"] != false {
		t.Fatalf("expected reauth_group_check=false, got %v", rec["reauth_group_check"])
	}
	if rec["claim_ignored"] != false {
		t.Fatalf("expected claim_ignored=false for jwt-claim mode, got %v", rec["claim_ignored"])
	}
}

func TestLogStartupNotices_GroupsSourceConfigured_CognitoAPIClaimIgnored(t *testing.T) {
	cfg := baseValidConfig()
	cfg.GroupsSource = GroupsSourceCognitoAPI
	cfg.GroupsClaim = "custom:groups"
	cfg.CheckRequiredGroupOnReauth = true

	buf := withCaptureLogger(t, func() {
		cfg.LogStartupNotices()
	})

	rec := findMessageRecord(t, buf, "groups source configured")
	if rec == nil {
		t.Fatal("expected groups source configured startup record")
	}
	if rec["source"] != GroupsSourceCognitoAPI {
		t.Fatalf("expected source=%q, got %v", GroupsSourceCognitoAPI, rec["source"])
	}
	if rec["claim"] != "custom:groups" {
		t.Fatalf("expected claim=custom:groups, got %v", rec["claim"])
	}
	if rec["reauth_group_check"] != true {
		t.Fatalf("expected reauth_group_check=true, got %v", rec["reauth_group_check"])
	}
	if rec["claim_ignored"] != true {
		t.Fatalf("expected claim_ignored=true when cognito-api mode has a configured claim, got %v", rec["claim_ignored"])
	}
}

func findMessageRecord(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if rec["msg"] == msg {
			return rec
		}
	}
	return nil
}
