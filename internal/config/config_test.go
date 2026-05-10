package config

import (
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
	cfg.CognitoGroupsClaims = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when required-group is set without cognito-user-pool-id and cognito-groups-from-claims")
	}
}

func TestValidate_EmptyCognitoUserPoolID_WithRequiredGroup_ClaimsMode_NoError(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	cfg.RequiredGroup = "vpn-users"
	cfg.CognitoGroupsClaims = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error when using groups-from-claims without pool ID, got: %v", err)
	}
}

func TestValidate_EmptyCognitoUserPoolID_WithRequiredGroupClaimsModeAndReauthGroupCheck_Error(t *testing.T) {
	cfg := baseValidConfig()
	cfg.CognitoUserPoolID = ""
	cfg.ALBARN = ""
	cfg.RequiredGroup = "vpn-users"
	cfg.CognitoGroupsClaims = true
	cfg.CheckRequiredGroupOnReauth = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when reauth group checks require Cognito but cognito-user-pool-id is empty")
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
