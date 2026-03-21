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
