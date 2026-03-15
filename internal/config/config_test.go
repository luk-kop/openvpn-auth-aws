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
		HMACSecret:             "test-secret",
		CallbackURL:            "https://vpn-auth.example.com/callback/01/udp",
		CognitoUserPoolID:      "eu-west-1_TestPool",
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

func TestValidate_HMACSecretRequired(t *testing.T) {
	cfg := baseValidConfig()
	cfg.HMACSecret = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when HMACSecret is empty, got nil")
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

func TestValidate_InvalidLogFormat(t *testing.T) {
	cfg := baseValidConfig()
	cfg.LogFormat = "yaml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid log-format, got nil")
	}
}
