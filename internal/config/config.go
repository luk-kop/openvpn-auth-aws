package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	ManagementSocket       string
	ManagementPasswordFile string
	APIGatewayURL          string
	HMACSecret             string
	HMACSecretARN          string
	RequiredGroup          string
	CNCrossCheck           bool
	PollInterval           time.Duration
	HandWindow             time.Duration
	ReconnectMaxInterval   time.Duration
	ShutdownGracePeriod    time.Duration
	CheckGroupsOnReauth    bool
	ReauthCache            bool
	ReauthTimeout          time.Duration
	RenegInterval          time.Duration
	InstanceID             string

	// AWS configuration
	AWSRegion          string
	DynamoDBTable      string
	CognitoUserPoolID  string
	LocalStackEndpoint string
	UseLocalMocks      bool
	LocalIdentity      bool
}

func Parse() (Config, error) {
	cfg := Config{}

	flag.StringVar(&cfg.ManagementSocket, "management-socket", getenv("VPN_AUTH_MANAGEMENT_SOCKET", "/run/openvpn/management.sock"), "path to the OpenVPN management unix socket")
	flag.StringVar(&cfg.ManagementPasswordFile, "management-password-file", getenv("VPN_AUTH_MANAGEMENT_PASSWORD_FILE", "/etc/openvpn/management-pw"), "file containing the management password")
	flag.StringVar(&cfg.APIGatewayURL, "api-gateway-url", getenv("VPN_AUTH_API_GATEWAY_URL", ""), "public API Gateway base URL without trailing slash")
	flag.StringVar(&cfg.HMACSecret, "hmac-secret", getenv("VPN_AUTH_HMAC_SECRET", ""), "HMAC secret for signing state values")
	flag.StringVar(&cfg.HMACSecretARN, "hmac-secret-arn", getenv("VPN_AUTH_HMAC_SECRET_ARN", ""), "AWS Secrets Manager ARN for HMAC secret (overrides --hmac-secret)")
	flag.StringVar(&cfg.RequiredGroup, "required-group", getenv("VPN_AUTH_REQUIRED_GROUP", ""), "required Cognito group for VPN access")
	flag.BoolVar(&cfg.CNCrossCheck, "cn-cross-check", getBool("VPN_AUTH_CN_CROSS_CHECK", true), "enable CN cross-check in Lambda callback")
	flag.DurationVar(&cfg.PollInterval, "poll-interval", getDuration("VPN_AUTH_POLL_INTERVAL", 2*time.Second), "poll interval for pending auth sessions")
	flag.DurationVar(&cfg.HandWindow, "hand-window", getDuration("VPN_AUTH_HAND_WINDOW", 300*time.Second), "pending auth timeout")
	flag.DurationVar(&cfg.ReconnectMaxInterval, "reconnect-max-interval", getDuration("VPN_AUTH_RECONNECT_MAX_INTERVAL", 5*time.Second), "max backoff between management socket reconnect attempts")
	flag.DurationVar(&cfg.ShutdownGracePeriod, "shutdown-grace-period", getDuration("VPN_AUTH_SHUTDOWN_GRACE_PERIOD", 300*time.Second), "grace period for shutdown")
	flag.BoolVar(&cfg.CheckGroupsOnReauth, "check-groups-on-reauth", getBool("VPN_AUTH_CHECK_GROUPS_ON_REAUTH", false), "check required group during CLIENT:REAUTH")
	flag.BoolVar(&cfg.ReauthCache, "reauth-cache", getBool("VPN_AUTH_REAUTH_CACHE", false), "allow cached reauth decisions during identity provider outage")
	flag.DurationVar(&cfg.ReauthTimeout, "reauth-timeout", getDuration("VPN_AUTH_REAUTH_TIMEOUT", 5*time.Second), "timeout for Cognito calls during CLIENT:REAUTH")
	flag.DurationVar(&cfg.RenegInterval, "reneg-interval", getDuration("VPN_AUTH_RENEG_INTERVAL", 3600*time.Second), "OpenVPN reneg-sec value (for reauth cache TTL calculation)")
	flag.StringVar(&cfg.InstanceID, "instance-id", getenv("VPN_AUTH_INSTANCE_ID", "local-dev"), "instance identifier used in EMF metrics")

	// AWS configuration
	flag.StringVar(&cfg.AWSRegion, "aws-region", getenv("AWS_REGION", "eu-west-1"), "AWS region")
	flag.StringVar(&cfg.DynamoDBTable, "dynamodb-table", getenv("VPN_AUTH_DYNAMODB_TABLE", "vpn-sessions"), "DynamoDB table name")
	flag.StringVar(&cfg.CognitoUserPoolID, "cognito-user-pool-id", getenv("VPN_AUTH_COGNITO_USER_POOL_ID", ""), "Cognito User Pool ID")
	flag.StringVar(&cfg.LocalStackEndpoint, "localstack-endpoint", getenv("LOCALSTACK_ENDPOINT", ""), "LocalStack endpoint (e.g. http://localhost:4566)")
	flag.BoolVar(&cfg.UseLocalMocks, "use-local-mocks", getBool("VPN_AUTH_USE_LOCAL_MOCKS", false), "use in-memory store and static identity checker instead of AWS (local dev only)")
	flag.BoolVar(&cfg.LocalIdentity, "local-identity", getBool("VPN_AUTH_LOCAL_IDENTITY", false), "use static identity checker instead of Cognito, but keep real DynamoDB (local dev only)")

	flag.Parse()

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var problems []string
	if c.ManagementSocket == "" {
		problems = append(problems, "management-socket is required")
	}
	if c.ManagementPasswordFile == "" {
		problems = append(problems, "management-password-file is required")
	}
	if c.APIGatewayURL == "" {
		problems = append(problems, "api-gateway-url is required")
	}
	if !c.UseLocalMocks {
		if c.HMACSecret == "" && c.HMACSecretARN == "" {
			problems = append(problems, "either hmac-secret or hmac-secret-arn is required")
		}
		if c.CognitoUserPoolID == "" && !c.LocalIdentity {
			problems = append(problems, "cognito-user-pool-id is required (or set --local-identity for local dev)")
		}
	} else {
		if c.HMACSecret == "" {
			problems = append(problems, "hmac-secret is required when using local mocks")
		}
	}
	if c.PollInterval <= 0 {
		problems = append(problems, "poll-interval must be > 0")
	}
	if c.HandWindow <= 0 {
		problems = append(problems, "hand-window must be > 0")
	}
	if c.ReconnectMaxInterval <= 0 {
		problems = append(problems, "reconnect-max-interval must be > 0")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		panic(fmt.Sprintf("invalid duration in %s: %v", key, err))
	}
	return d
}
