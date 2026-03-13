package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
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
	HandWindow             time.Duration
	ReconnectMaxInterval   time.Duration
	ShutdownGracePeriod    time.Duration
	CheckGroupsOnReauth    bool
	ReauthCache            bool
	ReauthTimeout          time.Duration
	RenegInterval          time.Duration
	InstanceID             string

	// Auth timeout (callback flow)
	AuthTimeout  time.Duration
	CallbackPort int
	InstanceIP   string

	// Cognito token exchange
	CognitoTokenEndpoint string
	CognitoClientID      string
	CognitoRedirectURI   string
	CognitoIssuerURL     string

	// AWS configuration
	AWSRegion            string
	CognitoUserPoolID    string
	UseLocalMocks        bool
	LocalIdentity        bool
	SingleSessionPerUser bool
	EMFMetrics           bool
	EMFInterval          time.Duration
	LogFormat            string
}

func Parse() (Config, error) {
	cfg := Config{}
	var envErrors []string

	flag.StringVar(&cfg.ManagementSocket, "management-socket", getenv("VPN_AUTH_MANAGEMENT_SOCKET", "/run/openvpn/management.sock"), "path to the OpenVPN management unix socket")
	flag.StringVar(&cfg.ManagementPasswordFile, "management-password-file", getenv("VPN_AUTH_MANAGEMENT_PASSWORD_FILE", "/etc/openvpn/management-pw"), "file containing the management password")
	flag.StringVar(&cfg.APIGatewayURL, "api-gateway-url", getenv("VPN_AUTH_API_GATEWAY_URL", ""), "public API Gateway base URL without trailing slash")
	flag.StringVar(&cfg.HMACSecret, "hmac-secret", getenv("VPN_AUTH_HMAC_SECRET", ""), "HMAC secret for signing state values")
	flag.StringVar(&cfg.HMACSecretARN, "hmac-secret-arn", getenv("VPN_AUTH_HMAC_SECRET_ARN", ""), "AWS Secrets Manager ARN for HMAC secret (overrides --hmac-secret)")
	flag.StringVar(&cfg.RequiredGroup, "required-group", getenv("VPN_AUTH_REQUIRED_GROUP", ""), "required Cognito group for VPN access")
	flag.BoolVar(&cfg.CNCrossCheck, "cn-cross-check", getBool("VPN_AUTH_CN_CROSS_CHECK", true), "enable CN cross-check in Lambda callback")
	flag.DurationVar(&cfg.HandWindow, "hand-window", getDurationOrCollect("VPN_AUTH_HAND_WINDOW", 300*time.Second, &envErrors), "pending auth timeout (must match OpenVPN server hand-window)")
	flag.DurationVar(&cfg.ReconnectMaxInterval, "reconnect-max-interval", getDurationOrCollect("VPN_AUTH_RECONNECT_MAX_INTERVAL", 5*time.Second, &envErrors), "max backoff between management socket reconnect attempts")
	flag.DurationVar(&cfg.ShutdownGracePeriod, "shutdown-grace-period", getDurationOrCollect("VPN_AUTH_SHUTDOWN_GRACE_PERIOD", 300*time.Second, &envErrors), "grace period for shutdown")
	flag.BoolVar(&cfg.CheckGroupsOnReauth, "check-groups-on-reauth", getBool("VPN_AUTH_CHECK_GROUPS_ON_REAUTH", false), "check required group during CLIENT:REAUTH")
	flag.BoolVar(&cfg.ReauthCache, "reauth-cache", getBool("VPN_AUTH_REAUTH_CACHE", false), "allow cached reauth decisions during identity provider outage")
	flag.DurationVar(&cfg.ReauthTimeout, "reauth-timeout", getDurationOrCollect("VPN_AUTH_REAUTH_TIMEOUT", 5*time.Second, &envErrors), "timeout for Cognito calls during CLIENT:REAUTH")
	flag.DurationVar(&cfg.RenegInterval, "reneg-interval", getDurationOrCollect("VPN_AUTH_RENEG_INTERVAL", 3600*time.Second, &envErrors), "OpenVPN reneg-sec value (for reauth cache TTL calculation)")
	flag.StringVar(&cfg.InstanceID, "instance-id", getenv("VPN_AUTH_INSTANCE_ID", "local-dev"), "instance identifier used in EMF metrics")

	// Auth timeout and callback
	flag.DurationVar(&cfg.AuthTimeout, "auth-timeout", getDurationOrCollect("VPN_AUTH_AUTH_TIMEOUT", 270*time.Second, &envErrors), "timeout for WebAuth callback flow (should be hand-window minus ~30s)")
	flag.IntVar(&cfg.CallbackPort, "callback-port", getIntOrCollect("VPN_AUTH_CALLBACK_PORT", 8080, &envErrors), "port for callback HTTP server")
	flag.StringVar(&cfg.InstanceIP, "instance-ip", getenv("VPN_AUTH_INSTANCE_IP", ""), "instance IP for callback URL (auto-detect from EC2 metadata if empty)")

	// Cognito token exchange
	flag.StringVar(&cfg.CognitoTokenEndpoint, "cognito-token-endpoint", getenv("VPN_AUTH_COGNITO_TOKEN_ENDPOINT", ""), "Cognito token endpoint URL")
	flag.StringVar(&cfg.CognitoClientID, "cognito-client-id", getenv("VPN_AUTH_COGNITO_CLIENT_ID", ""), "Cognito app client ID")
	flag.StringVar(&cfg.CognitoRedirectURI, "cognito-redirect-uri", getenv("VPN_AUTH_COGNITO_REDIRECT_URI", ""), "OAuth2 redirect URI")
	flag.StringVar(&cfg.CognitoIssuerURL, "cognito-issuer-url", getenv("VPN_AUTH_COGNITO_ISSUER_URL", ""), "Cognito issuer URL for JWT validation")

	// AWS configuration
	flag.StringVar(&cfg.AWSRegion, "aws-region", getenv("AWS_REGION", "eu-west-1"), "AWS region")
	flag.StringVar(&cfg.CognitoUserPoolID, "cognito-user-pool-id", getenv("VPN_AUTH_COGNITO_USER_POOL_ID", ""), "Cognito User Pool ID")
	flag.BoolVar(&cfg.UseLocalMocks, "use-local-mocks", getBool("VPN_AUTH_USE_LOCAL_MOCKS", false), "use in-memory store and static identity checker instead of AWS (local dev only)")
	flag.BoolVar(&cfg.LocalIdentity, "local-identity", getBool("VPN_AUTH_LOCAL_IDENTITY", false), "use static identity checker instead of Cognito (local dev only)")
	flag.BoolVar(&cfg.SingleSessionPerUser, "single-session-per-user", getBool("VPN_AUTH_SINGLE_SESSION_PER_USER", true), "enforce one active VPN session per certificate CN")
	flag.BoolVar(&cfg.EMFMetrics, "emf-metrics", getBool("VPN_AUTH_EMF_METRICS", false), "emit CloudWatch EMF metrics to stdout")
	flag.DurationVar(&cfg.EMFInterval, "emf-interval", getDurationOrCollect("VPN_AUTH_EMF_INTERVAL", 10*time.Second, &envErrors), "interval for EMF heartbeat metrics (0 to disable heartbeat only)")
	flag.StringVar(&cfg.LogFormat, "log-format", getenv("VPN_AUTH_LOG_FORMAT", "text"), "log output format: text or json")

	flag.Parse()

	if len(envErrors) > 0 {
		return Config{}, fmt.Errorf("invalid environment variables: %s", strings.Join(envErrors, "; "))
	}
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
		if c.CognitoTokenEndpoint == "" {
			problems = append(problems, "cognito-token-endpoint is required")
		}
		if c.CognitoClientID == "" {
			problems = append(problems, "cognito-client-id is required")
		}
		if c.CognitoRedirectURI == "" {
			problems = append(problems, "cognito-redirect-uri is required")
		}
	} else {
		if c.HMACSecret == "" {
			problems = append(problems, "hmac-secret is required when using local mocks")
		}
	}
	if c.HandWindow <= 0 {
		problems = append(problems, "hand-window must be > 0")
	}
	if c.ReconnectMaxInterval <= 0 {
		problems = append(problems, "reconnect-max-interval must be > 0")
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		problems = append(problems, fmt.Sprintf("log-format must be 'text' or 'json', got %q", c.LogFormat))
	}
	if c.AuthTimeout >= c.HandWindow {
		slog.Warn("auth-timeout should be less than hand-window to ensure AUTH_FAILED reaches the client before it self-restarts", "auth_timeout", c.AuthTimeout, "hand_window", c.HandWindow)
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

func getDurationOrCollect(key string, fallback time.Duration, errs *[]string) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("invalid duration in %s: %v", key, err))
		return fallback
	}
	return d
}

func getIntOrCollect(key string, fallback int, errs *[]string) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		*errs = append(*errs, fmt.Sprintf("invalid int in %s: %v", key, err))
		return fallback
	}
	return n
}
