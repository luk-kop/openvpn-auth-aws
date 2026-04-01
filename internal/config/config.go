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
	HMACSecret             string
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

	// ALB fields
	CallbackURL         string // --callback-url / VPN_AUTH_CALLBACK_URL
	ALBARN              string // --alb-arn / VPN_AUTH_ALB_ARN
	CognitoSkipReauth   bool   // --cognito-skip-reauth / VPN_AUTH_COGNITO_SKIP_REAUTH
	CognitoGroupsClaims bool   // --cognito-groups-from-claims / VPN_AUTH_COGNITO_GROUPS_FROM_CLAIMS

	// Cognito identity
	CognitoIssuerURL  string
	CognitoUserPoolID string

	// AWS configuration
	ALBPublicKeyBaseURL  string
	AWSRegion            string
	SingleSessionPerUser bool
	EMFMetrics           bool
	EMFInterval          time.Duration
	LogFormat            string

	// HTML templates
	TemplatesDir string
	ServerName   string
}

func Parse() (Config, error) {
	cfg := Config{}
	var envErrors []string

	flag.StringVar(&cfg.ManagementSocket, "management-socket", getenv("VPN_AUTH_MANAGEMENT_SOCKET", "/run/openvpn/management.sock"), "path to the OpenVPN management unix socket")
	flag.StringVar(&cfg.ManagementPasswordFile, "management-password-file", getenv("VPN_AUTH_MANAGEMENT_PASSWORD_FILE", "/etc/openvpn/management-pw"), "file containing the management password")
	flag.StringVar(&cfg.HMACSecret, "hmac-secret", getenv("VPN_AUTH_HMAC_SECRET", ""), "HMAC secret for signing state values")
	flag.StringVar(&cfg.RequiredGroup, "required-group", getenv("VPN_AUTH_REQUIRED_GROUP", ""), "required Cognito group for VPN access")
	flag.BoolVar(&cfg.CNCrossCheck, "cn-cross-check", getBool("VPN_AUTH_CN_CROSS_CHECK", true), "enable CN cross-check against ALB JWT email claim")
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

	// ALB flags
	flag.StringVar(&cfg.CallbackURL, "callback-url", getenv("VPN_AUTH_CALLBACK_URL", ""), "full callback URL including path (e.g. https://vpn-auth.example.com/callback/01/udp); daemon appends ?state=...")
	flag.StringVar(&cfg.ALBARN, "alb-arn", getenv("VPN_AUTH_ALB_ARN", ""), "ALB ARN for validating the signer field in ALB JWTs (omit to skip JWT signature validation in dev/test)")
	flag.BoolVar(&cfg.CognitoSkipReauth, "cognito-skip-reauth", getBool("VPN_AUTH_COGNITO_SKIP_REAUTH", false), "skip Cognito AdminGetUser call on CLIENT:REAUTH (dev/test only)")
	flag.BoolVar(&cfg.CognitoGroupsClaims, "cognito-groups-from-claims", getBool("VPN_AUTH_COGNITO_GROUPS_FROM_CLAIMS", false), "read group membership from ALB JWT claims instead of AdminListGroupsForUser")

	// Cognito identity
	flag.StringVar(&cfg.CognitoIssuerURL, "cognito-issuer-url", getenv("VPN_AUTH_COGNITO_ISSUER_URL", ""), "Cognito issuer URL for JWT validation")
	flag.StringVar(&cfg.CognitoUserPoolID, "cognito-user-pool-id", getenv("VPN_AUTH_COGNITO_USER_POOL_ID", ""), "Cognito User Pool ID")

	// AWS configuration
	flag.StringVar(&cfg.ALBPublicKeyBaseURL, "alb-public-key-base-url", getenv("VPN_AUTH_ALB_PUBLIC_KEY_BASE_URL", ""), "base URL for ALB public key endpoint (default: https://public-keys.auth.elb.{region}.amazonaws.com)")
	flag.StringVar(&cfg.AWSRegion, "aws-region", getenv("AWS_REGION", "eu-west-1"), "AWS region")
	flag.BoolVar(&cfg.SingleSessionPerUser, "single-session-per-user", getBool("VPN_AUTH_SINGLE_SESSION_PER_USER", true), "enforce one active VPN session per certificate CN")
	flag.BoolVar(&cfg.EMFMetrics, "emf-metrics", getBool("VPN_AUTH_EMF_METRICS", false), "emit CloudWatch EMF metrics to stdout")
	flag.DurationVar(&cfg.EMFInterval, "emf-interval", getDurationOrCollect("VPN_AUTH_EMF_INTERVAL", 10*time.Second, &envErrors), "interval for EMF heartbeat metrics (0 to disable heartbeat only)")
	flag.StringVar(&cfg.LogFormat, "log-format", getenv("VPN_AUTH_LOG_FORMAT", "text"), "log output format: text or json")
	flag.StringVar(&cfg.TemplatesDir, "templates-dir", getenv("VPN_AUTH_TEMPLATES_DIR", ""), "path to custom HTML templates (overrides built-in)")
	flag.StringVar(&cfg.ServerName, "server-name", getenv("VPN_AUTH_SERVER_NAME", ""), "human-readable server name exposed to HTML templates")

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
	if c.CallbackURL == "" {
		problems = append(problems, "callback-url is required")
	} else if !strings.HasPrefix(c.CallbackURL, "https://") {
		if c.ALBARN != "" {
			problems = append(problems, "callback-url must use https:// scheme in production (alb-arn is set)")
		} else {
			slog.Warn("callback-url does not use https:// — acceptable for local dev only", "callback_url", c.CallbackURL)
		}
	}
	if c.ALBARN != "" {
		if c.CognitoUserPoolID == "" {
			problems = append(problems, "cognito-user-pool-id is required when alb-arn is set")
		}
		if c.CognitoIssuerURL == "" {
			problems = append(problems, "cognito-issuer-url is required when alb-arn is set (prevents cross-pool JWT acceptance)")
		}
	}
	if c.CognitoUserPoolID == "" && !c.CognitoGroupsClaims && c.RequiredGroup != "" {
		problems = append(problems, "cognito-user-pool-id is required when required-group is set without cognito-groups-from-claims")
	}
	if c.CognitoUserPoolID == "" && c.ALBARN == "" {
		slog.Info("local dev mode: cognito-user-pool-id and alb-arn not set, using static identity checker")
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
	if c.HMACSecret != "" && len(c.HMACSecret) < 16 {
		problems = append(problems, fmt.Sprintf("hmac-secret must be at least 16 bytes, got %d", len(c.HMACSecret)))
	}
	// Estimate whether the WEB_AUTH URL will fit in the 229-byte OpenVPN CE
	// INFOMSG buffer. The URL is: OPEN_URL:<callback-url>?state=<blob>
	// State blob is ~128 bytes. Warn early if the callback URL is too long.
	if c.CallbackURL != "" {
		// 9 ("OPEN_URL:") + len(url) + 7 ("?state=") + ~128 (worst-case state blob)
		estimatedLen := 9 + len(c.CallbackURL) + 7 + 128
		if estimatedLen > 229 {
			slog.Warn("callback-url may be too long for OpenVPN CE clients — WEB_AUTH URL may exceed the 229-byte INFOMSG buffer limit, causing silent auth failure; consider using a shorter URL",
				"callback_url_len", len(c.CallbackURL),
				"estimated_webauth_len", estimatedLen,
				"max", 229)
		}
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
