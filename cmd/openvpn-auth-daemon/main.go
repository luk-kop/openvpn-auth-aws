package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/config"

	"openvpn-auth-aws/internal/app"
	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/callback"
	"openvpn-auth-aws/internal/cognito"
	appconfig "openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/metrics"
	"openvpn-auth-aws/internal/secrets"
)

func main() {
	cfg, err := appconfig.Parse()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	setupLogging(cfg.LogFormat)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var metricsWriter io.Writer = os.Stdout
	if !cfg.EMFMetrics {
		metricsWriter = io.Discard
		slog.Info("EMF metrics disabled")
	}
	m := metrics.NewEmitter(metricsWriter, cfg.InstanceID)

	sessions := auth.NewSessionStore()
	sessions.StartReaper(ctx)

	var identity auth.IdentityChecker
	var signer auth.StateSigner
	var exchanger auth.TokenExchanger

	if cfg.UseLocalMocks {
		slog.Info("using local mocks", "aws", false)
		identity = cognito.NewStaticChecker(cfg.CheckGroupsOnReauth)
		signer = secrets.NewStaticSigner(cfg.HMACSecret)
		exchanger = cognito.NewStaticExchanger("mock@example.com", []string{"vpn-users"})
	} else {
		slog.Info("initializing AWS clients")
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.AWSRegion))
		if err != nil {
			slog.Error("aws config failed", "error", err)
			os.Exit(1)
		}

		if cfg.LocalIdentity {
			slog.Info("using static identity checker", "cognito", false)
			identity = cognito.NewStaticChecker(cfg.CheckGroupsOnReauth)
		} else {
			identity = cognito.NewChecker(awsCfg, cfg.CognitoUserPoolID)
		}

		if cfg.HMACSecretARN != "" {
			signer, err = secrets.NewSigner(awsCfg, cfg.HMACSecretARN)
			if err != nil {
				slog.Error("secrets manager init failed", "error", err)
				os.Exit(1)
			}
		} else {
			signer = secrets.NewStaticSigner(cfg.HMACSecret)
		}

		exchanger = cognito.NewExchanger(cfg.CognitoTokenEndpoint, cfg.CognitoClientID, cfg.CognitoIssuerURL)
	}

	// Auto-detect instance IP from EC2 metadata if not set
	if cfg.InstanceIP == "" {
		cfg.InstanceIP = detectInstanceIP(ctx)
	}

	handler := auth.NewHandler(cfg, sessions, identity, signer, m)

	// Create daemon first to get the command channel, then create callback server with DaemonSink
	daemon := app.New(cfg, handler, nil, m)
	daemonSink := app.DaemonSink{CmdCh: daemon.CmdCh()}
	callbackSrv := callback.NewServer(sessions, exchanger, signer, daemonSink, cfg, m)
	daemon.SetCallbackServer(callbackSrv)

	if err := daemon.Run(ctx); err != nil {
		slog.Error("daemon exited", "error", err)
		os.Exit(1)
	}
}

func setupLogging(format string) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{}
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func detectInstanceIP(ctx context.Context) string {
	// Try EC2 IMDS
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		slog.Warn("EC2 metadata unavailable, using 127.0.0.1")
		return "127.0.0.1"
	}

	// Use ec2imds client
	imdsClient := newIMDSClient(awsCfg)
	ip, err := imdsClient.getPublicIP(ctx)
	if err != nil {
		slog.Warn("EC2 metadata unavailable", "error", err, "fallback", "127.0.0.1")
		return "127.0.0.1"
	}
	slog.Info("detected instance IP", "ip", ip)
	return ip
}
