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

	if cfg.CognitoUserPoolID == "" {
		identity = cognito.NewStaticChecker(cfg.CheckGroupsOnReauth)
		signer = secrets.NewStaticSigner(cfg.HMACSecret)
	} else {
		slog.Info("initializing AWS clients")
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.AWSRegion))
		if err != nil {
			slog.Error("aws config failed", "error", err)
			os.Exit(1)
		}

		identity = cognito.NewChecker(awsCfg, cfg.CognitoUserPoolID)
		signer = secrets.NewStaticSigner(cfg.HMACSecret)
	}

	handler := auth.NewHandler(cfg, sessions, identity, signer, m)

	// Create daemon first to get the command channel, then create callback server with DaemonSink.
	// The mgmtConnected closure reads the daemon's socketConnected atomic so /healthz reflects
	// live socket state without coupling the callback package to the app package.
	daemon := app.New(cfg, handler, nil, m)
	daemonSink := app.DaemonSink{CmdCh: daemon.CmdCh()}
	callbackSrv, err := callback.NewServer(
		sessions,
		signer,
		daemonSink,
		cfg,
		m,
		identity,
		daemon.SocketConnected,
	)
	if err != nil {
		slog.Error("callback server init failed", "error", err)
		os.Exit(1)
	}
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
