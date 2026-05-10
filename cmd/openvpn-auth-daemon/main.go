package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

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

	setupLogging(cfg)

	if cfg.ManagementRawLog {
		slog.Warn("management raw logging enabled; lab/debug only, do not enable in production")
	}

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
	var awsCfg aws.Config
	var awsCfgLoaded bool

	loadAWSConfig := func() (aws.Config, error) {
		if awsCfgLoaded {
			return awsCfg, nil
		}
		slog.Info("initializing AWS clients")
		loaded, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.AWSRegion))
		if err != nil {
			return aws.Config{}, err
		}
		awsCfg = loaded
		awsCfgLoaded = true
		return awsCfg, nil
	}

	if cfg.HMACSecret != "" {
		var err error
		signer, err = secrets.NewStaticSigner(cfg.HMACSecret)
		if err != nil {
			slog.Error("invalid hmac-secret", "error", err)
			os.Exit(1)
		}
	} else if cfg.HMACSecretSecretID != "" {
		loaded, err := loadAWSConfig()
		if err != nil {
			slog.Error("aws config failed", "error", err)
			os.Exit(1)
		}
		secret, err := secrets.FetchHMACSecret(ctx, secretsmanager.NewFromConfig(loaded), cfg.HMACSecretSecretID)
		if err != nil {
			slog.Error("failed to fetch hmac secret", "secret_id", cfg.HMACSecretSecretID, "error", err)
			os.Exit(1)
		}
		signer, err = secrets.NewStaticSigner(secret)
		if err != nil {
			slog.Error("invalid hmac secret from Secrets Manager", "secret_id", cfg.HMACSecretSecretID, "error", err)
			os.Exit(1)
		}
		slog.Info("loaded hmac secret from Secrets Manager", "secret_id", cfg.HMACSecretSecretID)
	} else {
		slog.Info("no hmac-secret provided, generating random key")
		signer = secrets.NewRandomSigner()
	}

	if cfg.CognitoUserPoolID == "" {
		identity = cognito.NewStaticChecker(cfg.CheckRequiredGroupOnReauth)
	} else {
		loaded, err := loadAWSConfig()
		if err != nil {
			slog.Error("aws config failed", "error", err)
			os.Exit(1)
		}

		identity = cognito.NewChecker(loaded, cfg.CognitoUserPoolID)
	}

	handler := auth.NewHandler(cfg, sessions, identity, signer, m)

	// Create daemon first to get the command channel, then create callback server with DaemonSink.
	// The mgmtConnected closure reads the daemon's socketConnected atomic so /healthz reflects
	// live socket state without coupling the callback package to the app package.
	daemon := app.New(cfg, handler, sessions, nil, m)
	daemonSink := daemon.Sink()

	// Give the handler a daemon-level sink for authTimeout goroutines so that
	// timeout denials survive management socket reconnections.
	handler.SetTimeoutSink(daemonSink)
	callbackSrv, err := callback.NewServer(
		sessions,
		signer,
		daemonSink,
		handler,
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

func setupLogging(cfg appconfig.Config) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{}
	if cfg.ManagementRawLog {
		opts.Level = slog.LevelDebug
	}
	switch cfg.LogFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}
