package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/config"

	"openvpn-auth-aws/internal/app"
	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/cognito"
	appconfig "openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/dynamo"
	"openvpn-auth-aws/internal/metrics"
	"openvpn-auth-aws/internal/secrets"
)

func main() {
	cfg, err := appconfig.Parse()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := metrics.NewEmitter(os.Stdout, cfg.InstanceID)

	var store auth.SessionStore
	var identity auth.IdentityChecker
	var signer auth.StateSigner

	// Use mocks for local dev, real AWS for production
	if cfg.UseLocalMocks {
		log.Println("Using local mocks (no AWS)")
		store = dynamo.NewMemoryStore()
		identity = cognito.NewStaticChecker(cfg.CheckGroupsOnReauth)
		signer = secrets.NewStaticSigner(cfg.HMACSecret)
	} else {
		log.Println("Initializing AWS clients")
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.AWSRegion))
		if err != nil {
			log.Fatalf("aws config: %v", err)
		}

		// Override endpoint for LocalStack
		if cfg.LocalStackEndpoint != "" {
			log.Printf("Using LocalStack endpoint: %s", cfg.LocalStackEndpoint)
			awsCfg.BaseEndpoint = &cfg.LocalStackEndpoint
		}

		store = dynamo.NewStore(awsCfg, cfg.DynamoDBTable)

		if cfg.LocalIdentity {
			log.Println("Using static identity checker (no Cognito)")
			identity = cognito.NewStaticChecker(cfg.CheckGroupsOnReauth)
		} else {
			identity = cognito.NewChecker(awsCfg, cfg.CognitoUserPoolID)
		}

		if cfg.HMACSecretARN != "" {
			signer, err = secrets.NewSigner(awsCfg, cfg.HMACSecretARN)
			if err != nil {
				log.Fatalf("secrets manager: %v", err)
			}
		} else {
			signer = secrets.NewStaticSigner(cfg.HMACSecret)
		}
	}

	handler := auth.NewHandler(cfg, store, identity, signer, m)
	daemon := app.New(cfg, handler, m)

	if err := daemon.Run(ctx); err != nil {
		log.Fatalf("daemon exited: %v", err)
	}
}
