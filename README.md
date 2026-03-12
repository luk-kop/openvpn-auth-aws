# OpenVPN Auth Daemon

![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Cognito-FF9900?logo=amazonaws&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)

Go daemon that authenticates OpenVPN clients via browser-based OIDC (AWS Cognito). Connects to the OpenVPN management socket, receives client events, and orchestrates an OAuth2/PKCE flow through a Lambda-backed API Gateway.

## Features

- Browser-based OIDC authentication via WebAuth (`WEB_AUTH::` URL)
- OAuth2/PKCE flow with JWT validation (email, nonce, groups)
- Reauth on TLS renegotiation with Cognito user lookup (+ optional cache for IdP outages)
- Configurable single-session-per-user enforcement (`--single-session-per-user`)
- CN cross-check: certificate CN must match OIDC email claim (`--cn-cross-check`)
- Structured logging via `log/slog` with text/JSON output (`--log-format`)
- Optional CloudWatch EMF metrics (`--emf-metrics`)
- Graceful shutdown with in-flight session draining
- Local dev mode with mocks (`--use-local-mocks`)

## Quick Start

### Full Docker Stack

```bash
make stack-up                              # start OpenVPN + daemon + lambda-mock
sudo openvpn --config lab/client.ovpn      # connect test client
docker compose -f lab/docker-compose.yml logs -f daemon  # view logs
make stack-down                            # stop
```

### Manual Testing with mgmt-mock

```bash
# Terminal 1: OpenVPN management socket simulator
make run-mgmt-mock

# Terminal 2: daemon with local mocks
make run-daemon

# Terminal 3: OAuth2 simulator
make run-lambda-mock
```

In mgmt-mock terminal: `connect 3 john@example.com`, `reauth 3 john@example.com`, `disconnect 3`.

## Build & Test

```bash
make build          # build all binaries
make test           # unit tests (go test -v -short ./...)
make test-integration  # integration tests with LocalStack
```

## Layout

```text
openvpn-auth-aws/
├── cmd/
│   ├── openvpn-auth-daemon/  # Main entry point
│   ├── mgmt-mock/            # OpenVPN management interface mock
│   └── lambda-mock/          # Lambda /auth + /callback mock
├── internal/
│   ├── app/       # Daemon lifecycle, event loop, management socket reconnection
│   ├── auth/      # Auth orchestration, session store, state blob signing
│   ├── callback/  # HTTP server for POST /callback from Lambda
│   ├── cognito/   # Cognito token exchange, JWT/JWKS validation, user checks
│   ├── config/    # CLI flags + env vars (VPN_AUTH_* prefix)
│   ├── metrics/   # CloudWatch EMF metrics
│   ├── mgmt/      # OpenVPN management socket protocol (parser + commands)
│   └── secrets/   # HMAC signing (static secret or Secrets Manager)
├── docs/          # Documentation
└── lab/           # Docker compose stack, PKI setup, test configs
```

## Documentation

- [Configuration](docs/configuration.md) — all flags, env vars, logging, EMF metrics
- [Architecture](docs/architecture.md) — auth flow, session lifecycle, eviction, reauth
- [OpenVPN Server](docs/openvpn-server.md) — required directives, verb levels, UDP disconnect behavior, client config
- [Testing](docs/testing.md) — test strategy, LocalStack, CI/CD
- [Security Issues](docs/security-issues.md) — known issues, fixes, rejected false positives
- [Lambda Auth Token](docs/lambda-auth-token.md) — HMAC token implementation for callback verification
