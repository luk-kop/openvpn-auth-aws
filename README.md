# OpenVPN Auth Daemon

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Cognito-FF9900?logo=amazonaws&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)

Go daemon that authenticates OpenVPN clients via browser-based OIDC (AWS Cognito). Connects to the OpenVPN management socket, receives client events, and drives authentication through an ALB with a Cognito authenticate action — no Lambda or API Gateway required.

## Features

- Browser-based OIDC authentication via WebAuth (`WEB_AUTH::` URL)
- ALB JWT validation (ES256) — ALB handles the full OIDC flow and forwards signed `x-amzn-oidc-*` headers
- Two independent daemons per EC2 (UDP + TCP), each with its own callback port and session store
- `/healthz` endpoint for ALB target group health checks and EIP association gating
- Reauth on TLS renegotiation with Cognito user lookup (+ optional cache for IdP outages)
- Configurable single-session-per-user enforcement (`--single-session-per-user`)
- CN cross-check: certificate CN must match OIDC email claim (`--cn-cross-check`)
- Structured logging via `log/slog` with text/JSON output (`--log-format`)
- Optional CloudWatch EMF metrics (`--emf-metrics`)
- Graceful shutdown with in-flight session draining

## Quick Start

### Full Docker Stack

```bash
make stack-up                              # start OpenVPN + daemon + alb-mock
sudo openvpn --config lab/client.ovpn      # connect test client
docker compose -f lab/docker-compose.yml logs -f daemon  # view logs
make stack-down                            # stop
```

### Manual Testing with mgmt-mock

```bash
# Terminal 1: OpenVPN management socket simulator
make run-mgmt-mock

# Terminal 2: daemon (local dev mode — no ALB ARN, groups from claims)
make run-daemon

# Terminal 3: ALB + Cognito authenticate action simulator
make run-alb-mock
```

In mgmt-mock terminal: `connect 3 john@example.com`, `reauth 3 john@example.com`, `disconnect 3`.

## Build & Test

```bash
make build          # build all binaries
make test           # unit tests (go test -v -short ./...)
```

## Layout

```text
openvpn-auth-aws/
├── cmd/
│   ├── openvpn-auth-daemon/  # Main entry point
│   ├── mgmt-mock/            # OpenVPN management interface mock
│   └── alb-mock/             # ALB + Cognito authenticate action mock
├── internal/
│   ├── app/       # Daemon lifecycle, event loop, management socket reconnection
│   ├── auth/      # Auth orchestration, session store, state blob signing
│   ├── callback/  # HTTP server for GET /callback and GET /healthz, HTML templates
│   ├── cognito/   # ALB public key fetching, JWT validation, user group checks
│   ├── config/    # CLI flags + env vars (VPN_AUTH_* prefix)
│   ├── metrics/   # CloudWatch EMF metrics
│   ├── mgmt/      # OpenVPN management socket protocol (parser + commands)
│   └── secrets/   # HMAC signing
├── docs/          # Documentation
└── lab/           # Docker compose stack, PKI setup, test configs
```

## Documentation

- [Configuration](docs/configuration.md) — all flags, env vars, logging, EMF metrics
- [Architecture](docs/architecture.md) — auth flow, ALB JWT validation, healthz, EIP association, session lifecycle
- [Architecture Design](docs/architecture-design.md) — detailed design doc with infrastructure diagrams, instance replacement, local dev setup
- [PKI](docs/pki.md) — certificate management with `scripts/pki.sh`
- [OpenVPN Server](docs/openvpn-server.md) — required directives, verb levels, UDP disconnect behavior, client config
- [Testing](docs/testing.md) — test strategy, local and AWS modes, CI/CD
- [Troubleshooting](docs/troubleshooting.md) — useful commands, known issues, debugging auth flow
- [Security Issues](docs/security-issues.md) — known issues, fixes, rejected false positives
