# OpenVPN Auth Daemon

![Go](https://img.shields.io/badge/Go-1.26.1-00ADD8?logo=go&logoColor=white)
![OpenVPN](https://img.shields.io/badge/OpenVPN_CE-2.6.19-EA7E20?logo=openvpn&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Cognito-FF9900?logo=amazonaws&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)

Go daemon that authenticates OpenVPN clients via browser-based OIDC (AWS Cognito). Connects to the OpenVPN management socket, receives client events, and drives authentication through an ALB with a Cognito authenticate action. Includes an optional Lambda Router for multi-instance EC2 deployments.

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

### Prerequisites

- Docker + Docker Compose
- `make`
- Go 1.26.x
- OpenVPN client (`openvpn`) for the full-stack test flow

Choose one of these local workflows:

- Use **Full Docker Stack** for the fastest end-to-end validation.
- Use **Manual Testing with mgmt-mock** when iterating on daemon/auth logic without Docker.

### Full Docker Stack

Starts OpenVPN, the auth daemon, and `alb-mock`. On the first run, PKI assets are generated automatically.

```bash
make stack-up                              # start OpenVPN + daemon + alb-mock
sudo openvpn --config lab/client.ovpn      # connect test client
docker compose -f lab/docker-compose.yml logs -f daemon  # view logs
make stack-down                            # stop
```

Expected result: the OpenVPN client opens the browser-based auth flow, `alb-mock` forwards the callback to the daemon, and the VPN session is authenticated.

### Manual Testing with mgmt-mock

Runs the auth loop locally without Docker or a real OpenVPN server.

```bash
# Terminal 1: OpenVPN management socket simulator
make run-mgmt-mock

# Terminal 2: daemon (local dev mode — no ALB ARN, groups from claims)
make run-daemon

# Terminal 3: ALB + Cognito authenticate action simulator
make run-alb-mock
```

In mgmt-mock terminal: `connect 3 john@example.com`, `reauth 3 john@example.com`, `disconnect 3`.

Expected result: the daemon emits a `WEB_AUTH` URL, the browser callback is processed locally, and the mocked client is accepted or rejected based on the auth flow.

## Build & Test

```bash
make build          # build all binaries (daemon, mgmt-mock, alb-mock)
make build-lambda   # build Lambda Router package (outputs lambda-router/lambda.zip)
make test           # unit tests (go test -v -short ./...)
```

## Layout

```text
openvpn-auth-aws/
├── .github/       # CI/CD workflows, Dependabot, PR labeler
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
├── lambda-router/ # Go Lambda proxy for multi-instance EC2 callback routing
├── terraform/     # AWS infrastructure (modules: alb, cognito, lambda-router, nlb, vpn-server)
├── scripts/       # PKI management script (pki.sh)
├── pki/           # Generated PKI artifacts (CA, server/client certs, TLS auth key)
├── docs/          # Documentation
└── lab/           # Docker compose stack, PKI setup, test configs
```

## Documentation

- [Configuration](docs/configuration.md) — all flags, env vars, logging, EMF metrics
- [Architecture](docs/architecture.md) — auth flow, ALB JWT validation, healthz, EIP association, session lifecycle
- [ALB Authenticate Users](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html) — AWS docs on ALB Cognito authenticate action
- [Architecture Design](docs/architecture-design.md) — detailed design doc with infrastructure diagrams, instance replacement, local dev setup
- [PKI](docs/pki.md) — certificate management with `scripts/pki.sh`
- [OpenVPN Server](docs/openvpn-server.md) — required directives, verb levels, UDP disconnect behavior, client config
- [Testing](docs/testing.md) — test strategy, local and AWS modes, CI/CD
- [Troubleshooting](docs/troubleshooting.md) — useful commands, known issues, debugging auth flow
- [Lambda Router](docs/lambda-router-proxy.md) — Go Lambda proxy for multi-instance EC2 deployments: path-based IP routing, VPC CIDR validation, security model
