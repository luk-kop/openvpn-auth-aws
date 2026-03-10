# OpenVPN Auth Daemon

![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-DynamoDB%20%7C%20Cognito-FF9900?logo=amazonaws&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)

Go implementation of the OpenVPN management-interface daemon described in the project docs.

## Features

- Unix management socket connection with password auth
- Management event parsing for `CLIENT:CONNECT`, `CLIENT:REAUTH`, `CLIENT:DISCONNECT`
- Serialized command writer
- Connect flow orchestration with browser-based OIDC
- Reauth flow with Cognito AdminGetUser (or static checker in local dev)
- In-memory session store for local development (`--use-local-mocks`)
- AWS DynamoDB integration for production
- AWS Cognito integration for user verification
- AWS Secrets Manager for HMAC secret rotation
- EMF metric emission to stdout

## Layout

```text
openvpn-auth-aws/
├── cmd/
│   ├── openvpn-auth-daemon/  # Main entry point
│   ├── mgmt-mock/            # OpenVPN management interface mock
│   └── lambda-mock/          # Lambda /auth + /callback mock (HTTP)
├── internal/
│   ├── app/                  # Daemon orchestration
│   ├── auth/                 # Auth flow logic + interfaces
│   ├── cognito/              # Cognito client (real + mock)
│   ├── config/               # Configuration parsing
│   ├── dynamo/               # DynamoDB client (real + mock)
│   ├── metrics/              # CloudWatch EMF metrics
│   ├── mgmt/                 # OpenVPN management interface
│   └── secrets/              # Secrets Manager client (real + mock)
└── lab/
    ├── docker-compose.yml    # Full local stack
    ├── setup.sh              # PKI + config generator (run once)
    ├── Dockerfile.openvpn    # OpenVPN container image
    ├── Dockerfile.lambda-mock # lambda-mock container image
    ├── localstack-init/      # LocalStack DynamoDB init scripts
    └── openvpn-data/         # Generated server config + certs (gitignored)
```

## Running Locally

### Quick Start — Full Stack

```bash
# One-time setup: generates PKI and OpenVPN configs
make setup

# Start everything (runs setup automatically if configs are missing)
make stack-up

# Connect test VPN client
sudo openvpn --config lab/client.ovpn

# View daemon logs
docker compose -f lab/docker-compose.yml logs -f daemon

# Stop everything
make stack-down
```

This starts:

- OpenVPN server on UDP 1194
- Auth daemon connected to OpenVPN management socket
- LocalStack (DynamoDB only)
- lambda-mock on HTTP 8080

**Architecture:**

```
┌─────────────────────┐
│  OpenVPN Container  │
│  UDP 1194           │
│  management.sock    ├──┐
└─────────────────────┘  │ shared volume
                         │ /run/openvpn
┌─────────────────────┐  │
│  Daemon Container   │◄─┘
│  Go application     │
└──────────┬──────────┘
           │
     ┌─────┴──────┐
     ▼            ▼
┌─────────┐  ┌──────────────┐
│LocalStack│  │ lambda-mock  │
│DynamoDB  │  │ HTTP :8080   │
└─────────┘  └──────────────┘
```

**Auth flow:**

1. VPN client connects → OpenVPN sends `CLIENT:CONNECT` to management socket
2. Daemon reads event → creates session in DynamoDB, sends `client-pending-auth` with WebAuth URL
3. OpenVPN forwards URL to client
4. Client opens browser → lambda-mock handles `/auth` and `/callback`
5. Daemon polls DynamoDB for status change
6. Daemon sends `client-auth` or `client-deny` to OpenVPN

### Manual Testing with mgmt-mock

`mgmt-mock` simulates the OpenVPN management interface on a Unix socket,
so you can test the daemon without a real OpenVPN server.

**Terminal 1** — start the mock:

```bash
go run ./cmd/mgmt-mock
# Tip: use rlwrap for command history (sudo apt install rlwrap):
rlwrap go run ./cmd/mgmt-mock
```

**Terminal 2** — start the daemon:

```bash
go test -v -short ./...  # verify first
go run ./cmd/openvpn-auth-daemon \
  --use-local-mocks \
  --hmac-secret test-secret \
  --api-gateway-url http://localhost:8080
```

Commands in Terminal 1:

```text
connect 3 john@example.com     — CLIENT:CONNECT (CID=3, KID defaults to 1)
reauth  3 john@example.com     — CLIENT:REAUTH
disconnect 3                   — CLIENT:DISCONNECT
connect 5 jane@example.com 2   — CLIENT:CONNECT with explicit KID=2
help                           — show available commands
quit                           — close connection
```

## Testing

```bash
# Unit tests (fast, no AWS)
make test

# Integration tests with LocalStack
make test-integration
```

## Build

```bash
make build
# or
go build -o openvpn-auth-daemon ./cmd/openvpn-auth-daemon
```

## Configuration

All flags can be set via environment variables with `VPN_AUTH_` prefix:

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--management-socket` | `VPN_AUTH_MANAGEMENT_SOCKET` | `/run/openvpn/management.sock` | Path to OpenVPN management socket |
| `--management-password-file` | `VPN_AUTH_MANAGEMENT_PASSWORD_FILE` | `/etc/openvpn/management-pw` | File containing management password |
| `--api-gateway-url` | `VPN_AUTH_API_GATEWAY_URL` | — | Public API Gateway base URL (no trailing slash) |
| `--hmac-secret` | `VPN_AUTH_HMAC_SECRET` | — | HMAC secret for signing state values (local dev) |
| `--hmac-secret-arn` | `VPN_AUTH_HMAC_SECRET_ARN` | — | Secrets Manager ARN for HMAC secret (production) |
| `--aws-region` | `AWS_REGION` | `eu-west-1` | AWS region |
| `--dynamodb-table` | `VPN_AUTH_DYNAMODB_TABLE` | `vpn-sessions` | DynamoDB table name |
| `--cognito-user-pool-id` | `VPN_AUTH_COGNITO_USER_POOL_ID` | — | Cognito User Pool ID |
| `--required-group` | `VPN_AUTH_REQUIRED_GROUP` | — | Required Cognito group for VPN access |
| `--use-local-mocks` | `VPN_AUTH_USE_LOCAL_MOCKS` | `false` | In-memory store + static identity (no AWS) |
| `--local-identity` | `VPN_AUTH_LOCAL_IDENTITY` | `false` | Static identity checker, real DynamoDB (local dev) |
| `--localstack-endpoint` | `LOCALSTACK_ENDPOINT` | — | LocalStack endpoint (e.g. `http://localhost:4566`) |
| `--poll-interval` | `VPN_AUTH_POLL_INTERVAL` | `2s` | Poll interval for pending auth sessions |
| `--hand-window` | `VPN_AUTH_HAND_WINDOW` | `5m` | Pending auth timeout |
| `--cn-cross-check` | `VPN_AUTH_CN_CROSS_CHECK` | `true` | Enable CN cross-check in Lambda callback |
| `--check-groups-on-reauth` | `VPN_AUTH_CHECK_GROUPS_ON_REAUTH` | `false` | Check required group during `CLIENT:REAUTH` |
| `--reauth-cache` | `VPN_AUTH_REAUTH_CACHE` | `false` | Allow cached reauth decisions during IdP outage |
| `--reauth-timeout` | `VPN_AUTH_REAUTH_TIMEOUT` | `5s` | Timeout for Cognito calls during `CLIENT:REAUTH` |
| `--instance-id` | `VPN_AUTH_INSTANCE_ID` | `local-dev` | Instance identifier used in EMF metrics |

See `--help` for the full list.
