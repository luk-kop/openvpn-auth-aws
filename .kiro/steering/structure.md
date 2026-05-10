# Project Structure

```
openvpn-auth-aws/
├── .github/       # CI/CD workflows, Dependabot, PR labeler
├── cmd/
│   ├── openvpn-auth-daemon/  # Main binary entry point
│   ├── mgmt-mock/            # OpenVPN management socket simulator (dev/test)
│   └── alb-mock/             # ALB + Cognito authenticate action simulator (dev/test)
├── internal/
│   ├── app/        # Daemon lifecycle, event loop, management socket reconnection
│   ├── auth/       # Core auth orchestration, session store, state blob signing, reauth cache
│   ├── callback/   # HTTP server for GET /callback and GET /healthz, embedded HTML templates
│   ├── cognito/    # ALB public key fetching, JWT validation, user group checks
│   ├── config/     # CLI flags + VPN_AUTH_* env vars, validation
│   ├── metrics/    # CloudWatch EMF metrics
│   ├── mgmt/       # OpenVPN management socket protocol (parser, events, command writer, client)
│   └── secrets/    # HMAC signing + Secrets Manager fetcher for the HMAC secret
├── lambda-router/ # Separate Go module: Lambda proxy for multi-instance EC2 callback routing
│   ├── main.go
│   ├── main_test.go
│   └── templates/ # Embedded HTML (error page)
├── terraform/     # AWS infrastructure (modules: alb, cognito, lambda-router, nlb, vpn-server)
├── scripts/       # PKI management script (pki.sh)
├── pki/           # Generated PKI artifacts (CA, server/client certs, tls-crypt key, ta.key)
│   └── clients/   # Per-client .crt/.key/.ovpn output
├── docs/          # Architecture, configuration, security, testing, lambda-router, pki docs
├── notes/         # Design notes and architecture explorations
└── lab/           # Docker Compose stack(s), PKI setup scripts, test configs
    ├── docker-compose.yml               # Single-socket lab
    ├── docker-compose.multisocket.yml   # OpenVPN 2.7 multi-socket lab (UDP 1194 + TCP 1195)
    ├── setup.sh / setup-multisocket.sh  # PKI + compose env bootstrap
    └── run-multisocket-verification.sh  # Reauth/renegotiation verification harness
```

## Key Files

- `internal/auth/types.go` — all shared interfaces (`IdentityChecker`, `StateSigner`, `Metrics`, `DecisionSink`, `AckDecisionSink`, `AuthSuccessTracker`) and domain types (`PendingSession`, `Decision`, `DecisionType`, `SessionStatus`, `ALBClaims`, `IdentityResult`)
- `internal/auth/handler.go` — central auth orchestration; handles `CLIENT:CONNECT`, `CLIENT:REAUTH`, `CLIENT:DISCONNECT`, `CLIENT:ESTABLISHED`
- `internal/auth/sessions.go` — in-memory session store with TTL reaper
- `internal/auth/state.go` — HMAC-signed state blob encode/decode (`StatePayload`: `SID`, `IAT`, `EXP`)
- `internal/auth/cache.go` — `ReauthCache` with TTL for caching `IdentityResult` during IdP outages
- `internal/callback/server.go` — `GET /callback` (ALB JWT validation, group check, session resolution) and `GET /healthz`
- `internal/callback/render.go` — HTML template loading (`//go:embed`), rendering with buffer-first pattern, plain text fallback
- `internal/callback/templates/` — embedded HTML templates (`success.html`, `error.html`) with inline CSS and dark mode
- `internal/cognito/albkeys.go` — fetches ALB EC public keys from `public-keys.auth.elb.{region}.amazonaws.com`
- `internal/cognito/client.go` — `Checker` (Cognito `AdminGetUser` + `AdminListGroupsForUser`) and `StaticChecker` (local dev mode)
- `internal/mgmt/parser.go` — OpenVPN management protocol line parser
- `internal/mgmt/events.go` — management event types
- `internal/mgmt/commands.go` — management command writer (client-auth, client-auth-nt, client-deny, client-pending-auth, client-kill)
- `internal/mgmt/client.go` — management socket connection, read loop, reconnection
- `internal/mgmt/status.go` — `status 3` parsing for session reconciliation
- `internal/app/daemon.go` — top-level daemon wiring, reconnect loop, graceful shutdown
- `internal/config/config.go` — single `Config` struct, all flags and env vars
- `internal/secrets/manager.go` — `FetchHMACSecret` loads the HMAC signing key from AWS Secrets Manager
- `internal/secrets/hmac.go` — in-process HMAC `StateSigner` implementation
- `lambda-router/main.go` — Lambda proxy for multi-instance EC2 callback routing

## Conventions

- All interfaces live in `internal/auth/types.go`; implementations are in their respective packages
- Dependency injection via constructor functions (`NewHandler`, `New`, etc.) — no globals
- Concurrency: `sync.Mutex` guards shared maps in `Handler`; goroutines communicate via channels
- Error handling: wrap errors with `fmt.Errorf("context: %w", err)`; log at the call site, return up the stack
- No third-party frameworks — stdlib `net/http`, `flag`, `log/slog`, `sync`, `context` throughout
- Tests are table-driven; use interfaces from `types.go` to inject fakes/stubs without mocking libraries
- If `--cognito-user-pool-id` is not set, the daemon uses a static identity checker automatically (local dev mode — no AWS credentials needed)
- `AckDecisionSink` is used when the caller needs confirmation that a management command was written (or failed) before proceeding
