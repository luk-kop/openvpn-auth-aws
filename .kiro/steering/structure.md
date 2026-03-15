# Project Structure

```
openvpn-auth-aws/
├── cmd/
│   ├── openvpn-auth-daemon/  # Main binary entry point
│   ├── mgmt-mock/            # OpenVPN management socket simulator (dev/test)
│   └── alb-mock/             # ALB + Cognito authenticate action simulator (dev/test)
├── internal/
│   ├── app/        # Daemon lifecycle, event loop, management socket reconnection
│   ├── auth/       # Core auth orchestration, session store, state blob signing
│   ├── callback/   # HTTP server for GET /callback and GET /healthz
│   ├── cognito/    # ALB public key fetching, JWKS validation, user group checks
│   ├── config/     # CLI flags + VPN_AUTH_* env vars, validation
│   ├── metrics/    # CloudWatch EMF metrics
│   ├── mgmt/       # OpenVPN management socket protocol (parser + command writer)
│   └── secrets/    # HMAC signing via static secret
├── docs/           # Architecture, configuration, security, testing docs
└── lab/            # Docker Compose stack, PKI setup scripts, test configs
```

## Key Files

- `internal/auth/types.go` — all shared interfaces (`IdentityChecker`, `StateSigner`, `Metrics`, `DecisionSink`) and domain types (`PendingSession`, `Decision`, `SessionStatus`, `ALBClaims`)
- `internal/auth/handler.go` — central auth orchestration; handles `CLIENT:CONNECT`, `CLIENT:REAUTH`, `CLIENT:DISCONNECT`, `CLIENT:ESTABLISHED`
- `internal/auth/sessions.go` — in-memory session store with TTL reaper
- `internal/auth/state.go` — HMAC-signed state blob encode/decode (`StatePayload`: `SID`, `IAT`, `EXP`)
- `internal/callback/server.go` — `GET /callback` (ALB JWT validation, group check, session resolution) and `GET /healthz`
- `internal/cognito/albkeys.go` — fetches ALB EC public keys from `public-keys.auth.elb.{region}.amazonaws.com`
- `internal/app/daemon.go` — top-level daemon wiring, reconnect loop, graceful shutdown
- `internal/config/config.go` — single `Config` struct, all flags and env vars

## Conventions

- All interfaces live in `internal/auth/types.go`; implementations are in their respective packages
- Dependency injection via constructor functions (`NewHandler`, `New`, etc.) — no globals
- Concurrency: `sync.Mutex` guards shared maps in `Handler`; goroutines communicate via channels
- Error handling: wrap errors with `fmt.Errorf("context: %w", err)`; log at the call site, return up the stack
- No third-party frameworks — stdlib `net/http`, `flag`, `log/slog`, `sync`, `context` throughout
- Tests are table-driven; use interfaces from `types.go` to inject fakes/stubs without mocking libraries
- If `--cognito-user-pool-id` is not set, the daemon uses a static identity checker automatically (local dev mode — no AWS credentials needed)
