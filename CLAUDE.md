# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
make build                  # Build all binaries (openvpn-auth-daemon, mgmt-mock, alb-mock)
make test                   # Unit tests: go test -v -short ./...
go test -v -short ./internal/auth/...  # Run tests for a single package
go vet ./...                # Static analysis
golangci-lint run           # Linter (also runs via pre-commit)
make clean                  # Remove binaries and test cache
```

## Local Development

Three-terminal setup without Docker:
- `make run-mgmt-mock` — simulates OpenVPN management socket at `/tmp/openvpn-mgmt.sock`
- `make run-daemon` — starts daemon in local dev mode (no AWS needed)
- `make run-alb-mock` — ALB + Cognito authenticate action simulator on `:8080`

In mgmt-mock terminal, type `connect <cid> <email>` / `reauth <cid> <email>` / `disconnect <cid>` to trigger events.

Full Docker stack: `make stack-up` (auto-runs PKI setup), then `sudo openvpn --config lab/client.ovpn`.

## Architecture

OpenVPN auth daemon that orchestrates browser-based OIDC flows with AWS Cognito. The daemon connects to OpenVPN's Unix management socket, receives client events, and drives authentication through an ALB with a Cognito authenticate action — no Lambda or API Gateway required.

**Auth flow:** CLIENT:CONNECT → daemon creates session + signs state blob → sends `client-pending-auth` with WebAuth URL → browser hits ALB → ALB runs Cognito authenticate action (OIDC) → ALB forwards authenticated GET `/callback` with `x-amzn-oidc-*` headers to daemon → daemon validates ALB JWT, checks groups → sends `client-auth` or `client-deny` to OpenVPN.

**Session lifecycle:** `SessionPending` → `SessionProcessing` → `SessionDone`/`SessionFailed`. By default, one active session per user (`--single-session-per-user`); new connects evict existing sessions (`client-deny` for pending, `client-kill` for established). Can be disabled to allow multiple concurrent sessions per CN.

**Key packages:**
- `internal/app/` — daemon lifecycle, event loop, management socket reconnection
- `internal/auth/` — core auth orchestration, session store with TTL reaper, state blob signing
- `internal/callback/` — HTTP server handling GET `/callback` (ALB-forwarded) and GET `/healthz`
- `internal/mgmt/` — OpenVPN management socket protocol (parser + command writer)
- `internal/cognito/` — ALB public key fetching, JWT validation (ES256), Cognito Admin API for user/group checks
- `internal/secrets/` — HMAC signing via static secret or AWS Secrets Manager
- `internal/config/` — CLI flags + env vars (`VPN_AUTH_*` prefix), validation

**Entry points:** `cmd/openvpn-auth-daemon/` (main daemon), `cmd/mgmt-mock/` (OpenVPN simulator), `cmd/alb-mock/` (ALB + Cognito mock).

## Pre-commit Hooks

Configured in `.pre-commit-config.yaml`: `golangci-lint run`, `go vet ./...`, `go test ./...`, plus file hygiene checks (trailing whitespace, EOF, merge conflicts, AWS credential detection).
