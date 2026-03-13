# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
make build                  # Build all binaries (openvpn-auth-daemon, mgmt-mock, lambda-mock)
make test                   # Unit tests: go test -v -short ./...
go test -v -short ./internal/auth/...  # Run tests for a single package
go vet ./...                # Static analysis
golangci-lint run           # Linter (also runs via pre-commit)
make clean                  # Remove binaries and test cache
```

## Local Development

Three-terminal setup without Docker:
- `make run-mgmt-mock` — simulates OpenVPN management socket at `/tmp/openvpn-mgmt.sock`
- `make run-daemon` — starts daemon with `--use-local-mocks` (no AWS needed)
- `make run-lambda-mock` — OAuth2 simulator on `:8080`

In mgmt-mock terminal, type `connect <cid> <email>` / `reauth <cid> <email>` / `disconnect <cid>` to trigger events.

Full Docker stack: `make stack-up` (auto-runs PKI setup), then `sudo openvpn --config lab/client.ovpn`.

## Architecture

OpenVPN auth daemon that orchestrates browser-based OIDC flows with AWS Cognito. The daemon connects to OpenVPN's Unix management socket, receives client events, and drives an OAuth2/PKCE flow through a Lambda-backed API Gateway.

**Auth flow:** CLIENT:CONNECT → daemon creates session + signs state blob → sends `client-pending-auth` with WebAuth URL → browser hits Lambda `/auth` → Lambda POSTs auth code to daemon `/callback` → daemon exchanges code for tokens, validates JWT claims → sends `client-auth` or `client-deny` to OpenVPN.

**Session lifecycle:** `SessionPending` → `SessionProcessing` → `SessionDone`/`SessionFailed`. By default, one active session per user (`--single-session-per-user`); new connects evict existing sessions (`client-deny` for pending, `client-kill` for established). Can be disabled to allow multiple concurrent sessions per CN.

**Key packages:**
- `internal/app/` — daemon lifecycle, event loop, management socket reconnection
- `internal/auth/` — core auth orchestration, session store with TTL reaper, state blob signing
- `internal/callback/` — HTTP server receiving POST `/callback` from Lambda
- `internal/mgmt/` — OpenVPN management socket protocol (parser + command writer)
- `internal/cognito/` — Cognito token exchange, JWT/JWKS validation, user group checks
- `internal/secrets/` — HMAC signing via static secret or AWS Secrets Manager
- `internal/config/` — CLI flags + env vars (`VPN_AUTH_*` prefix), validation

**Entry points:** `cmd/openvpn-auth-daemon/` (main daemon), `cmd/mgmt-mock/` (OpenVPN simulator), `cmd/lambda-mock/` (OAuth2 mock).

## Pre-commit Hooks

Configured in `.pre-commit-config.yaml`: `golangci-lint run`, `go vet ./...`, `go test ./...`, plus file hygiene checks (trailing whitespace, EOF, merge conflicts, AWS credential detection).
