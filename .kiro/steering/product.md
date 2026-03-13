# Product

OpenVPN Auth Daemon (`openvpn-auth-aws`) is a Go daemon that authenticates OpenVPN clients via browser-based OIDC using AWS Cognito. It connects to OpenVPN's Unix management socket, receives client events, and orchestrates an OAuth2/PKCE flow through a Lambda-backed API Gateway.

## Core Capabilities

- Browser-based OIDC authentication via OpenVPN's `WEB_AUTH::` URL mechanism
- OAuth2/PKCE flow with JWT validation (email, nonce, group membership)
- TLS renegotiation reauth via Cognito `AdminGetUser` with optional cache for IdP outages
- Single-session-per-user enforcement (evicts stale sessions on new connect)
- CN cross-check: certificate CN must match OIDC email claim
- CloudWatch EMF metrics and structured logging (`log/slog`)
- Graceful shutdown with in-flight session draining

## Auth Flow Summary

`CLIENT:CONNECT` → daemon creates session + signs HMAC state blob → sends `client-pending-auth` with WebAuth URL → browser hits Lambda `/auth` → Lambda POSTs auth code to daemon `/callback` → daemon exchanges code for tokens, validates JWT → sends `client-auth` or `client-deny` to OpenVPN.

## Target Environment

Linux only. Deployed as a Docker container alongside an OpenVPN server, communicating via a shared Unix socket volume.
