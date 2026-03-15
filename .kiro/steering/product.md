# Product

OpenVPN Auth Daemon (`openvpn-auth-aws`) is a Go daemon that authenticates OpenVPN clients via browser-based OIDC using AWS Cognito. It connects to OpenVPN's Unix management socket, receives client events, and orchestrates an authentication flow through an AWS Application Load Balancer (ALB) with Cognito authenticate action.

## Core Capabilities

- Browser-based OIDC authentication via OpenVPN's `WEB_AUTH::` URL mechanism
- ALB + Cognito authenticate action: ALB handles the OAuth2 flow and injects a signed `x-amzn-oidc-data` JWT into the callback request
- JWT validation: ES256 signature (ALB public key), expiry, issuer, `signer` field (ALB ARN)
- Group membership check via `AdminListGroupsForUser` or JWT claims (`--cognito-groups-from-claims`)
- TLS renegotiation reauth via Cognito `AdminGetUser` with optional cache for IdP outages
- Single-session-per-user enforcement (evicts stale sessions on new connect)
- CN cross-check: certificate CN must match OIDC email claim
- `/healthz` endpoint reflecting management socket connectivity
- CloudWatch EMF metrics and structured logging (`log/slog`)
- Graceful shutdown with in-flight session draining

## Auth Flow Summary

`CLIENT:CONNECT` → daemon creates session + signs HMAC state blob → sends `client-pending-auth` with WebAuth URL (`{callback-url}?state=<blob>`) → browser hits ALB → ALB authenticates via Cognito → ALB forwards `GET /callback` to daemon with `x-amzn-oidc-data` header → daemon validates JWT, checks group, CN → sends `client-auth` or `client-deny` to OpenVPN.

## Target Environment

Linux only. Deployed as one or two Docker containers per EC2 instance (UDP + TCP daemons) alongside an OpenVPN server, communicating via a shared Unix socket volume. ALB routes `/callback/{server}/{proto}` path patterns to the appropriate daemon instance.
