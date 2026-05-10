# Product

OpenVPN Auth Daemon (`openvpn-auth-aws`) is a Go daemon that authenticates OpenVPN clients via browser-based OIDC using AWS Cognito. It connects to OpenVPN's Unix management socket, receives client events, and orchestrates an authentication flow through an AWS Application Load Balancer (ALB) with a Cognito authenticate action. Includes an optional Lambda Router for multi-instance EC2 deployments.

## Core Capabilities

- Browser-based OIDC authentication via OpenVPN's `WEB_AUTH::` URL mechanism
- ALB + Cognito authenticate action: ALB handles the OAuth2 flow and injects a signed `x-amzn-oidc-data` JWT into the callback request
- JWT validation: ES256 signature (ALB public key), expiry, issuer, `signer` field (ALB ARN)
- Group membership check via `AdminListGroupsForUser` or JWT claims (`--cognito-groups-from-claims`)
- TLS renegotiation reauth via Cognito `AdminGetUser` with optional cache for IdP outages (`--reauth-cache`)
- Reauth can be skipped entirely with `--cognito-skip-reauth`
- Single-session-per-user enforcement (evicts stale sessions on new connect)
- CN cross-check: certificate CN must match OIDC email claim
- HMAC state blob signing; secret supplied inline or loaded from AWS Secrets Manager
- `/healthz` endpoint reflecting management socket connectivity (used for ALB target health and EIP association gating)
- CloudWatch EMF metrics and structured logging (`log/slog`)
- Graceful shutdown with in-flight session draining
- Lambda Router for multi-instance EC2 callback routing (path-based IP routing, VPC CIDR validation)
- OpenVPN 2.7.4 multi-socket support: one OpenVPN process handling UDP + TCP through a single management socket (verified in the lab; daemon routing and auth decisions rely on signed state plus `cid/kid`, not listener/protocol hints)

## Auth Flow Summary

`CLIENT:CONNECT` → daemon creates session + signs HMAC state blob → sends `client-pending-auth` with WebAuth URL (`{callback-url}?state=<blob>`) → browser hits ALB → ALB authenticates via Cognito → ALB forwards `GET /callback` to daemon with `x-amzn-oidc-data` header → daemon validates JWT, checks group, CN → sends `client-auth` or `client-deny` to OpenVPN.

## Deployment Modes

- **Single-instance mode** (default): one Auto Scaling Group with `desired=1`, `min=1`, `max=2`. The EIP is attached only after daemon `/healthz` passes, so clients always reach a ready instance. The second slot exists purely for rolling replacement.
- **Multi-instance mode**: EIP association is disabled. Client VPN traffic goes through an NLB, and browser callbacks are routed by the Lambda Router to the correct instance using path-based IP routing with VPC CIDR validation.

## Target Environment

Linux only. Deployed as one or two Docker containers per EC2 instance (UDP + TCP daemons, or a single daemon attached to an OpenVPN 2.7 multi-socket process) alongside an OpenVPN server, communicating via a shared Unix socket volume. ALB routes `/callback/{server}/{proto}` path patterns to the appropriate daemon instance.
