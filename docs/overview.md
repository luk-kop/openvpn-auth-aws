# Overview

`openvpn-auth-aws` authenticates OpenVPN clients with browser-based OIDC through AWS Cognito. OpenVPN verifies the client certificate first, then pauses the connection in `AUTH_PENDING` while the daemon sends the user through the ALB/Cognito login flow.

## Table of Contents

- [What It Solves](#what-it-solves)
- [Components](#components)
- [End-To-End Flow](#end-to-end-flow)
- [Runtime Shape](#runtime-shape)
- [Deployment Modes](#deployment-modes)
- [Security Model](#security-model)
- [Read Next](#read-next)

## What It Solves

OpenVPN Community Edition can delegate connection decisions to the management interface, but it does not provide an AWS-native browser OIDC flow on its own. This project bridges that gap by combining:

- OpenVPN client certificate authentication as the first factor.
- OpenVPN WebAuth (`WEB_AUTH::`) to send the user to a browser login.
- ALB `authenticate-cognito` to run the OIDC flow and forward signed identity headers.
- A Go daemon that verifies the callback, checks certificate CN vs identity, and accepts or rejects the OpenVPN client.
- Terraform modules for the AWS infrastructure around ALB, Cognito, EC2, NLB, and optional Lambda Router callback routing.

The intended deployment target is Linux on EC2, with local Docker and mock-based labs for development and validation.

## Components

| Component | Role |
|---|---|
| OpenVPN server | Terminates VPN client TLS, emits management events, and waits in `AUTH_PENDING` during browser auth. |
| Auth daemon | Owns pending sessions, signs callback state, validates ALB JWTs, checks CN/email/groups, and sends `client-auth` or `client-deny`. |
| ALB | Handles HTTPS callbacks and Cognito authentication, then forwards signed `x-amzn-oidc-*` headers to the daemon. |
| Cognito | User pool and optional federation layer for the browser login flow. |
| Lambda Router | Optional multi-instance callback proxy that routes browser callbacks to the correct EC2 daemon by private IP. |
| Terraform | Builds the AWS deployment, including networking, ALB, Cognito, EC2, NLB, IAM, and secrets wiring. |

## End-To-End Flow

```mermaid
sequenceDiagram
    participant C as OpenVPN client
    participant O as OpenVPN server
    participant D as Auth daemon
    participant B as Browser
    participant A as ALB
    participant Co as Cognito

    C->>O: TLS connect with client certificate
    O->>D: >CLIENT:CONNECT (CID, KID, ENV)
    D->>D: Validate CN and WebAuth capability
    D->>D: Create pending session and signed state
    D->>O: client-pending-auth + WEB_AUTH URL
    O->>C: AUTH_PENDING + WEB_AUTH URL
    C->>B: Open auth URL
    B->>A: GET /callback?state=...
    A->>Co: Cognito authenticate action
    B->>Co: Login
    Co->>A: Auth code
    A->>A: Token exchange and add x-amzn-oidc-* headers
    A->>D: GET /callback?state=... with ALB OIDC JWT
    D->>D: Verify state, session, JWT, CN/email, groups
    alt accepted
        D->>O: client-auth CID KID
        O->>C: Tunnel established
    else rejected
        D->>O: client-deny CID KID reason
        O->>C: AUTH_FAILED
    end
```

## Runtime Shape

The current deployment runs separate OpenVPN and daemon processes for UDP and TCP. Each daemon owns one OpenVPN management socket, one callback port, and one in-memory session store.

```text
EC2 instance
  ├─ openvpn-server@udp  -> management socket -> openvpn-auth-udp  :8080
  └─ openvpn-server@tcp  -> management socket -> openvpn-auth-tcp  :8081
```

OpenVPN 2.7 multi-socket support is verified in the lab and is the target migration path, but the first compatibility step keeps the current one-management-socket runtime model.

## Deployment Modes

- **Single-instance mode** is the default. OpenVPN client traffic uses an Elastic IP attached only after daemon health checks pass. Browser callbacks are routed by static ALB paths.
- **Multi-instance mode** sends OpenVPN client traffic through an NLB and browser callbacks through the Lambda Router, which proxies callback requests to the correct EC2 daemon by private IP.

## Security Model

The daemon treats the browser callback as valid only after several independent checks pass:

- The OpenVPN client must support WebAuth and present a certificate CN.
- The callback state must be HMAC-signed, unexpired, and tied to an active pending session.
- The request must arrive with a valid ALB-signed JWT when production validation is enabled.
- The certificate CN can be cross-checked against the OIDC email claim.
- Required group membership can be checked from ALB/Cognito claims or Cognito lookup, depending on configuration.
- Duplicate CN handling, session TTLs, auth timeouts, and reauth checks limit stale or reused sessions.

For the full security model, see [Daemon Security Features](daemon-security.md), [Architecture](architecture.md), and [Group Authorization and OIDC Claims](group-authorization.md).

## Read Next

- [Architecture](architecture.md) - full auth flow, callback verification, deployment modes, health, and session lifecycle.
- [OpenVPN WebAuth Protocol](webauth-protocol.md) - exact OpenVPN management messages and WebAuth behavior.
- [OpenVPN Server](openvpn-server.md) - required OpenVPN directives, client profile behavior, and reauth.
- [Configuration](configuration.md) - daemon flags, environment variables, logging, and metrics.
- [Group Authorization and OIDC Claims](group-authorization.md) - group checks, claim parsing, OIDC debug logging, and ALB/Cognito scope behavior.
- [Daemon Security Features](daemon-security.md) - layered daemon-side validation and rejection controls.
- [Direct Entra OIDC](direct-entra-oidc.md) - possible future ALB `authenticate-oidc` mode without Cognito federation.
- [PKI](pki.md) - certificate and `tls-crypt` key management.
- [OpenVPN 2.7 Migration Notes](openvpn-2.7-migration.md) - multi-socket lab results and supervisor/runtime migration plan.
- [Testing](testing.md) - local, Docker, and AWS validation flows.
- [Troubleshooting](troubleshooting.md) - known failure modes and useful diagnostic commands.
