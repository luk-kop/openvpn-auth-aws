# Architecture

OpenVPN auth daemon that orchestrates browser-based OIDC flows with AWS Cognito. The daemon connects to OpenVPN's Unix management socket, receives client events, and drives an OAuth2/PKCE flow through a Lambda-backed API Gateway.

## Auth Flow

```text
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client   │     │ OpenVPN  │     │  Daemon  │     │  Lambda  │
│ (browser) │     │  Server  │     │          │     │ /auth    │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │  TLS connect    │               │                 │
     │────────────────>│  >CLIENT:      │                 │
     │                 │  CONNECT       │                 │
     │                 │──────────────>│                 │
     │                 │               │ create session  │
     │                 │               │ sign state blob │
     │                 │  client-       │                 │
     │                 │  pending-auth  │                 │
     │                 │<──────────────│                 │
     │  WEB_AUTH URL   │               │                 │
     │<────────────────│               │                 │
     │                 │               │                 │
     │  open browser ──────────────────────────────────>│
     │                 │               │                 │ verify HMAC
     │                 │               │                 │ redirect to
     │                 │               │                 │ Cognito login
     │  login in       │               │                 │
     │  Cognito ───────────────────────────────────────>│
     │                 │               │                 │ get auth code
     │                 │               │  POST /callback │
     │                 │               │<────────────────│
     │                 │               │ exchange code   │
     │                 │               │ validate JWT    │
     │                 │  client-auth  │                 │
     │                 │<──────────────│                 │
     │  tunnel up      │               │                 │
     │<────────────────│  >CLIENT:      │                 │
     │                 │  ESTABLISHED  │                 │
     │                 │──────────────>│                 │
```

1. VPN client connects → OpenVPN sends `>CLIENT:CONNECT` to management socket
2. Daemon creates an in-memory session with PKCE code verifier, signs a state blob, sends `client-pending-auth` with WebAuth URL
3. OpenVPN forwards the URL to the client, client opens browser
4. Lambda `/auth` verifies the HMAC on state, redirects to Cognito login
5. After login, Lambda extracts the auth code, POSTs it to the daemon's `/callback` endpoint
6. Daemon exchanges the code for tokens (PKCE), validates JWT claims (email, nonce, groups)
7. Daemon sends `client-auth` (success) or `client-deny` (failure) to OpenVPN

## Session Lifecycle

```
SessionPending ──► SessionProcessing ──► SessionDone
                                    └──► SessionFailed
```

- **SessionPending** — created on `>CLIENT:CONNECT`, waiting for browser callback
- **SessionProcessing** — callback received, token exchange in progress (atomic transition prevents double-processing)
- **SessionDone** — auth successful, `client-auth` sent
- **SessionFailed** — auth failed (timeout, token exchange error, claim validation failed), `client-deny` sent

Sessions have a TTL of `2 × hand-window` and are reaped automatically.

## Session Eviction

When `--single-session-per-user=true` (default), only one active session per certificate CN is allowed:

- **New connect with same CN while pending** — old session cancelled, `client-deny` sent for old CID
- **New connect with same CN while established** — old session killed, `client-kill` sent for old CID
- **Disconnect** — session tracking cleaned up, CN slot freed

Set `--single-session-per-user=false` to allow multiple concurrent sessions per CN.

## Reauth Flow

OpenVPN triggers `>CLIENT:REAUTH` on TLS renegotiation (controlled by `reneg-sec`). The daemon:

1. Looks up user by CN in Cognito (`AdminGetUser`)
2. Checks user exists, is enabled, and optionally in required group
3. Sends `client-auth-nt` (allow) or `client-deny` (deny)

Reauth results can be cached (`--reauth-cache=true`) to survive brief Cognito outages.

## Docker Compose Stack

```text
┌─────────────────────┐
│  OpenVPN Container  │
│  UDP 1194           │
│  management.sock    ├──┐
└─────────────────────┘  │ shared volume
                         │ /run/openvpn
┌─────────────────────┐  │
│  Daemon Container   │◄─┘
│  Go application     │
│  HTTP :8081         │◄─────────────────┐
└─────────────────────┘                  │ POST /callback
                                         │
                              ┌──────────┴───────┐
                              │  lambda-mock      │
                              │  HTTP :8080       │
                              │  /auth /callback  │
                              └──────────────────┘
```
