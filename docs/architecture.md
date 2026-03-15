# Architecture

OpenVPN auth daemon that authenticates OpenVPN clients via browser-based OIDC with AWS Cognito. The daemon connects to OpenVPN's Unix management socket, receives client events, and drives authentication through an ALB with a Cognito authenticate action — no Lambda or API Gateway required.

## Auth Flow

```text
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│  Client   │   │ OpenVPN  │   │  Daemon  │   │   ALB    │   │ Cognito  │
│ (browser) │   │  Server  │   │          │   │          │   │          │
└────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘
     │  TLS connect  │              │               │               │
     │──────────────>│  >CLIENT:    │               │               │
     │               │  CONNECT     │               │               │
     │               │─────────────>│               │               │
     │               │              │ create session│               │
     │               │              │ sign state    │               │
     │               │              │ blob (sid,    │               │
     │               │              │  iat, exp)    │               │
     │               │  client-     │               │               │
     │               │  pending-auth│               │               │
     │               │<─────────────│               │               │
     │  WEB_AUTH URL │              │               │               │
     │<──────────────│              │               │               │
     │               │              │               │               │
     │  open browser ──────────────────────────────>│               │
     │               │              │               │ Cognito auth  │
     │               │              │               │ action ──────>│
     │  login ───────────────────────────────────────────────────>  │
     │               │              │               │<── auth code ─│
     │               │              │               │ exchange +    │
     │               │              │               │ add oidc hdrs │
     │               │              │  GET /callback│               │
     │               │              │<──────────────│               │
     │               │              │ verify state  │               │
     │               │              │ validate ALB  │               │
     │               │              │ JWT (ES256)   │               │
     │               │              │ check groups  │               │
     │               │  client-auth │               │               │
     │               │<─────────────│               │               │
     │  tunnel up    │              │               │               │
     │<──────────────│  >CLIENT:    │               │               │
     │               │  ESTABLISHED │               │               │
     │               │─────────────>│               │               │
```

1. VPN client connects → OpenVPN sends `>CLIENT:CONNECT` to management socket
2. Daemon creates an in-memory session, signs a state blob (`sid`, `iat`, `exp`), sends `client-pending-auth` with WEB_AUTH URL: `{--callback-url}?state={blob}`
3. OpenVPN forwards the URL to the client; client opens browser
4. ALB intercepts the request, runs the Cognito authenticate action (full OIDC flow), then forwards the authenticated request to the daemon's callback port with `x-amzn-oidc-*` headers
5. Daemon verifies the state HMAC, validates the ALB JWT signature (ES256), checks email and group membership
6. Daemon sends `client-auth` (success) or `client-deny` (failure) to OpenVPN

## Two Daemons per EC2

Each EC2 instance runs two independent daemon processes — one for UDP, one for TCP. They have separate management sockets, callback ports, and session stores with no shared state.

```text
EC2 Instance
├── openvpn-auth-udp  (--callback-url .../callback/01/udp, port 8080)
│   ├── GET /callback/01/udp
│   ├── GET /healthz
│   └── mgmt: /run/openvpn/udp/management.sock
└── openvpn-auth-tcp  (--callback-url .../callback/01/tcp, port 8081)
    ├── GET /callback/01/tcp
    ├── GET /healthz
    └── mgmt: /run/openvpn/tcp/management.sock

ALB
├── Listener rule: /callback/01/udp → Target Group (EC2:8080)
├── Listener rule: /callback/01/tcp → Target Group (EC2:8081)
└── Default action: Cognito authenticate action
```

## ALB JWT Validation

ALB signs the `x-amzn-oidc-data` header with ES256 (ECDSA P-256 + SHA-256). On first use of each `kid`, the daemon fetches the public key from:

```
https://public-keys.auth.elb.{region}.amazonaws.com/{kid}
```

Keys are cached in memory for the process lifetime. The daemon verifies:

- ES256 signature using the fetched public key
- `signer` field in the JWT header matches `--alb-arn`
- `exp` and `iss` fields in the JWT payload

If `--alb-arn` is absent, signature validation is skipped (dev/test only — never in production).

## WEB_AUTH URL Length Constraints

OpenVPN CE clients have a hard limit of ~229 usable bytes for the WEB_AUTH URL (the `alloc_buf_gc(256)` buffer in `src/openvpn/push.c`, after the `>INFOMSG:` prefix). If exceeded, the client silently drops the message and the browser never opens.

The daemon checks `len("OPEN_URL:") + len(authURL)` at runtime for every `CLIENT:CONNECT`. If the limit is exceeded, it sends `client-deny` with reason `"auth URL too long"` rather than silently failing.

At startup, the daemon also estimates the worst-case URL length from `--callback-url` and logs a warning if it is likely to exceed the limit.

### Byte budget

```text
Component                                          Bytes
─────────────────────────────────────────────────────────
OPEN_URL:                                              9
https://<domain>/callback/01/udp?state=           45–65  (varies by domain)
state blob:
  base64url(JSON payload, ~60 bytes)                 ~80
  "." separator                                        1
  HMAC-SHA256 (32 bytes) → base64url, no padding      43
                                                  ───────
Total                                           178–198
229-byte limit                                       229
```

Keep `--callback-url` short. A custom domain (e.g. `vpn-auth.example.com`) is recommended over long auto-generated hostnames.

## Health Check Endpoint

Each daemon exposes `GET /healthz` on its callback port. The endpoint returns:

- **200** with `{"status":"ok","mgmt_connected":true,"uptime_seconds":N,"stored_sessions":N}` when the management socket is connected
- **503** with `{"status":"degraded","mgmt_connected":false,...}` when disconnected

ALB target group health checks use this endpoint (path `/healthz`, interval 30s, timeout 5s, healthy threshold 3). EIP association is gated on both target groups reaching healthy state — see [EIP Association](#eip-association) below.

No authentication is required on `/healthz`.

## EIP Association

Each VPN server has a pre-allocated Elastic IP. After an instance replacement, the `eip-associate.service` systemd unit:

1. Starts after both `openvpn-auth-udp.service` and `openvpn-auth-tcp.service` are active
2. Polls `elasticloadbalancing:DescribeTargetHealth` for both target groups until the instance is `healthy` (300s timeout)
3. Calls `ec2:AssociateAddress --allow-reassociation` to atomically move the EIP from the old instance

This ensures VPN clients reconnecting after an instance replacement always reach a fully ready daemon.

## Session Lifecycle

```
SessionPending ──► SessionProcessing ──► SessionDone ──► (deleted on ESTABLISHED)
                                    └──► SessionFailed
```

- **SessionPending** — created on `>CLIENT:CONNECT`, waiting for browser callback
- **SessionProcessing** — callback received, identity checks in progress (atomic transition prevents double-processing)
- **SessionDone** — auth successful, `client-auth` sent; deleted when `>CLIENT:ESTABLISHED` is received
- **SessionFailed** — auth failed (timeout, JWT validation error, group check failed), `client-deny` sent

Sessions that never reach `ESTABLISHED` have a TTL of `2 × hand-window` and are reaped automatically.

## Auth Timeout vs Hand-Window

- `hand-window` (OpenVPN server directive) — total time OpenVPN allows for the TLS handshake including auth
- `--auth-timeout` (daemon flag) — how long the daemon waits for the browser callback before sending `client-deny`

`auth-timeout` must be **less than** `hand-window`. If equal, the daemon's `client-deny` races with OpenVPN's own timeout, causing the client to receive a `no-push-reply` soft restart instead of `AUTH_FAILED`.

Recommended values:

```
hand-window 300        # OpenVPN server config
--auth-timeout 270s    # daemon (hand-window minus ~30s)
```

## Session Eviction

When `--single-session-per-user=true` (default), only one active session per certificate CN is allowed:

- **New connect with same CN while pending** — old session cancelled, `client-deny` sent for old CID
- **New connect with same CN while established** — old session killed, `client-kill` sent for old CID
- **Disconnect** — session tracking cleaned up, CN slot freed

## Reauth Flow

OpenVPN triggers `>CLIENT:REAUTH` on TLS renegotiation (controlled by `reneg-sec`). The daemon:

1. Looks up user by CN in Cognito (`AdminGetUser`)
2. Checks user exists, is enabled, and optionally is in the required group
3. Sends `client-auth-nt` (allow) or `client-deny` (deny)

Reauth results can be cached (`--reauth-cache=true`) to survive brief Cognito outages. The reauth flow does not depend on ALB headers or the callback server.

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
│  HTTP :8080         │◄─────────────────┐
│  GET /callback      │                  │ GET /callback (with oidc headers)
│  GET /healthz       │                  │
└─────────────────────┘                  │
                                         │
                              ┌──────────┴───────┐
                              │  alb-mock         │
                              │  HTTP :8080       │
                              │  GET /callback    │
                              └──────────────────┘
```
