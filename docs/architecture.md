# Architecture

## Table of Contents

- [Auth Flow](#auth-flow)
- [Two Daemons per EC2](#two-daemons-per-ec2)
- [Management Socket Bootstrap](#management-socket-bootstrap)
- [Callback Verification Chain](#callback-verification-chain)
- [ALB JWT Validation](#alb-jwt-validation)
- [WEB_AUTH URL Length Constraints](#web_auth-url-length-constraints)
- [Health Check Endpoint](#health-check-endpoint)
- [EIP Association](#eip-association)
- [Session Lifecycle](#session-lifecycle)
- [Auth Timeout vs Hand-Window](#auth-timeout-vs-hand-window)
- [Duplicate CN and Local Cleanup](#duplicate-cn-and-local-cleanup)
- [Reauth Flow](#reauth-flow)
- [Docker Compose Stack](#docker-compose-stack)

OpenVPN auth daemon that authenticates OpenVPN clients via browser-based OIDC with AWS Cognito. The daemon connects to OpenVPN's Unix management socket, receives client events, and drives authentication through an ALB with a Cognito authenticate action — no Lambda or API Gateway required.

## Auth Flow

For the detailed OpenVPN WebAuth protocol used by this flow, see [OpenVPN WebAuth Protocol](webauth-protocol.md).

```mermaid
sequenceDiagram
    participant C as Client (browser)
    participant V as OpenVPN Server
    participant D as Daemon
    participant A as ALB
    participant Co as Cognito

    C->>V: TLS connect
    V->>D: >CLIENT:CONNECT (CID, KID, ENV)

    note over D: Pre-checks (IV_SSO, CN, local stale-state cleanup)

    alt IV_SSO missing WebAuth or CN empty
        D->>V: client-deny
    end

    D->>D: create session, sign state blob</br>(sid, iat, exp)
    D->>V: client-pending-auth</br>+ WEB_AUTH URL
    V->>C: WEB_AUTH URL

    C->>A: open browser → GET /callback?state=...
    A->>Co: Cognito authenticate action (OIDC)
    C->>Co: login (username + password)
    Co->>A: auth code
    A->>A: token exchange,</br>add x-amzn-oidc-* headers
    A->>D: GET /callback?state=...</br>(with x-amzn-oidc-data JWT)

    note over D: Callback verification chain (see below)

    alt verification passed
        D->>V: client-auth (CID, KID)
        D->>D: mark session authenticated, start expiry timer (if enabled)
        V->>C: tunnel up
        V->>D: >CLIENT:ESTABLISHED (CID)
        D->>D: idempotent promotion / cleanup if ESTABLISHED arrives later
    else verification failed
        D->>V: client-deny (CID, KID, reason)
    end
```

### Pre-checks

Before starting the OIDC flow, the daemon validates the `CLIENT:CONNECT` event:

- **IV_SSO check** — client must advertise `webauth` or `openurl` in the `IV_SSO` env variable; otherwise `client-deny` with reason `"client does not support WebAuth"`
- **Common Name** — certificate CN must be non-empty; otherwise `client-deny` with reason `"missing common name"`
- **Local stale-state cleanup** — if daemon memory still contains an older CID for the same CN, the old local entry is evicted (`client-deny` for pending, `client-kill ... HALT` for established) before creating a new one. This is defensive bookkeeping; OpenVPN itself rejects duplicate CNs per server process by default when `duplicate-cn` is absent.

### Steps

1. VPN client connects → OpenVPN sends `>CLIENT:CONNECT` to management socket
2. Daemon runs pre-checks, creates an in-memory session, signs a state blob (`sid`, `iat`, `exp`), sends `client-pending-auth` with WEB_AUTH URL: `{--callback-url}?state={blob}`
3. OpenVPN forwards the URL to the client; client opens browser
4. ALB intercepts the request, runs the Cognito authenticate action (full OIDC flow), then forwards the authenticated request to the daemon's callback port with `x-amzn-oidc-*` headers
5. Daemon runs the [callback verification chain](#callback-verification-chain) — state HMAC, session transition, ALB JWT signature (ES256), CN cross-check, group membership
6. Daemon sends `client-auth` (success) or `client-deny` (failure) to OpenVPN

## Two Daemons per EC2

Each EC2 instance runs two independent daemon processes — one for UDP, one for TCP. They have separate management sockets, callback ports, and session stores with no shared state.

## Management Socket Bootstrap

On every management socket connection, the daemon performs a short bootstrap phase before it starts handling live `>CLIENT:*` events.

Sequence:

1. Connect to the OpenVPN management Unix socket
2. Authenticate with the management password
3. Send `hold release`
4. Send `status 3`
5. Parse the current OpenVPN snapshot (`HEADER`, `CLIENT_LIST`, `ROUTING_TABLE`, `GLOBAL_STATS`, `END`)
6. Rebuild in-memory session tracking from the live OpenVPN state
7. Enter the normal event loop and process new `>CLIENT:CONNECT`, `>CLIENT:REAUTH`, `>CLIENT:DISCONNECT`, `>CLIENT:ESTABLISHED` events

This happens not only at daemon startup, but also after any management reconnect, for example:

- daemon restart
- OpenVPN restart
- temporary management socket disconnect
- parser or socket read error that forces a reconnect

The purpose of bootstrap is to resynchronize daemon memory with the actual OpenVPN state. The daemon keeps some session-tracking data in memory, so after reconnect it must rebuild that state from `status 3` before it can safely process new client events.

Bootstrap uses a short read timeout for the `status 3` snapshot. This prevents the daemon from hanging for minutes if OpenVPN is in the middle of a restart and the management socket accepts a connection but does not finish the snapshot.

If bootstrap fails or times out, the daemon reconnects and retries. In that state OpenVPN may still be running, but the daemon is not yet ready to process live `CLIENT:CONNECT` events because it has not completed the initial state sync.

Observed behavior during OpenVPN restart:

- the first bootstrap attempt may time out while the new OpenVPN process is still coming up
- the next reconnect attempt usually succeeds immediately
- once bootstrap completes, the daemon resumes normal client handling

From the VPN client's point of view, a UDP-based OpenVPN server restart may not appear as an explicit "session terminated" event. Instead, the client often observes missing replies, repeated `PUSH_REQUEST` retries, and then a soft restart/reconnect once its own timeout logic fires.

Similarly, when a UDP client process exits locally, the server may observe repeated `ECONNREFUSED` reads before it finally declares the peer dead via `--ping-restart`. In that case the daemon may receive `>CLIENT:DISCONNECT` only when OpenVPN reaches the inactivity timeout, not immediately when the client exits.

### Single-instance mode (default)

Static ALB listener rules route callbacks by server name:

```mermaid
graph TD
    subgraph EC2["EC2 Instance"]
        subgraph UDP["openvpn-auth-udp — port 8080"]
            UDP_CB("GET /callback/01/udp")
            UDP_HZ("GET /healthz")
            UDP_MGMT("mgmt: /run/openvpn/management-udp.sock")
        end
        subgraph TCP["openvpn-auth-tcp — port 8081"]
            TCP_CB("GET /callback/01/tcp")
            TCP_HZ("GET /healthz")
            TCP_MGMT("mgmt: /run/openvpn/management-tcp.sock")
        end
    end

    subgraph ALB["ALB"]
        R_UDP("/callback/01/udp → TG EC2:8080")
        R_TCP("/callback/01/tcp → TG EC2:8081")
        R_DEF("Default: Cognito authenticate action")
    end

    R_UDP --> UDP_CB
    R_TCP --> TCP_CB

    style EC2 fill:#2c3e50,stroke:#1a252f,color:#ecf0f1
    style UDP fill:#1e8449,stroke:#186a3b,color:#fff
    style TCP fill:#1e8449,stroke:#186a3b,color:#fff
    style ALB fill:#1a5276,stroke:#154360,color:#ecf0f1
```

### Multi-instance mode

When `multi_instance_mode = true`, multiple EC2 instances run behind an NLB for OpenVPN client traffic and a Lambda Router for callback routing:

```mermaid
graph TD
    subgraph NLB["NLB — vpn-nlb.example.com"]
        NLB_UDP("UDP :1194 → TG all EC2 instances")
        NLB_TCP("TCP :1195 → TG all EC2 instances")
    end

    subgraph ALB["ALB — vpn.example.com"]
        ALB_CB("/callback/* → Lambda Router")
        ALB_DEF("Default: Cognito authenticate action")
    end

    subgraph LR["Lambda Router"]
        LR_PARSE("Parse path: /callback/private-ip/udp|tcp")
        LR_VALID("Validate IP in VPC CIDR")
        LR_PROXY("Proxy HTTP to EC2 daemon on private IP")
    end

    ALB_CB --> LR_PARSE --> LR_VALID --> LR_PROXY

    style NLB fill:#6c3483,stroke:#5b2c6f,color:#fff
    style ALB fill:#1a5276,stroke:#154360,color:#ecf0f1
    style LR fill:#b9770e,stroke:#9c640c,color:#fff
```

Each EC2 instance uses its private IP in the callback URL (e.g. `/callback/10.0.1.42/udp`). The Lambda Router extracts the IP from the path, validates it against the VPC CIDR, and proxies the request directly to the daemon. See [Lambda Router](lambda-router-proxy.md) for details.

## Callback Verification Chain

When the daemon receives `GET /callback` from the ALB, it runs a multi-step verification pipeline. Every step must pass — failure at any point results in `client-deny`. The flow is implemented in `internal/callback/server.go:handleCallback`.

```mermaid
flowchart TD
    A("GET /callback?state=...") --> B{"1. State HMAC</br>valid?"}
    B -- no --> R1("400 Bad Request")
    B -- yes --> C{"2. Session exists</br>and PENDING?"}
    C -- not found --> R2("404 Not Found")
    C -- not pending --> R3("409 Conflict")
    C -- yes --> D("Session → PROCESSING")
    D --> E{"3. x-amzn-oidc-data</br>header present?"}
    E -- no --> R4("403 missing oidc header</br>client-deny")
    E -- yes --> F{"4. Parse JWT header</br>kid, signer"}
    F -- error --> R5("403 invalid jwt header</br>client-deny")
    F -- ok --> G{"--alb-arn</br>set?"}
    G -- "yes (prod)" --> H("5. Fetch ALB public key</br>cache by kid")
    H -- fetch error --> R6("503 retry</br>Session → PENDING")
    H -- ok --> I{"6. Validate JWT</br>ES256 signature</br>signer == ALB ARN</br>exp not expired"}
    I -- fail --> R7("403 jwt validation failed</br>client-deny")
    I -- ok --> J{"7. CN cross-check</br>enabled?"}
    G -- "no (dev)" --> P("Parse claims</br>without signature")
    P --> J
    J -- "yes: email ≠ CN" --> R8("403 cn mismatch</br>client-deny")
    J -- "no / match" --> K{"8. Required group</br>configured?"}
    K -- no --> L("9. Auth SUCCESS</br>Session → DONE</br>client-auth")
    K -- yes --> M{"Check group</br>membership"}
    M -- "not in group" --> R9("403 not in required group</br>client-deny")
    M -- "in group" --> L

    style L fill:#1e8449,stroke:#186a3b,color:#fff
    style R1 fill:#922b21,stroke:#7b241c,color:#fff
    style R2 fill:#922b21,stroke:#7b241c,color:#fff
    style R3 fill:#922b21,stroke:#7b241c,color:#fff
    style R4 fill:#922b21,stroke:#7b241c,color:#fff
    style R5 fill:#922b21,stroke:#7b241c,color:#fff
    style R6 fill:#b9770e,stroke:#9c640c,color:#fff
    style R7 fill:#922b21,stroke:#7b241c,color:#fff
    style R8 fill:#922b21,stroke:#7b241c,color:#fff
    style R9 fill:#922b21,stroke:#7b241c,color:#fff
```

### Step-by-step

| # | Check | What it protects against | Failure | Metric reason |
|---|-------|--------------------------|---------|---------------|
| 1 | **State HMAC** — `DecodeState` verifies the HMAC-SHA256 signature on the `state` query parameter, checks `iat`/`exp`. **Note:** if state is invalid, the daemon cannot extract the session ID, so it cannot send `client-deny` — the VPN client waits until `--auth-timeout` expires. This is a UX limitation, not a security issue. | CSRF, forged callbacks, replay after expiry | 400 | `missing_state` / `invalid_state` |
| 2 | **Session lookup** — `TryProcess` atomically transitions session from `PENDING` → `PROCESSING` | Replay (double callback), race conditions | 404 / 409 | `session_not_found` / `session_not_pending` |
| 3 | **OIDC header** — checks `x-amzn-oidc-data` header is present | Direct access bypassing ALB | 403 + deny | `missing_oidc_header` |
| 4 | **JWT header parse** — extracts `kid` and `signer` from the JWT header segment | Malformed tokens | 403 + deny | `invalid_jwt_header` |
| 5 | **ALB public key fetch** — fetches ECDSA public key from `https://public-keys.auth.elb.{region}.amazonaws.com/{kid}`, cached in memory | N/A (infrastructure step) | 503 (retryable) | `public_key_fetch_failed` |
| 6 | **JWT signature + claims** — verifies ES256 signature with the ALB public key, checks `signer` matches `--alb-arn`, requires valid `exp` | Token forgery, ALB spoofing, expired tokens | 403 + deny | `jwt_validation_failed` / `invalid_jwt_claims` |
| 7 | **CN cross-check** — compares JWT `email` claim with the client certificate's Common Name (case-insensitive) | User A authenticating with User B's browser session | 403 + deny | `cn_mismatch` |
| 8 | **Group membership** — checks if the user belongs to the required Cognito group. By default (`--groups-source=cognito-api`) this uses Cognito Admin APIs. With `--groups-source=jwt-claim`, the callback/connect decision reads groups from the top-level claim named by `--groups-claim` in `x-amzn-oidc-data`; reauth group checks always require Cognito Admin API access (`--groups-source=jwt-claim` cannot be combined with `--check-required-group-on-reauth=true`). | Unauthorized access by authenticated but unprivileged users | 403 + deny | `group_check_error` / `group_denied` |

All rejection reasons are emitted as `CallbackRejected` EMF metric with a `Reason` dimension. See [EMF Metrics](configuration.md#emf-metrics) for the full list.

### Production vs dev mode

In production (`--alb-arn` is set), steps 5-6 enforce full cryptographic verification of the ALB JWT. The daemon only trusts tokens signed by the specific ALB identified by its ARN.

In dev mode (`--alb-arn` is absent), JWT signature validation is skipped — claims are parsed from the token payload without verification. This mode should never be used in production. All other checks (state HMAC, session, CN cross-check, groups) still apply.

### Network-level defense

The callback port is only reachable from the ALB security group (no public ingress). JWT validation provides defense-in-depth — even if network isolation were compromised, an attacker would need a valid JWT signed by the correct ALB.

## ALB JWT Validation

See [AWS docs: Authenticate users using an Application Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html) for the full ALB authenticate action reference.

Before the daemon sees a normal callback request, the ALB's `authenticate-cognito` action performs the browser login flow with Cognito and stores its own session in `AWSELBAuthSessionCookie-*` cookies. In the currently tested setup with native Cognito users (`supported_identity_providers = ["COGNITO"]`), the forwarded request contained these headers:

- `x-amzn-oidc-data` — ES256-signed JWT from ALB. In the tested Cognito flow its payload contained `email`, `sub`, `username`, `exp`, `iss`.
- `x-amzn-oidc-identity` — plain-text copy of the user `sub`.
- `x-amzn-oidc-accesstoken` — raw Cognito access token. In the tested flow its payload contained `sub`, `username`, `scope`, `client_id`, `token_use`, `auth_time`, `exp`, `iat`, `iss`, `jti`, `origin_jti`, `version`.

Important details from production logs for the native-Cognito flow:

- `x-amzn-oidc-data` contained `username`, not `cognito:username`
- for native Cognito users in this deployment, `username` was a UUID-like internal Cognito username, while `email` remained a separate attribute
- `x-amzn-oidc-data` did not contain `cognito:groups`
- `x-amzn-oidc-accesstoken` also did not contain `cognito:groups`
- adding a user to a Cognito User Pool group did not make that group appear automatically in `x-amzn-oidc-data` for this ALB `authenticate-cognito` flow
- adding a user to a Cognito User Pool group also did not make that group appear automatically in `x-amzn-oidc-accesstoken`
- because of that, the daemon must treat `username` as the fallback lookup key for `AdminGetUser`
- group checks from JWT claims only work when claims are explicitly made available in the ALB-forwarded token; in this native-Cognito deployment they were absent from both forwarded JWTs

These observations are empirical for the current native-Cognito deployment. External IdP federation through Cognito may produce different forwarded claims and should be verified separately.

In Terraform this repo configures:

- `scope = "openid email profile"` so Cognito returns the user's `email` claim and ALB can include it in `x-amzn-oidc-data`; `profile` helps profile/custom mapped claims but is not a reliable path to native Cognito `cognito:groups`
- `session_timeout` via `alb_auth_session_timeout_hours` (default `1h`) so the ALB browser session does not outlive the short-lived daemon `state` by too much

These ALB cookies are separate from the daemon's `state` parameter. A browser may still have a valid ALB auth session while the callback `state` has already expired; in that case the request reaches the daemon and is correctly rejected as `invalid_state`.

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

| Component | Bytes |
|-----------|------:|
| `OPEN_URL:` | 9 |
| `https://<domain>/callback/01/udp?state=` | 45-65 (varies by domain) |
| State blob (base64url JSON + `.` + HMAC-SHA256) | up to ~128 |
| **Total** | `9 + len(callback-url) + 7 + up to ~128` |
| **229-byte limit** | **229** |

Keep `--callback-url` short. A custom domain (e.g. `vpn-auth.example.com`) is recommended over long auto-generated hostnames.

## Health Check Endpoint

Each daemon exposes `GET /healthz` on its callback port. The endpoint returns:

- **200** with `{"status":"ok","mgmt_connected":true,"uptime_seconds":N,"stored_sessions":N}` when the management socket is connected
- **503** with `{"status":"degraded","mgmt_connected":false,...}` when disconnected

ALB target group health checks use this endpoint (path `/healthz`, interval 30s, timeout 5s, healthy threshold 3). EIP association is gated on both target groups reaching healthy state — see [EIP Association](#eip-association) below.

No authentication is required on `/healthz`.

## EIP Association

> **Note:** EIP association is used only in single-instance mode (`multi_instance_mode = false`). In multi-instance mode, instances have no EIPs — OpenVPN client traffic reaches instances through the NLB.

Each VPN server has a pre-allocated Elastic IP. After an instance replacement, the `eip-associate.service` systemd unit:

1. Starts after both `openvpn-auth-udp.service` and `openvpn-auth-tcp.service` are active
2. Polls `elasticloadbalancing:DescribeTargetHealth` for both target groups until the instance is `healthy` (300s timeout)
3. Calls `ec2:AssociateAddress --allow-reassociation` to atomically move the EIP from the old instance

This ensures VPN clients reconnecting after an instance replacement always reach a fully ready daemon.

## Session Lifecycle

```mermaid
graph LR
    P("SessionPending") --> PR("SessionProcessing")
    PR --> D("SessionDone")
    PR --> F("SessionFailed")
    D --> DEL("Deleted on ESTABLISHED")

    style P fill:#b9770e,stroke:#9c640c,color:#fff
    style PR fill:#1a5276,stroke:#154360,color:#ecf0f1
    style D fill:#1e8449,stroke:#186a3b,color:#fff
    style F fill:#922b21,stroke:#7b241c,color:#fff
    style DEL fill:#2c3e50,stroke:#1a252f,color:#ecf0f1
```

- **SessionPending** — created on `>CLIENT:CONNECT`, waiting for browser callback
- **SessionProcessing** — callback received, identity checks in progress (atomic transition prevents double-processing)
- **SessionDone** — auth successful, `client-auth` sent; deleted as soon as auth success is promoted, so a missed `>CLIENT:ESTABLISHED` does not lose max-session tracking
- **SessionFailed** — auth failed (timeout, JWT validation error, group check failed), `client-deny` sent

Sessions that never reach `ESTABLISHED` have a TTL of `2 × hand-window` and are reaped automatically.

### Management Socket Reconnect and Session Tracking

On each management socket connect, the daemon sends `hold release` followed by `status 3`. OpenVPN responds with a snapshot of all currently established clients. The daemon uses this snapshot to rebuild its in-memory session tracking (`cids`, `cnToActiveCID`) — a process handled by `RebuildSessionTrackingFromStatus`.

This covers three scenarios:

| Scenario | What happens |
| --- | --- |
| **Daemon restart** (OpenVPN still running) | Daemon starts with empty maps. `status 3` returns all active clients. Maps are populated from scratch — local stale-state tracking and `max-session-duration` enforcement resume for existing sessions. |
| **Management socket drops** (both still running) | Daemon reconnects to the socket. Maps may contain stale entries for clients that disconnected while the socket was down. `status 3` returns the current state — stale entries are pruned, surviving sessions are kept or have their expiry timers restarted. |
| **OpenVPN restart** | All VPN tunnels are terminated. `status 3` returns an empty list. All map entries and expiry timers are cleaned up. Clients must reconnect (new `CLIENT:CONNECT`), so tracking starts fresh. |

When `--max-session-duration` is disabled (`0`), `RebuildSessionTrackingFromStatus` still rebuilds `cids` and `cnToActiveCID` for local stale-state cleanup. Expiry timer logic is simply skipped.

## Auth Timeout vs Hand-Window

- `hand-window` (OpenVPN server directive) — total time OpenVPN allows for the TLS handshake including auth
- `--auth-timeout` (daemon flag) — how long the daemon waits for the browser callback before sending `client-deny`

`auth-timeout` must be **less than** `hand-window`. If equal, the daemon's `client-deny` races with OpenVPN's own timeout, causing the client to receive a `no-push-reply` soft restart instead of `AUTH_FAILED`.

Recommended values:

```text
hand-window 300        # OpenVPN server config
--auth-timeout 270s    # daemon (hand-window minus ~30s)
```

## Duplicate CN and Local Cleanup

OpenVPN rejects duplicate certificate CNs by default within a single server process. Do not set `duplicate-cn`; that directive disables OpenVPN's built-in per-process duplicate protection.

The daemon also tracks `CN -> CID` locally so it can clean up stale state after missed disconnects or management socket reconnects:

- **New connect with same CN while old local auth is pending** — old local pending session is cancelled and `client-deny` is sent for the old CID
- **New connect with same CN while old local CID is established** — old local CID is removed and `client-kill ... HALT` is sent as defensive cleanup
- **Disconnect** — session tracking is cleaned up and the CN slot is freed

This is not a global single-session security control. UDP and TCP daemons have separate memory, and multi-instance deployments require a shared ownership mechanism if strict fleet-wide one-session-per-CN enforcement is required. See [Multi-Instance Single-Session Design](multi-instance-single-session.md).

## Reauth Flow

OpenVPN triggers `>CLIENT:REAUTH` on TLS renegotiation (controlled by `reneg-sec`). The daemon:

1. Looks up the user in Cognito (`AdminGetUser`) using the Cognito lookup username stored at callback time; for older/native-only sessions without that value, the CN is the fallback identity.
2. Checks user exists, is enabled, and optionally is in the required group
3. Sends `client-auth-nt` (allow) or `client-deny` (deny)

Reauth results can be cached (`--reauth-cache=true`) to survive brief Cognito outages. The reauth flow does not depend on ALB headers or the callback server.

**Federated users:** For federated Cognito users the certificate CN does not match the Cognito username (which has the form `providerName_externalId`). At authentication time the daemon stores the Cognito lookup username from the ALB callback claims alongside the session, preferring `cognito:username` when present and falling back to `username`. It then uses that stored value — rather than the CN — when calling `AdminGetUser` on reauth. See [Cognito Federation](cognito-federation.md) for known limitations with federated identities.

## Docker Compose Stack

```mermaid
graph LR
    client("🖥️ VPN Client")

    subgraph docker["Docker Compose"]
        subgraph openvpn["OpenVPN"]
            ovpn_port("UDP :1194")
            mgmt_sock("/run/openvpn/management.sock")
        end

        subgraph daemon["Auth Daemon"]
            daemon_cb("GET /callback — :8081")
            daemon_hz("GET /healthz — :8081")
        end

        subgraph albmock["ALB Mock"]
            alb_cb("GET /callback — :8080")
            alb_hz("GET /healthz — :8080")
        end
    end

    client -- "UDP :1194" --> ovpn_port
    mgmt_sock -. "Unix socket</br>/run/openvpn" .-> daemon_cb
    client -- "browser</br>GET /callback?state=..." --> alb_cb
    alb_cb -- "GET /callback</br>+ x-amzn-oidc-data JWT" --> daemon_cb

    style openvpn fill:#1a5276,stroke:#154360,color:#fff
    style daemon fill:#1e8449,stroke:#186a3b,color:#fff
    style albmock fill:#b9770e,stroke:#9c640c,color:#fff
    style docker fill:#2c3e50,stroke:#1a252f,color:#ecf0f1
    style client fill:#6c3483,stroke:#5b2c6f,color:#fff
```
