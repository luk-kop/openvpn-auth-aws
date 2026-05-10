# OpenVPN 2.7 Migration Notes

> ⚠️ **VALIDATION NOTES AND TARGET ARCHITECTURE — NOT THE PRIMARY USER GUIDE**
>
> This document captures OpenVPN 2.7 migration evidence, lab findings, remaining uncertainties, and target architecture decisions. OpenVPN 2.7.4 daemon compatibility and multi-socket Docker lab behavior are verified only where this document explicitly marks them as verified. Supervisor and multi-runtime items remain target architecture work unless explicitly marked as implemented elsewhere. Keep operational OpenVPN configuration guidance in [OpenVPN Server Configuration](openvpn-server.md), and do not cite this file as complete documentation of current runtime behavior.

## Why Migrate

OpenVPN 2.7 is the right target before the first release because it changes a core assumption in this project: OpenVPN servers can now listen on multiple sockets from one server process. The daemon target is broader than that: one daemon process should support both one OpenVPN 2.7 multi-socket process and multiple OpenVPN server processes on the same EC2/VM.

Confirmed upstream changes as of OpenVPN 2.7.4:

- OpenVPN 2.7.0 introduced server multi-socket support.
- Multiple `--local` statements can configure multiple listen sockets.
- A single server can listen on UDP and TCP, or on multiple addresses and ports.
- OpenVPN 2.7 also adds support for the newer upstream Linux `ovpn` DCO module, client DNS handling changes, minimal server-side `PUSH_UPDATE` support through management commands, and several deprecated/removed options.
- OpenVPN 2.7.4 is a bugfix release. Notable items include a Windows `--dns server ...` with win-dco DNSSEC fix/workaround note, corrected `--dns-up-down` script comments, mbedTLS error-message improvements for invalid `tls-group`, and removal of no-op `--enable-strict` / `--enable-strict-options` configure flags.

Sources:

- OpenVPN 2.7 release notes: https://github.com/OpenVPN/openvpn/releases/tag/v2.7.0
- OpenVPN 2.7.4 release notes: https://github.com/OpenVPN/openvpn/releases/tag/v2.7.4
- OpenVPN 2.7.4 announcement: https://www.mail-archive.com/openvpn-announce%40lists.sourceforge.net/msg00165.html
- OpenVPN `Changes.rst`: https://github.com/OpenVPN/openvpn/blob/master/Changes.rst
- OpenVPN management interface docs: https://openvpn.net/community-resources/management-interface/
- OpenVPN 2.6 manual for current management-client-auth behavior: https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html

## Current Project Assumptions

The current deployment model uses one OpenVPN process per listener:

- `openvpn-server@udp`
- `openvpn-server@tcp`

Each OpenVPN process has its own management socket, and each auth daemon process connects to exactly one management socket:

- `openvpn-auth-udp`
- `openvpn-auth-tcp`

This means the daemon currently assumes:

- one daemon runtime owns one OpenVPN management connection
- OpenVPN `cid` and `kid` values are scoped to one OpenVPN process
- callback URLs route to a daemon tied to one server/listener
- daemon health means one OpenVPN management socket is reachable
- session state is local to one OpenVPN server process

That model is valid for OpenVPN 2.6 and still valid for OpenVPN 2.7 if we keep separate OpenVPN processes.

## Target Architecture

The target daemon architecture is one process with a supervisor that can run multiple isolated OpenVPN management runtimes.

Supported deployment shapes:

1. One OpenVPN 2.7 multi-socket process, one daemon runtime, one management socket.
2. Multiple OpenVPN processes on one EC2/VM, one daemon process, multiple daemon runtimes and management sockets.
3. Mixed mode, if needed: multiple OpenVPN 2.7 multi-socket processes, each represented by one daemon runtime.

This replaces the current pattern:

```text
OpenVPN UDP process + daemon UDP process
OpenVPN TCP process + daemon TCP process
```

with:

```text
One daemon process
  ├─ runtime: ovpn-main management socket
  │    ├─ listener: udp-1194
  │    └─ listener: tcp-443
  └─ runtime: ovpn-admin management socket
       └─ listener: admin-tcp-8443
```

This should simplify EC2/systemd while preserving a valid model for multiple separate OpenVPN server processes. It is only safe if the daemon strictly routes every management command to the runtime that owns the signed callback state and session.

### Terminology: Supervisor And Runtime

The **supervisor** is the top-level coordinator inside one `openvpn-auth-daemon` process. It starts and stops runtimes, tracks per-runtime health, owns shared dependencies, and routes callback decisions to the correct runtime.

A **management runtime** is the isolated auth loop for exactly one OpenVPN management socket. It owns its own management connection, command queue, reconnect loop, CID/session mapping, health state, and graceful shutdown path.

Invariant: one runtime equals one OpenVPN process and one management endpoint. In OpenVPN 2.7 multi-socket mode, multiple listen sockets inside one OpenVPN process still map to one runtime because they share one management interface.

Example:

```text
openvpn-auth-daemon
  ├─ supervisor
  │
  ├─ runtime: ovpn-main
  │    ├─ management socket: /run/openvpn/main-mgmt.sock
  │    └─ listeners: udp-1194, tcp-443
  │
  └─ runtime: ovpn-admin
       ├─ management socket: /run/openvpn/admin-mgmt.sock
       └─ listeners: admin-tcp-8443
```

The signed callback state must identify the owning runtime:

```text
callback state says: server_id=ovpn-admin, cid=7, kid=2
supervisor selects runtime "ovpn-admin"
runtime writes: client-auth 7 2
```

This prevents a `client-auth`, `client-deny`, or `client-kill` for one OpenVPN process from being written to the wrong management socket.

### Supervisor Architecture Risks

The supervisor model is useful, but it is not risk-free. The implementation must be strict about ownership boundaries.

Main risks:

- Wrong-socket command routing: sending `client-auth`, `client-deny`, or `client-kill` to the wrong OpenVPN process.
- Shared state bugs: treating `cid=7` from two different OpenVPN processes as the same client.
- Callback confusion: trusting URL path data instead of signed callback state.
- Partial failure: one runtime dies while other runtimes keep running.
- Shutdown complexity: one daemon process must drain and stop multiple runtimes.
- Health ambiguity: process-level health is not enough; health must report each runtime.
- Locking/concurrency bugs: multiple runtimes process management events at the same time.

The mitigation is simple but non-negotiable: only a runtime may write to its own OpenVPN management socket, and all routing decisions must use signed `server_id` state.

OpenVPN supports at most one management client connection per OpenVPN process at a time, regardless of whether the management interface is exposed through a Unix socket or localhost TCP. The supervisor must validate that no two runtimes are configured with the same management endpoint. One runtime means one OpenVPN management interface owner.

### Go Implementation Shape

Target shape:

```go
type Supervisor struct {
    runtimes map[string]*Runtime
    owners   *LocalOwnerIndex
    signer   auth.StateSigner
    callback *callback.Server
    metrics  *metrics.Emitter
}

type Runtime struct {
    serverID string
    cfg      ServerConfig

    cmdCh chan queuedCommand

    sessions  *auth.SessionStore
    handler   *auth.Handler
    connected atomic.Bool
}
```

The supervisor owns the runtime registry and shared process-wide dependencies. A runtime owns exactly one OpenVPN management socket, its command queue, its reconnect loop, and its per-runtime CID/session state.

Callback flow:

```go
state := verifySignedState(req)

rt := supervisor.Runtime(state.ServerID)
if rt == nil {
    rejectCallback()
    return
}

rt.Send(auth.Decision{
    Type: auth.DecisionAllow,
    CID:  state.CID,
    KID:  state.KID,
})
```

Session keys must include `server_id` because OpenVPN client IDs are scoped to one OpenVPN process:

```go
type SessionKey struct {
    ServerID string
    CID      string
}
```

Local single-session ownership should be a separate index:

```go
type CNOwnerKey struct {
    VPNGroup string
    CN       string
}

type CNOwner struct {
    ServerID    string
    CID         string
    SourceIP    string
    ConnectedAt time.Time
}
```

`vpn_group` is a logical single-session scope, not necessarily the same as Cognito `required_group`. It should be explicit daemon configuration in the multi-runtime design. If not configured, default to `default`. Do not derive `vpn_group` implicitly from `required_group`, because deployments can choose no required Cognito group while still needing single-session enforcement.

On a new connect for the same `vpn_group + CN`, the supervisor can evict an old local owner even if it belongs to another OpenVPN runtime in the same process:

```go
old := supervisor.owners.Get(vpnGroup, cn)
if old.Exists && old.ServerID != currentServerID {
    supervisor.Runtime(old.ServerID).Kill(old.CID)
}

supervisor.owners.Set(vpnGroup, cn, currentOwner)
```

Avoid these implementation shortcuts:

- one global `cmdCh`
- one global `cid -> session` map
- callback routing by URL path alone
- shared `auth.Handler` instances if they contain mutable CID/session state
- direct management socket access from the callback server
- ad hoc mutexes around the existing single-runtime daemon loop instead of explicit runtime ownership

Strict ownership model:

```text
Supervisor
  owns runtime registry
  owns local CN ownership index
  owns callback server
  routes signed callback decisions

Runtime
  owns exactly one management socket
  owns command queue
  owns per-runtime CID/session state
  reconnects independently
  reports health independently
```

### Goroutine Model

The supervisor should be the top-level coordinator, but runtimes should execute concurrently. In Go, the expected shape is one goroutine per management runtime, plus separate goroutines for callback serving and background metrics/reaping work.

Example:

```go
func (s *Supervisor) Run(ctx context.Context) error {
    group, ctx := errgroup.WithContext(ctx)

    for _, rt := range s.runtimes {
        rt := rt
        group.Go(func() error {
            return rt.Run(ctx)
        })
    }

    group.Go(func() error {
        return s.callbackServer.Run(ctx)
    })

    return group.Wait()
}
```

Expected process shape:

```text
openvpn-auth-daemon process
  ├─ main/supervisor goroutine
  ├─ callback HTTP server goroutine
  ├─ runtime ovpn-main goroutine(s)
  ├─ runtime ovpn-admin goroutine(s)
  └─ metrics/reaper goroutine(s)
```

Each runtime may have internal goroutines for management reconnect/read loops, command writing, and timeout/graceful-shutdown work. That is acceptable as long as the runtime owns its own management socket and mutable CID/session state.

Shared supervisor-level state, such as the local `vpn_group + CN -> server_id + cid` ownership index, must be hidden behind a narrow API with internal locking. Do not let runtimes mutate shared maps directly.

Use the fresh `kid` from the current management event when writing `client-auth` or `client-deny`. Do not cache a `kid` from `CLIENT:CONNECT` and reuse it for later `CLIENT:REAUTH`; `kid` is tied to the current key/auth event, not a durable session identifier.

Treat `cid` and `kid` as management-interface identifiers for active OpenVPN state, not as durable identities. Upstream documentation says both counters can eventually recycle, with collision-free recycling. In this daemon, `server_id + cid` is valid as a runtime-local active-session key, but it must not be used as persistent user/session identity after the OpenVPN process or session lifetime has ended.

## Compatibility Checks Required

These checks must be run against the latest OpenVPN 2.7 patch release, currently 2.7.4, before changing the daemon architecture.

1. Confirm `management-client-auth` works with a multi-socket server.

   Verified in Docker lab for UDP and TCP clients in one OpenVPN 2.7.4 process. All client auth events arrived on the single management interface.

2. Confirm the current `{cid,kid}` pair is sufficient to target the correct client auth event within a single OpenVPN process.

   Partially verified: `client-auth` targeted the correct UDP and TCP clients using the current `{cid,kid}` pair. `cid` values were unique within the process, while `kid` values may repeat across different clients and must not be treated as globally unique. `client-deny` and explicit `client-kill` still need negative-path lab coverage.

   Caveat: use the `kid` from the current OpenVPN management event. Do not reuse a stale `kid` across reconnect or reauth events.

3. Confirm whether management events expose exact accepted listener identity.

   Current result: they do not expose enough data for exact listener identity. `CLIENT:*` env lists configured listeners but not the accepted listener. Active `status 3` exposes protocol in the `Real Address` field, but not local bind address/port.

   Design decision: do not use `listener_id` as a routing, authorization, session ownership, callback state, or persistence key. Listener/protocol data may be logged as diagnostics only.

4. Confirm `status` output shape in multi-socket mode.

   Current result: active `CLIENT_LIST` and `ROUTING_TABLE` include protocol prefixes such as `udp4` and `tcp4-server` in the `Real Address` field. They do not include local bind address/port.

5. Confirm callback URL strategy.

   If one OpenVPN process owns all sockets and one daemon owns all sessions, callback URLs may not need listener-specific routing. A single callback URL may be enough:

   ```text
   https://vpn-auth.example.com/callback
   ```

   Do not keep listener-specific callback paths for daemon correctness. If old paths remain temporarily for infrastructure compatibility, the daemon must ignore them for authorization and route by signed state.

6. Confirm DCO compatibility.

   OpenVPN 2.7 supports the newer upstream Linux `ovpn` DCO module. This project must not assume DCO is available on the target EC2 kernel. DCO should be treated as a separate performance enhancement, not a requirement for the 2.7 migration.

7. Confirm config compatibility with removed/deprecated options.

   Known OpenVPN 2.7 changes relevant to audits:

   - static key `secret` mode is removed by default
   - `persist-key` is enabled by default
   - OpenSSL 1.0.2 and mbedTLS 2.x support were removed
   - send-side compression was removed
   - default server topology changed to `subnet`
   - `--dh none` is now the default if `--dh` is not specified

   Current project config already uses TLS/PKI server mode and explicitly sets `topology subnet`, so these items are not obvious blockers. Still verify the generated OpenVPN config with `openvpn --config ... --test-crypto` or an equivalent startup test on the target AMI.

## Recommended Migration Path

Do not build supervisor or custom multi-server daemon support before testing OpenVPN 2.7.4 management behavior. Supervisor remains the target architecture, but the first implementation task should be OpenVPN 2.7.4 migration and lab verification.

Recommended sequence:

1. Add an OpenVPN 2.7.4 lab profile. Done for the Docker lab, including the multi-socket profile.
2. Keep the existing two-process UDP/TCP deployment model initially.
3. Verify current daemon behavior against OpenVPN 2.7.4 with no daemon architectural changes. Done in the Docker lab for the current single-management-socket daemon flow.
4. Capture real management output from OpenVPN 2.7.4:
   - `CLIENT:CONNECT`
   - `CLIENT:REAUTH`
   - `CLIENT:DISCONNECT`
   - `status 3`
   - `client-auth`
   - `client-deny`
   - `client-kill`
   Use `--management-raw-log` only in lab/debug runs. It logs redacted raw management lines with `MGMT_RAW` at DEBUG level and must stay disabled in production.
   `CLIENT:CONNECT`, `CLIENT:REAUTH`, `CLIENT:DISCONNECT`, `status 3`, and `client-auth` are captured for the main positive paths. `client-deny` and explicit `client-kill` still need negative-path multi-socket coverage.
5. Add a multi-socket OpenVPN config in lab. Done for the Docker lab with one UDP listener and one TCP listener in a single OpenVPN process.
6. Repeat the same management-output capture in multi-socket mode. Partially done: positive callback/auth, reauth, disconnect, and status recovery are captured; negative paths and same-protocol/multi-address listener cases remain open.
7. Use the captured behavior to finalize the supervisor runtime/listener model. Current decision: model OpenVPN 2.7 multi-socket as one runtime per OpenVPN process, and do not use listener identity for routing or authorization.
8. Only after the remaining negative-path checks pass, collapse Terraform/cloud-init from separate UDP/TCP OpenVPN processes to one OpenVPN multi-socket process.

### Current Single-Socket Lab Result

Verified on May 9, 2026 against the Docker lab using OpenVPN `2.7.4-bookworm1`:

- OpenVPN 2.7.4 starts with the generated lab server config.
- The daemon connects to the Unix management socket, sends `hold release`, sends `status 3`, and completes bootstrap with zero established sessions.
- A real OpenVPN 2.7.4 client without `auth-user-pass` reaches the `management-client-auth` path with `auth-user-pass-optional`.
- OpenVPN sends `AUTH_PENDING` and `WEB_AUTH` to the client.
- The local `alb-mock` callback succeeds and the daemon sends `client-auth`.
- The client receives `PUSH_REPLY` and completes tunnel setup with `Initialization Sequence Completed`.

Observed daemon log fields for the connect event:

```text
cid=0 kid=1 cn=test-user@example.com ip=172.18.0.1 port=47857 plat=linux ver=2.7.4
```

Observed OpenVPN command path:

```text
MANAGEMENT: CMD 'hold release'
MANAGEMENT: CMD 'status 3'
MANAGEMENT: CMD 'client-pending-auth 0 1 "WEB_AUTH::http://localhost:8080/callback/01/udp?...'
MANAGEMENT: CMD 'client-auth 0 1'
```

Observed redacted raw management frames with `--management-raw-log` enabled:

```text
MGMT_RAW line=>CLIENT:CONNECT,0,1
MGMT_RAW line=">CLIENT:ENV,password=[REDACTED]"
MGMT_RAW line=">CLIENT:ENV,common_name=test-user@example.com"
MGMT_RAW line=">CLIENT:ENV,IV_VER=2.7.4"
MGMT_RAW line=">CLIENT:ENV,local_port_1=1194"
MGMT_RAW line=">CLIENT:ENV,proto_1=udp"
MGMT_RAW line=">CLIENT:ENV,remote_port_1=1194"
MGMT_RAW line=>CLIENT:ENV,END
MGMT_RAW line=>CLIENT:ADDRESS,0,10.8.0.2,1
MGMT_RAW line=>CLIENT:ESTABLISHED,0
MGMT_RAW line=>CLIENT:REAUTH,0,3
MGMT_RAW line=>CLIENT:REAUTH,0,4
MGMT_RAW line=>CLIENT:DISCONNECT,0
```

`CLIENT:REAUTH` used fresh `kid` values after the initial `CLIENT:CONNECT` (`1` -> `3` -> `4`). The daemon must continue using the `kid` from the current event and must not cache the connect-time `kid` for later reauth decisions.

`CLIENT:DISCONNECT,0` was captured during stale-session eviction through `client-kill`. A normal client-exit capture is still useful as an extra fixture, but the raw event shape is verified for the current parser path.

Observed raw `status 3` output during bootstrap:

```text
TITLE	OpenVPN 2.7.4 ...
TIME	...
HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Virtual IPv6 Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username	Client ID	Peer ID	Data Channel Cipher
HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)
GLOBAL_STATS	Max bcast/mcast queue length	0
GLOBAL_STATS	dco_enabled	1
END
```

This verifies the current single-management-socket daemon flow and raw management capture against OpenVPN 2.7.4. It does not verify multi-socket behavior.

The single-socket raw env contains `local_port_1`, `proto_1`, and `remote_port_1`. Treat this only as a useful observation. It does not prove that OpenVPN 2.7.4 exposes enough stable listener identity in multi-socket mode.

### Current Multi-Socket Lab Result

Verified on May 9, 2026 against the Docker lab using one OpenVPN `2.7.4-bookworm1` process with two listening sockets:

```text
local 0.0.0.0 1194 udp
local 0.0.0.0 1195 tcp-server
```

Lab harness:

```bash
VPN_AUTH_MANAGEMENT_RAW_LOG=true RENEG_SEC=30 make stack-rebuild-multisocket
REAUTH_WAIT=35 make verify-multisocket
```

Observed result:

- One OpenVPN process accepted both a UDP client and a TCP client.
- Both clients reached `AUTH_PENDING`, completed the browser callback through `alb-mock`, and established tunnels through the current daemon.
- `client-auth <cid> <kid>` worked for both UDP and TCP clients in the same OpenVPN process.
- `CLIENT:REAUTH` was captured for both clients after lowering `reneg-sec`.
- Restarting the daemon while both clients were connected forced a fresh management bootstrap and captured active `status 3` output.
- `CLIENT:DISCONNECT` was captured after stopping the TCP client container.

Concrete run details:

| Client | Connect Event | Reauth Event | Tunnel IP | `status 3` Real Address | Confirmed |
|---|---|---|---|---|---|
| UDP client `udp-user@example.com` | `CLIENT:CONNECT,2,1` | `CLIENT:REAUTH,2,3` | `10.8.0.2` | `udp4:172.18.0.1:50029` | connect, callback, `client-auth`, established, reauth, status recovery |
| TCP client `tcp-user@example.com` | `CLIENT:CONNECT,3,1` | `CLIENT:REAUTH,3,3` | `10.8.0.3` | `tcp4-server:172.18.0.1:43702` | connect, callback, `client-auth`, established, reauth, status recovery, disconnect |

The `cid` values were unique inside the one OpenVPN process. Both clients used connect-time `kid=1`; both later used reauth `kid=3`. The important invariant is still per-event freshness, not global uniqueness of `kid` by itself: management commands must target the current `{cid,kid}` pair from the current event.

Representative raw management events:

```text
MGMT_RAW line=>CLIENT:CONNECT,2,1
MGMT_RAW line=>CLIENT:ESTABLISHED,2
MGMT_RAW line=>CLIENT:REAUTH,2,3

MGMT_RAW line=>CLIENT:CONNECT,3,1
MGMT_RAW line=>CLIENT:ESTABLISHED,3
MGMT_RAW line=>CLIENT:REAUTH,3,3
MGMT_RAW line=>CLIENT:DISCONNECT,3
```

Important listener-identity finding:

```text
>CLIENT:ENV,local_port_2=1195
>CLIENT:ENV,local_2=0.0.0.0
>CLIENT:ENV,proto_2=tcp-server
>CLIENT:ENV,local_port_1=1194
>CLIENT:ENV,local_1=0.0.0.0
>CLIENT:ENV,proto_1=udp
>CLIENT:ENV,remote_port_1=1194
```

The same listener-list fields appeared on both UDP and TCP client events. This means `CLIENT:CONNECT`, `CLIENT:ESTABLISHED`, `CLIENT:REAUTH`, and `CLIENT:DISCONNECT` expose the configured listener list, but they do not unambiguously identify the listener that accepted the specific client.

Specific observations from the raw env:

- UDP and TCP events both contained `local_port_1=1194`, `proto_1=udp`, `local_port_2=1195`, and `proto_2=tcp-server`.
- UDP events included `remote_port_1=1194`.
- TCP events also included `remote_port_1=1194`, so `remote_port_1` is not a reliable accepted-listener indicator.
- The client source port appeared in `untrusted_port` and `trusted_port`; it changed by client connection and is not the OpenVPN listener port.
- The tunnel address appeared as `ifconfig_pool_remote_ip` after establishment/reauth/disconnect.

Do not derive `listener_id` from these event env fields.

Active `status 3` after daemon reconnect included protocol information in the `Real Address` field:

```text
CLIENT_LIST	tcp-user@example.com	tcp4-server:172.18.0.1:43702	10.8.0.3	...	3	1	AES-256-GCM
CLIENT_LIST	udp-user@example.com	udp4:172.18.0.1:50029	10.8.0.2	...	2	0	AES-256-GCM
ROUTING_TABLE	10.8.0.2	udp-user@example.com	udp4:172.18.0.1:50029	...
ROUTING_TABLE	10.8.0.3	tcp-user@example.com	tcp4-server:172.18.0.1:43702	...
```

This is useful for reconnect/bootstrap recovery and for distinguishing UDP vs TCP at a coarse diagnostic level. It still does not expose local bind address/port, so it is not enough for routing, authorization, session ownership, or persistent identity when multiple listeners share protocol or use multiple addresses.

Pragmatic decision for implementation: support OpenVPN 2.7 multi-socket mode as one `Runtime` connected to one management socket. Remove `listener_id` from the planned decision model. If listener/protocol data is exposed in logs, metrics, or debug output, treat it as best-effort diagnostics only.

Validated multi-socket assumptions:

- `management-client-auth` works through one management socket for both UDP and TCP listeners.
- `auth-user-pass-optional` still supports the browser-auth flow without static username/password.
- `client-auth <cid> <kid>` is sufficient for successful callback decisions for UDP and TCP clients in the same OpenVPN process.
- `CLIENT:REAUTH` keeps the same `cid` and provides a fresh `kid`.
- `status 3` after daemon reconnect can rebuild established sessions by `CLIENT_LIST` rows containing CN, virtual IP, CID, peer ID, and data-channel cipher.

Still not covered by this lab:

- `client-deny <cid> <kid>` negative path in multi-socket mode.
- Explicit `client-kill <cid>` against one active client while another active client remains connected.
- Multiple listeners with the same protocol, for example UDP `1194` and UDP `443`.
- Multiple local bind addresses.

## Required Daemon Target State

The project target is OpenVPN 2.7.4 compatibility including multi-socket server mode and multiple OpenVPN server processes on one EC2/VM. The daemon should support both deployment shapes:

1. One OpenVPN process per listener or server, one daemon runtime per management socket, all inside one daemon process.
2. One OpenVPN 2.7 multi-socket process, one daemon runtime connected to its management socket.

The second shape is preferred where it covers the deployment cleanly. The first shape must still be supported because operators may need multiple independent OpenVPN server processes on one VM for separate routing, config, PKI, or operational domains.

### Required Daemon Work

These changes are required regardless of the exact OpenVPN 2.7 event details:

- Keep the OpenVPN 2.7.4 lab/test profile current. The Docker lab profile exists.
- Keep the generated OpenVPN multi-socket lab config current, and later add the production Terraform/cloud-init equivalent when the target architecture is ready. The lab config exists; production deployment still uses separate UDP/TCP OpenVPN configs.
- Add daemon supervisor mode that can own multiple isolated management runtimes in one process.
- Add integration tests or scripted lab checks for:
  - initial connect
  - browser callback success
  - callback rejection
  - reauth
  - disconnect
  - `client-deny`
  - `client-kill`
  - management reconnect
- Record the OpenVPN version at daemon startup or health/debug output so operators can see whether the daemon is running against 2.6 or 2.7.
- Keep the management parser tolerant of additive fields in `CLIENT:*` and `status` output.
- Make logs and metrics ready for `server_id` / `runtime_id`. Listener/protocol fields, if present, are best-effort diagnostics only and must not be used as identity keys.
- Make callback state carry `server_id`, `cid`, and `kid`, then dispatch callback decisions by signed state rather than URL path alone.
- Document OpenVPN 2.7.4 as the supported target version once validation passes.
- Add explicit `vpn_group` configuration for single-session ownership. Default to `default` when unset.

### Conditional Daemon Work For Multi-Socket Mode

These changes are required if one daemon controls one OpenVPN 2.7 multi-socket process:

- Do not introduce `listener_id` as a stable daemon identity.
- Namespace session metadata by OpenVPN process/runtime, not by listener.
- Keep callback state scoped to `server_id`, `cid`, and `kid`; do not add `listener_id`.
- If protocol/listener-like fields are logged, keep them diagnostic-only:
  - logs may include `protocol_hint=udp|tcp|unknown` when safely inferred
  - metrics may include only low-cardinality diagnostic protocol labels when useful
  - health/debug output may show configured listeners for operator visibility
  - future distributed session records must not use listener/protocol as ownership keys
- Rework callback routing assumptions.
  - If one daemon owns all sockets, a single callback endpoint may be enough.
  - If listener-specific callback paths remain for infrastructure compatibility, the daemon must ignore them for authorization and route by signed state.
- Ensure HMAC state signing is deterministic across restarts and across any callback path that can reach another runtime.
  - Multi-socket target mode should require `--hmac-secret` or `--hmac-secret-secret-id`.
  - Random startup keys are acceptable only for local/dev single-runtime mode.
  - Secret rotation needs an explicit two-key verification window: sign new state with the current key, verify callbacks with current or previous key during rollout, then remove the previous key after at least one `hand-window` has elapsed. The signed state should either carry a `key_id`, or the verifier should use a small explicit keyring such as `current,previous`. Without this, rotating the HMAC secret kills in-flight browser callbacks.
- Add local cross-runtime single-session ownership.
  - Key ownership by `vpn_group + CN`.
  - Store owner as `server_id + cid + source_ip + connected_at`.
  - On a new connect for the same key, evict the old local owner even if it belongs to another management runtime in the same daemon process.
  - This improves enforcement on one EC2/VM but does not replace DynamoDB for cross-instance enforcement.
- Confirm that `client-auth`, `client-deny`, and `client-kill` commands need only `cid,kid` or `cid` in a multi-socket OpenVPN process.
  - If OpenVPN requires additional socket/listener scoping, update command generation.

### Parser Compatibility Work

OpenVPN 2.7 may add fields or change `status` output around multi-socket/listener reporting. The daemon must handle that without brittle parsing.

Required parser behavior:

- Ignore unknown `CLIENT:ENV` keys.
- Preserve useful unknown `CLIENT:ENV` keys in debug logs or structured event metadata during lab validation.
- Treat `CLIENT_LIST`/`status` parsing as additive: known columns are parsed, extra columns are ignored unless explicitly supported.
- Add fixtures captured from OpenVPN 2.7.4 management output.
- Keep existing OpenVPN 2.6 fixtures until the project fully drops 2.6 support.

### OpenVPN Config Work

The target OpenVPN 2.7.4 server config should be audited for these compatibility points:

- Use TLS/PKI mode, not removed static `secret` mode.
- Keep `topology subnet` explicit.
- Keep `dh none`; the current lab, Terraform, and PKI scripts do not generate or upload finite-field DH parameters.
- Keep compression disabled.
- Audit `auth-user-pass-optional` with OpenVPN 2.7.4 because it is core to this project's browser-auth flow: clients authenticate with certificate CN plus management-client-auth, not static username/password.
- TLS/cipher policy is explicit for the first release target:
  - `tls-version-min 1.2`
  - `cipher AES-256-GCM`
  - `data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305`
  - Whether a CHACHA20-first order would be better is uncertain without a real client/device profile.
- Decide whether DCO is enabled, disabled, or auto.
  - DCO is not required for 2.7 compatibility.
  - DCO depends on kernel/module/package availability and should be a separate deployment decision.
- Validate multi-socket syntax with OpenVPN 2.7.4 using `openvpn --config <file>` in CI/lab if possible.

### Historical PKI Migration (`ta.key` → `tls-crypt.key`)

Current repository state already uses `tls-crypt`: Terraform defines `{prefix}/pki/tls-crypt-key`, cloud-init fetches `/etc/openvpn/server/tls-crypt.key`, `make pki-init` generates `pki/tls-crypt.key`, and generated client profiles inline a `<tls-crypt>` block.

The steps below apply only to an older deployment or local PKI directory that still uses `tls-auth` / `ta.key`. They are not required for a fresh checkout using the current PKI tooling.

In that older deployment, moving from `tls-auth` to `tls-crypt` changes the shared control-channel key file from `ta.key` to `tls-crypt.key` and the corresponding Secrets Manager entry from `{prefix}/pki/ta-key` to `{prefix}/pki/tls-crypt-key`.

If Terraform creates a new `tls-crypt-key` secret resource, the value is not populated automatically. It must be uploaded explicitly. If the EC2 instance boots before the upload, `fetch-pki.sh` will fail to fetch the key and OpenVPN will fail to start because `/etc/openvpn/server/tls-crypt.key` is unavailable.

Migration steps for an older PKI directory that still has `ta.key`:

```bash
# 1. Generate tls-crypt.key without touching the CA or server cert
make pki-tls-crypt

# 2. Apply Terraform if the deployment does not already have the tls-crypt-key secret
cd terraform && terraform apply && cd ..

# 3. Upload the populated PKI artifacts to Secrets Manager
make pki-upload

# 4. Regenerate each user's .ovpn so it embeds the new tls-crypt key
#    (existing client certs/keys remain valid)
make pki-client-config CN=<email> REMOTE=<host>
```

`.ovpn` files inline `<tls-crypt>` from `pki/tls-crypt.key`, so any client config issued under the old `ta.key` setup must be regenerated and redistributed before users can reconnect.

For fresh PKI directories, `make pki-init` already generates `tls-crypt.key`; only the normal Terraform + upload sequence applies.

### Terraform/Systemd Work

Infrastructure should collapse from per-listener daemon services to one daemon service per EC2 instance:

- Prefer replacing `openvpn-server@udp` and `openvpn-server@tcp` with one multi-socket server unit when one OpenVPN config can cover the deployment.
- Keep support for multiple OpenVPN server units when separate OpenVPN processes are operationally required.
- Replace `openvpn-auth-udp` and `openvpn-auth-tcp` with one daemon unit.
- Replace per-protocol daemon callback health checks with one daemon health endpoint that reports per-runtime health.
- Revisit ALB/Lambda Router callback routing:
  - single callback target if one daemon owns all sessions
  - listener/protocol-specific paths only as temporary infrastructure compatibility, not daemon correctness
- Revisit target groups and ports:
  - OpenVPN traffic still needs listener-specific NLB/SG rules
  - callback traffic may need only one daemon callback port

### Health Semantics

The supervisor health surface must distinguish process health from runtime health.

Recommended endpoints:

- `/healthz`: ALB target health. Return `200` only when every configured runtime required for callback routing is connected to its OpenVPN management socket. Return non-`200` if any required runtime is unhealthy.
- `/readyz` or `/runtimez`: operator/debug health. Return structured per-runtime status, including `server_id`, connected state, last error, and last successful management connection time.

Rationale: ALB target health is binary. If a callback can be routed to a runtime whose management socket is down, the daemon should be considered not ready for that callback surface. For partial availability use a debug endpoint and metrics, not a misleading global `200`.

If future routing can prove that a callback path targets only a healthy subset of runtimes, path-aware health can be revisited. The first implementation should be strict: all configured runtimes healthy means `/healthz=200`.

### Graceful Shutdown Ordering

Multi-runtime shutdown must be explicit:

1. Stop accepting new callback requests.
2. Stop accepting new management events where possible, or mark runtimes draining.
3. Drain in-flight callbacks and auth-timeout goroutines.
4. Flush queued `client-deny`, `client-auth`, and `client-kill` decisions to each runtime command queue.
5. Close management connections.
6. Stop runtime goroutines.
7. Exit after a bounded shutdown deadline.

The shutdown deadline should be configurable or derived from `shutdown-grace-period`. Do not multiply the default `hand-window` by runtime count; runtimes drain concurrently.

### Uncertain Until Tested

Do not assume these are true until captured against OpenVPN 2.7.4:

- Whether `client-kill <cid>` is always unambiguous in a multi-socket process.
- Whether `client-deny <cid> <kid>` is unambiguous in a multi-socket process. `client-auth` is verified for UDP and TCP.
- Whether management reconnect behavior changes under failure conditions when multiple sockets are active. A daemon restart with two active clients successfully recovered sessions through `status 3`.
- Whether the current OpenVPN package source for Ubuntu exposes 2.7.4 and the needed build options.

## Strict Design Position

Before first release, breaking changes are acceptable. Prefer one daemon process per EC2/VM with multiple isolated runtimes over preserving the older two-daemon model.

However, do not ship a partial migration:

- Do not share one global session map across multiple OpenVPN processes without `server_id`.
- Do not send management commands to a socket unless the session is known to belong to that OpenVPN process.
- Do not use listener identity as a daemon routing, authorization, session ownership, callback state, or persistence key.
- Do not make random HMAC startup keys acceptable for any architecture where callbacks can cross daemon/runtime boundaries.
- Do not enforce single-session globally from local memory alone. Local cross-runtime enforcement helps one EC2/VM; cross-instance enforcement still requires the DynamoDB ownership design.

## Supervisor Vs Separate Daemons

The project is before first release, so breaking changes, backward compatibility, and preserving the current daemon-per-management-socket model are not blockers. The decision should optimize for the valid long-term architecture, not for minimizing churn in the current code.

If the only goal were "support multiple OpenVPN servers on one VM," keeping separate daemon processes would be the simpler design. It already matches the current code and gives each OpenVPN management socket an independent process boundary.

That is not the full project goal. The target includes:

- OpenVPN 2.7 multi-socket support
- multiple OpenVPN server processes on one EC2/VM
- local single-session enforcement across all local OpenVPN servers
- one callback service where practical
- cleaner first-release architecture, with breaking changes allowed before release

Given those goals, the supervisor design is the target architecture. Separate daemons cannot enforce local `vpn_group + CN` ownership across multiple local OpenVPN servers without adding HTTP/DynamoDB-style coordination even for same-VM cases. A supervisor can coordinate local cross-runtime eviction in-process while still keeping each OpenVPN management connection isolated.

Trade-off:

| Design | Advantages | Costs |
|---|---|---|
| Separate daemon per management socket | Simpler; lower per-process blast radius; easier systemd debugging; matches current code | No clean local single-session enforcement across servers; duplicated callback ports/services; more Terraform/systemd surface; weaker fit for one OpenVPN 2.7 multi-socket process |
| One supervisor daemon with isolated runtimes | Local cross-server single-session enforcement; one callback service; one health surface with per-runtime status; better fit for OpenVPN 2.7 multi-socket; cleaner first-release target | More concurrency complexity; larger process blast radius; requires strict state ownership |

Decision: implement one daemon supervisor per EC2/VM, with a hard limit of 8 isolated runtimes. Treat it as a deliberate redesign. Do not casually mutate the existing single-runtime daemon into shared global state. The safer implementation path is:

1. Migrate the lab/deployment target to OpenVPN 2.7.4 while keeping the current one-daemon-per-management-socket model.
2. Capture real OpenVPN 2.7.4 management behavior in both current and multi-socket lab modes.
3. Extract the current daemon loop into a `Runtime` that owns exactly one management socket.
4. Preserve single-runtime behavior with one runtime under a supervisor.
5. Add the supervisor registry and signed `server_id` callback routing.
6. Add multiple-runtime support for multiple OpenVPN processes.
7. Add OpenVPN 2.7 multi-socket support as one runtime without listener-based routing.

Why this sequence matters:

The current daemon is effectively one hardcoded runtime:

```text
daemon
  ├─ one management socket
  ├─ one command queue
  ├─ one session store
  ├─ one callback server
  └─ one reconnect/read/write loop
```

A risky migration would add multiple sockets directly to that structure with shared maps, shared queues, and conditional logic such as "if server A, write here; if server B, write there". That makes wrong-socket routing and `cid` collisions likely:

```text
daemon
  ├─ management socket A
  ├─ management socket B
  ├─ shared session map
  ├─ shared command queue
  └─ scattered server_id checks
```

The safer migration first wraps the existing one-socket behavior in a `Runtime`:

```text
Runtime
  ├─ one management socket
  ├─ one command queue
  ├─ one session store
  ├─ one reconnect/read/write loop
  └─ health for that OpenVPN process
```

At first, the supervisor has only one runtime, so behavior stays close to the current daemon:

```text
Supervisor
  └─ Runtime: default
```

Only after that should the daemon run multiple runtimes:

```text
Supervisor
  ├─ Runtime: ovpn-main
  └─ Runtime: ovpn-admin
```

The supervisor routes by signed `server_id`; the runtime owns the management socket. This makes isolation a property of the code structure, not a convention that every call site must remember.

### First Refactor Impact

The first implementation milestone should be conservative:

```text
Supervisor
  └─ Runtime: default
```

No multi-runtime, no DynamoDB, no local cross-runtime single-session enforcement, and no OpenVPN 2.7 multi-socket support in this first step. The goal is to preserve current behavior while putting the code into the right shape.

Current shape:

```text
main.go
  ├─ parse config
  ├─ create signer
  ├─ create identity checker
  ├─ create session store
  ├─ create auth handler
  ├─ create callback server
  ├─ create app.Daemon
  └─ daemon.Run()
```

Target first-step shape:

```text
main.go
  ├─ parse config
  ├─ create signer
  ├─ create identity checker
  ├─ create metrics
  ├─ create Supervisor
  │    └─ Runtime: default
  └─ supervisor.Run()
```

Conceptual ownership after the first refactor:

```text
Supervisor
  ├─ callback server
  ├─ signer
  ├─ identity checker
  ├─ metrics
  └─ runtimes map[string]*Runtime

Runtime
  ├─ management socket config
  ├─ command queue
  ├─ session store / CID state
  ├─ auth handler
  ├─ management reconnect loop
  └─ socket health
```

Expected complications:

- The callback server should no longer write to one hardcoded command queue. It should call the supervisor, and the supervisor should route to the runtime named by signed state.
- Health checks need a runtime-aware model, even when there is only one runtime.
- Signed callback state should start carrying `server_id`, initially `default`.
- Tests that construct `app.Daemon`, `auth.Handler`, or `callback.Server` may need constructor updates.
- Graceful shutdown must preserve the current behavior: pending decisions and timeout denials must still reach OpenVPN before the runtime stops.

Potential regressions to watch:

- Callback success verifies correctly but `client-auth` is not written to the runtime.
- Timeout denial is dropped during management reconnect or shutdown.
- Runtime command queue deadlocks because supervisor and runtime lifecycle are coupled incorrectly.
- `/healthz` reports healthy when the default runtime is not connected to the management socket.
- Session cleanup accidentally moves from runtime-local state to shared global state.

Risk controls for the first step:

- Keep exactly one runtime named `default`.
- Keep the existing CLI and environment variables unchanged.
- Keep the existing callback URL behavior unchanged.
- Keep the existing management socket behavior unchanged.
- Add `server_id=default` internally, but do not require operators to configure it yet. This intentionally changes the signed state token format while preserving external behavior; pre-release compatibility with old state tokens is not required.
- Preserve existing tests and add focused tests around supervisor-to-runtime routing.
- Do not add multi-runtime config until the single-runtime supervisor passes the existing suite.

The first milestone should be:

```text
Extract current daemon loop into Runtime; add Supervisor with one default runtime; preserve current behavior.
```

### Runtime Count Limit

One runtime equals one OpenVPN management socket. OpenVPN 2.7 multi-socket mode still counts as one runtime because it is one OpenVPN process and one management socket, even if that process has multiple listen sockets.

The daemon should enforce a hard limit of 8 runtimes per process:

```go
const MaxRuntimes = 8
```

Do not add a `--max-runtimes` flag in the first implementation. A constant is stricter and keeps the first release configuration surface smaller. If a deployment needs more than 8 OpenVPN management sockets in one daemon process, that should trigger an explicit architecture review and performance testing instead of a casual config change.

Rationale:

- each runtime owns reconnect/read/write loops
- each runtime owns a command queue
- each runtime owns CID/session state
- each runtime adds goroutines and health state
- a limit prevents accidental bad config from starting dozens of management loops
- a limit bounds the blast radius of one daemon process

Validation behavior:

- `len(runtimes) == 0`: configuration error
- `len(runtimes) > MaxRuntimes`: configuration error; daemon must refuse to start
- OpenVPN 2.7 listener count is separate from runtime count and should not consume this limit

## Decision Matrix

| Finding | Decision |
|---|---|
| `client-auth` was verified in multi-socket mode using the current `{cid,kid}` pair; `client-deny` and `client-kill` remain uncertain until negative-path lab coverage passes | Use one OpenVPN process/runtime where possible only after the remaining negative-path checks pass |
| Exact accepted listener identity is absent | Do not model `listener_id`; use diagnostics-only protocol hints if useful |
| Future negative-path tests prove `{cid,kid}` / `{cid}` are not enough to target auth or kill commands in one multi-socket OpenVPN process | Do not collapse those listeners into one OpenVPN process; use separate OpenVPN processes and one runtime per management socket |
| Future tests find `management-client-auth` gaps in multi-socket mode | Do not use OpenVPN multi-socket for that deployment; use multiple OpenVPN runtimes, one per process/listener |
| Multiple independent OpenVPN configs are needed on one VM | Use one daemon process with multiple management runtimes |
| DCO requires kernel/package work | Defer DCO; migrate userspace OpenVPN first |

## Open Questions

- Does `client-kill <cid>` remain unambiguous across all sockets in one process?
- Does `client-deny <cid> <kid>` remain unambiguous across all sockets in one process?
- Does ALB callback routing still need protocol/listener paths for infrastructure compatibility after the collapse to one daemon?
- Which OpenVPN 2.7.4 package source should the AMI use for Ubuntu, and does it include the needed DCO/userland build options?
