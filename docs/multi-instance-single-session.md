# Global Single-Session Enforcement in Multi-Instance Mode

## Table of Contents

- [Purpose](#purpose)
- [Current Limitation](#current-limitation)
- [Options](#options)
- [Option 3 Design: DynamoDB Shared Session Store](#option-3-design-dynamodb-shared-session-store)
- [Additional Uses](#additional-uses)
- [Required Changes (Option 3)](#required-changes-option-3)
- [Test Requirement: `client-kill` on Zombie UDP Session](#test-requirement-client-kill-on-zombie-udp-session)

> **Status:** This feature is **not currently implemented**. This document describes a planned design for future global single-session enforcement. Current code relies on OpenVPN's default per-process duplicate-CN behavior plus local daemon stale-state cleanup.

## Purpose

Global single-session enforcement would be a **credential sharing prevention control**. It would ensure that two parties using the same certificate and credentials cannot maintain concurrent VPN sessions within the same VPN group. A second connect for the same CN in the same `vpn_group` would evict the first — preventing an unauthorized user from silently sharing a legitimate user's credentials.

This is a future security control, not a convenience feature. Concurrent sessions for the same CN in the same `vpn_group` should be treated as a potential credential sharing incident when strict credential sharing prevention is a requirement.

## Current Limitation

OpenVPN rejects duplicate certificate CNs by default within a single server process, as long as `duplicate-cn` is absent. The daemon also tracks `CN → CID` in memory, but that tracking is local stale-state cleanup, not a user-facing single-session feature.

When more than one OpenVPN server process exists (for example UDP+TCP, multiple TCP listeners, multiple UDP listeners, or multiple EC2 instances), each process has separate OpenVPN client IDs. The planned one-daemon supervisor can share local ownership across multiple OpenVPN processes on the same EC2/VM, which allows local cross-runtime eviction. That improves enforcement on one VM, but it does not solve cross-instance enforcement. If a user connects to instance A and then connects again to instance B, instance B needs a shared ownership mechanism to know about the existing session on A.

---

## Options

### Option 1: Accept the Limitation

The scenario where the same user simultaneously hits two different instances is uncommon. Under NLB load balancing, reconnects from the same source IP typically land on the same instance due to source-IP hashing. When it does happen, the user ends up with two concurrent sessions — which some deployments can tolerate.

**Effort:** none — rely on OpenVPN's default per-process duplicate-CN behavior only.

**Trade-off:** credential sharing prevention is not guaranteed across multiple OpenVPN server processes or multiple instances. An attacker connecting from a different IP than the legitimate user may land on a different server process and bypass per-process duplicate-CN replacement entirely. Acceptable only if the deployment does not treat credential sharing as a security concern.

### Option 2: NLB Sticky Sessions (rejected)

Configure the NLB with source-IP stickiness so reconnects from the same client always route to the same instance.

**Rejected.** Does not help if the same user connects from two different IPs or devices simultaneously — which is exactly the credential sharing scenario. Source-IP stickiness routes the attacker (different IP) to a different instance, bypassing enforcement. Gives a false sense of security. Not suitable as a credential sharing prevention control. Also redundant when Option 3 (DynamoDB shared store) is implemented — DDB handles reconnects to any instance correctly.

### Option 3: DynamoDB Shared Session Store

Add a DynamoDB ownership table shared across all instances and OpenVPN auth daemons. Eviction is **event-driven** — triggered synchronously on `CLIENT:CONNECT`, same as today, with an extra network hop to the owning daemon. The existing in-memory `cnToActiveCID` map remains local stale-state cleanup, not the global ownership source.

> **Decision point:** If credential sharing prevention is a security requirement, Option 3 is the only viable choice. Options 1 and 2 do not provide cross-instance enforcement. Option 3 also enables fleet-wide session visibility and reauth cache persistence as secondary benefits.

**Effort:** significant — new daemon package, internal HTTP endpoint, Terraform resources, new config flags, additional failure modes to handle.

**Trade-off:** the only true fix for strict cross-instance enforcement. As a credential sharing prevention control, the implementation complexity is justified. The same infrastructure also enables [additional benefits](#additional-uses) (fleet-wide session visibility, reauth cache persistence).

> **DynamoDB overhead:** connect/disconnect events are infrequent — the added latency is ~1-5ms per `CLIENT:CONNECT`. At VPN traffic volumes, DynamoDB on-demand billing costs cents per month.

### Why DynamoDB

Credential sharing prevention requires **atomic conditional writes** — the ability to claim session ownership only if the current owner matches an expected value. Without this, concurrent connects for the same `vpn_group` + CN on different instances can both succeed (race condition), breaking the security control.

Alternatives evaluated:

| Option | Conditional writes | Why it fails |
|--------|-------------------|--------------|
| **S3** | `If-None-Match` only (create-if-not-exists) | Cannot express "replace only if old owner matches". No conditional overwrite. |
| **SSM Parameter Store** | None | Last-writer-wins. Race condition unsolvable. No TTL. |
| **ElastiCache (Redis)** | Via Lua scripts / `SET NX` | Works technically, but ~$13+/mo minimum (cache.t4g.micro). Stateful infra to maintain (patching, monitoring). Overkill for this volume. |
| **Direct P2P query** | None | Each instance queries all peers "do you have vpn_group X / CN Y?". Two instances can simultaneously query, both get "no", both accept. No atomic claim — race condition. |
| **EFS (file locks)** | `flock()` — uncertain reliability | POSIX locks over NFS in production is a minefield (stale locks after crash, NFS lock recovery). No TTL. Uncertain whether `flock()` on EFS is reliable for distributed locking. |

DynamoDB is the only option that provides:

1. Native conditional writes covering both cases (create-if-not-exists + replace-if-owner-matches)
2. Built-in TTL for automatic stale record cleanup
3. Zero operational maintenance (serverless, no patching, no capacity planning)
4. On-demand billing at effectively $0/mo for this throughput

The operational cost of a single DynamoDB table with one record type is near-zero after initial setup — unlike Redis or ElastiCache, there is no replication, patching, or failover to manage.

---

## Option 3 Design: DynamoDB Shared Session Store

### Connect Flow

```text
New CLIENT:CONNECT for alice@example.com in vpn_group "devops" on instance B
  │
  ├─ GetItem from DynamoDB for vpn_group "devops", CN "alice@example.com"
  │    ├─ Not found → Conditional PutItem (attribute_not_exists(pk)) → claim ownership → proceed
  │    └─ Found: { vpn_group: "devops", instance_ip: "10.0.1.10", server_id: "devops-udp-1194", internal_evict_port: 18094, cid: 3 }
  │
  ├─ HTTP evict with retry:
  │    POST http://10.0.1.10:18094/internal/evict/devops-udp-1194/3
  │    ├─ 2s connect+read timeout per attempt
  │    ├─ Up to 3 attempts with exponential backoff (100ms, 200ms, 400ms)
  │    └─ Owning daemon validates server_id "devops-udp-1194" and sends
  │       `client-kill 3` to its local management socket
  │
  ├─ Conditional PutItem to DynamoDB:
  │    ├─ ConditionExpression: attribute_not_exists(pk) OR
  │    │    (instance_ip = :old_ip AND server_id = :old_server_id AND cid = :old_cid)
  │    ├─ Semantics: "claim if no owner, OR replace exactly the record I just evicted"
  │    └─ If ConditionalCheckFailed → retry from GetItem (max 3 iterations)
  │
  └─ Proceed with normal auth flow (client-pending-auth → callback → client-auth)
```

No polling needed — eviction happens at connect time, consistent with existing single-instance behaviour.

**Retry cap:** The GetItem → Evict → Conditional PutItem loop is capped at 3 iterations. ConditionalCheckFailed means another instance claimed the same `vpn_group` + CN between our GetItem and PutItem — retry sees the new owner and evicts them. At 2-3 instances, more than 2 collisions is pathological. After cap exhaustion: soft-fail (log, emit `EvictionRetryExhausted` metric, continue with auth without cross-instance enforcement).

**Eviction failure:** If all HTTP retry attempts fail (instance unreachable), log and continue. The old session dies via OpenVPN `ping-restart` (~120s for UDP). The conditional PutItem still succeeds — the new instance becomes the owner in DynamoDB regardless of whether the old session was actively killed.

This is **soft enforcement** during failure. For a short window there can be two active sessions for the same `vpn_group` + CN if the old daemon cannot be reached. The alternative is fail-closed (deny the new connection when eviction fails), but that turns transient instance/network failures into user-visible login failures and can lock out the legitimate user during replacement or partial outage. This design chooses availability and explicit alerting over strict fail-closed behavior.

### Self-Eviction Fast Path

When the DynamoDB session record shows `instance_ip` and `server_id` matching the current daemon/server, the daemon skips the HTTP eviction call and performs local eviction directly:

1. `SessionStore.Get(vpnGroup, cn)` returns record with `instance_ip == self` and `server_id == self`
2. Local `evictSession(oldCID)` — `client-kill` on the local management socket (synchronous, sub-ms)
3. Conditional PutItem with new CID (same condition expression as cross-instance flow)

This is the fastest eviction path when the old session belongs to the same local OpenVPN server process. With the planned one-daemon supervisor, if the old session belongs to a different local OpenVPN process on the same EC2/VM, the daemon should route the eviction through its in-process runtime registry rather than the internal HTTP endpoint. If the old session belongs to a different EC2 instance, the daemon still uses the internal eviction endpoint with the stored `instance_ip`, `internal_evict_port`, and `server_id`.

**Bootstrap invariant:** The self-eviction fast path relies on the daemon's management socket bootstrap (`hold release` → `status 3` → rebuild `cids`) completing before any `CLIENT:CONNECT` events are processed. After a daemon restart, bootstrap rebuilds local CID state from the live OpenVPN snapshot, so `evictSession(oldCID)` in step 2 will find the CID if the session is still alive in OpenVPN.

Without the DDB update in step 3, the session record would contain a stale CID. A subsequent connect on a different instance would see the stale record, attempt an HTTP eviction for a CID that no longer exists (404 from the endpoint), and proceed — functionally correct but wasteful.

### Eviction Policy

The eviction policy is **new-wins**: a new `CLIENT:CONNECT` for a `vpn_group` + CN that already has an active session evicts the old session. This is hardcoded, not configurable.

**Why new-wins:**

- **Visibility for the legitimate user.** When an attacker connects with shared credentials, the legitimate user is disconnected and sees an immediate reconnect/re-auth prompt. This is a visible signal that something is wrong with their credentials. With an "old-wins" policy, the attacker who connects first sits silently — the legitimate user gets a generic deny and may assume it is a bug.
- **Alertable ping-pong.** If both parties are online, new-wins produces a rapid series of connect/evict/connect events — a loud signal that is trivially alertable. Old-wins produces a single quiet deny.
- **User agency.** The legitimate user can reconnect and reclaim the session. The attacker is evicted. The resulting ping-pong triggers security alerts and SOC response.

**Why not old-wins:** Old-wins protects the first session, but if the attacker connects first (e.g. user is offline), the attacker holds the session indefinitely. The legitimate user is locked out with no indication of compromise. This is a worse security outcome than new-wins.

**Response policy:** The daemon does not automatically disable users or revoke certificates on eviction. That decision belongs to SOC based on the security event context (see [Security Event Logging](#security-event-logging)). Automatic response would be weaponizable — an attacker could deliberately trigger evictions to lock out the legitimate user.

**Rejected: Eviction rate-limiting / circuit breaker.** A per-`vpn_group`+CN rate limit (e.g. deny both sides after N evictions in a time window) was considered to mitigate ping-pong storms. Rejected because:

- **Weaponizable as DoS.** An attacker who knows about the circuit breaker can deliberately trigger N connects to trip it, locking out the legitimate user.
- **Disproportionate complexity.** Requires sliding window counter per CN, configurable threshold and window, "circuit open" state with TTL, and logic for what happens when the circuit closes.
- **Alert without circuit breaker is sufficient.** `SingleSessionViolation` metric with full forensic context gives SOC everything needed to react. SOC can disable the user in Cognito within minutes.
- **Ping-pong does not destabilize the management interface.** `client-kill` is a single line on the socket — OpenVPN handles it without issue.

### DynamoDB Table Design

Single record type — **session record** (one per active `vpn_group` + CN):

| Attribute | Type | Notes |
|-----------|------|-------|
| `pk` | String (PK) | `session#<vpn_group>#<cn>` |
| `vpn_group` | String | Logical VPN group/session scope, e.g. `devops`, `devs`, `hr`, or `default`. Single-session enforcement applies within this group only. |
| `instance_ip` | String | Private IP of the owning daemon instance |
| `server_id` | String | Stable identifier of the owning OpenVPN server process/listener, e.g. `vpn-udp-1194`, `vpn-tcp-443`, `blue-tcp-8443`. This is intentionally not named `protocol`: one EC2 instance can run multiple TCP or UDP OpenVPN servers. |
| `internal_evict_port` | Number | Internal eviction listener port for the owning daemon process. In the target one-daemon-per-VM model this is shared by all local OpenVPN runtimes; `server_id` selects the runtime inside that daemon. |
| `source_ip` | String | Client's `untrusted_ip` from `CLIENT:CONNECT` env — needed for security event logging |
| `cid` | Number | OpenVPN client ID on the owning `instance_ip` + `server_id` |
| `connected_at` | String | ISO 8601 timestamp of the connect event |
| `ttl` | Number | Unix timestamp — DynamoDB TTL for stale entry cleanup |

TTL on session records should be set to `now + max(24h, 2 × max_session_duration)` so that entries are auto-expired if a daemon crashes without cleaning up. The TTL must be refreshed on every `CLIENT:REAUTH` to prevent expiry during long-lived sessions — reauth already touches the session record's owning instance, so a conditional UpdateItem (same owner check) to bump the TTL adds negligible cost.

A single DynamoDB table can hold all VPN groups. Separate tables for `devops`, `devs`, `hr`, etc. are not required because `vpn_group` is part of the primary key. Use separate tables only if the groups need different AWS accounts, IAM boundaries, retention policies, or operational ownership.

### Conditional Expressions

Two DynamoDB operations use conditional expressions to prevent races:

**Claim (PutItem on connect):**

```
ConditionExpression: attribute_not_exists(pk) OR
  (instance_ip = :old_ip AND server_id = :old_server_id AND cid = :old_cid)
```

Semantics: "write if no owner exists, OR if I am replacing exactly the record I just evicted". The `vpn_group` + CN scope is enforced by the primary key (`pk = session#<vpn_group>#<cn>`); the condition only verifies that the current owner for that key still matches the owner observed before eviction. If a third instance claimed the same `vpn_group` + CN between GetItem and PutItem, the condition fails and the caller retries the full flow.

**Release (DeleteItem on disconnect):**

```
ConditionExpression: instance_ip = :self AND server_id = :self_server_id AND cid = :my_cid
```

Semantics: "delete only if I am still the owner". This prevents a delayed `>CLIENT:DISCONNECT` on instance A from deleting a session record that instance B has already claimed. If the condition fails (owner changed), the delete is a no-op.

**Delayed disconnect scenario:** User connects on A/server-1 (PutItem A/server-1/cid=5). User reconnects on B/server-2 → B evicts A/server-1, claims ownership (PutItem B/server-2/cid=7). Delayed DISCONNECT arrives on A/server-1 → A attempts DeleteItem. Without the condition, A would delete B's record. With the condition (`instance_ip=A AND server_id=server-1 AND cid=5`), the delete fails because the record now has `instance_ip=B, server_id=server-2, cid=7` — B's session is preserved.

### New Internal Endpoint

Each OpenVPN auth daemon exposes a VPC-internal HTTP endpoint for eviction:

```text
POST /internal/evict/{server_id}/{cid}
```

- Listens on a dedicated port (`--internal-evict-port`), separate from the ALB-facing callback port
- Receives the eviction request, verifies `server_id` matches the daemon's own configured `--server-id`, and sends `client-kill {cid}` to its local OpenVPN management socket
- Returns `200 OK` on success, `404` if the CID is not known locally

`server_id` is a local OpenVPN server identifier, not a network protocol. The default deployment could use values like `udp` and `tcp`, but the design must allow more specific IDs such as `vpn-udp-1194`, `vpn-udp-1195`, or `vpn-tcp-443` so multiple OpenVPN servers on one EC2 instance remain distinguishable.

**Daemon topology:** target one daemon process per EC2/VM with multiple isolated OpenVPN management runtimes. The internal eviction listener is per daemon process, not per OpenVPN runtime. Each session record still stores `server_id` so the receiving daemon can route `client-kill` to the correct local runtime. A replacing daemon sends the eviction request to `http://<instance_ip>:<internal_evict_port>/internal/evict/<server_id>/<cid>`.

**Security recommendation:** use network isolation as the default access control, with optional shared-HMAC request signing for deployments that need defense in depth.

**Default: SG-only / network isolation**

- Security group: self-referencing SG rule — only instances in the same VPN SG can reach the internal eviction port. No public ingress.
- This is acceptable when the VPN security group contains only VPN instances and there is no lateral access from unrelated workloads.
- Blast radius: an attacker with lateral movement inside the VPN security group could iterate over CID values and evict sessions across the fleet, disrupting active VPN users. Evicted users must complete a full re-authentication through ALB/Cognito — this is not a transparent auto-reconnect. However, this threat model already implies broader access to management sockets, DynamoDB, and Cognito APIs, making the eviction endpoint one of several internal control-plane risks.

**Recommended hardening: shared HMAC**

For production environments where unrelated hosts can reach the same VPC, where the VPN security group is not tightly dedicated, or where defense in depth is required, add shared-HMAC signing to daemon-to-daemon eviction requests.

Request headers:

```text
X-Evict-Timestamp: <unix-seconds>
X-Evict-Nonce: <random-128-bit-base64url>
X-Evict-Signature: <base64url-hmac-sha256>
```

Signature input:

```text
METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE
```

Receiver requirements:

- Reject missing or invalid signatures with `401 Unauthorized`
- Reject timestamps outside a short skew window, e.g. ±30s
- Keep a small in-memory nonce cache for the skew window and reject nonce replays
- Fetch the shared secret from AWS Secrets Manager or SSM Parameter Store
- Support secret rotation with a current + previous secret during rollout

Fleet rollout requirement: all daemons that can evict each other must use a consistent HMAC mode. A daemon that requires HMAC will reject unsigned requests from older daemons. If zero-downtime rollout from SG-only to HMAC is required, implement a temporary compatibility mode that signs outbound requests but accepts both signed and unsigned inbound requests, then switch the fleet to require signatures after all instances have been updated.

This adds meaningful protection against request spoofing from another compromised host in the VPC while keeping the endpoint simple and direct. It does not replace security-group isolation; it layers on top of it.

**Rejected for the initial design: mTLS and SigV4**

- **mTLS** provides strong daemon identity, but requires certificate issuance, trust anchor management, file permissions, rotation, and TLS listener configuration for every daemon. That is disproportionate for a narrow internal eviction endpoint.
- **AWS SigV4** is attractive conceptually, but a custom daemon HTTP server would need robust SigV4 verification or the traffic would need to be routed through another AWS service. That adds more moving parts than the eviction path needs.

**Timeouts and retry:**

- 2s connect+read timeout per HTTP attempt
- Up to 3 attempts with exponential backoff (100ms, 200ms, 400ms)
- If all attempts fail: log, continue with auth. Old session dies via `ping-restart` (~120s for UDP).
- Total worst-case latency added to `CLIENT:CONNECT`: ~7s per iteration (3 × 2s timeout + backoff). With the ConditionalCheckFailed retry loop (cap=3), the theoretical maximum is ~21s — but this requires 3 concurrent races for the same `vpn_group` + CN, which is pathological at 2-3 instances. Well within `auth-timeout` budget (270s).

### Edge Cases

| Scenario | Behaviour |
|----------|-----------|
| Instance A unreachable (crashed, terminated) | HTTP eviction times out after 3 retry attempts (~7s). Conditional PutItem claims ownership. Old session dies via `ping-restart` (~120s for UDP). Soft enforcement: concurrent sessions can exist until OpenVPN times out the old one. |
| Instance A alive, session is UDP zombie (client gone, `ping-restart` not yet fired) | HTTP eviction succeeds (~2-5ms). `client-kill` terminates the zombie session in OpenVPN immediately — no need to wait for `ping-restart`. Most common reconnect scenario for UDP. |
| Instance A alive but HTTP eviction fails (transient) | Retry 2-3x. Transient failures (GC pause, brief packet loss) typically resolve on retry. After exhaustion: log, continue with soft enforcement. |
| DynamoDB write failure on connect | Soft error — log, continue with auth. Cross-instance enforcement degrades gracefully rather than blocking the connect. |
| Daemon crash without cleanup | Stale session records removed automatically by DynamoDB TTL. |
| Simultaneous connects for same `vpn_group` + CN (race) | Conditional PutItem (`attribute_not_exists(pk) OR (instance_ip = :old_ip AND server_id = :old_server_id AND cid = :old_cid)`) serialises ownership. Loser gets ConditionalCheckFailed, retries from GetItem (max 3 iterations). |
| Delayed DISCONNECT overwrites new owner | Conditional DeleteItem (`instance_ip = :self AND server_id = :self_server_id AND cid = :my_cid`) prevents. If owner changed, delete is a no-op. |
| Conditional PutItem retry exhausted (cap=3) | Soft-fail: log, emit `EvictionRetryExhausted` metric, continue with auth without cross-instance enforcement. |

### Security Event Logging

Every eviction due to single-session enforcement is a potential credential sharing event and must be logged with forensic context.

**EMF metric:** `SingleSessionViolation` with dimensions `Instance`, `VPNGroup`, and `CN`. Alertable — N violations for the same `vpn_group` + CN in a time window (e.g. 3 in 60s) indicates active credential sharing or ping-pong.

**Structured log entry** (emitted on every eviction):

```json
{
  "level": "WARN",
  "msg": "single_session_violation",
  "security_event": "credential_sharing_suspected",
  "vpn_group": "devops",
  "cn": "alice@example.com",
  "new_session": {
    "cid": 7,
    "instance_ip": "10.0.1.20",
    "server_id": "devops-tcp-443",
    "internal_evict_port": 18443,
    "source_ip": "203.0.113.50",
    "source_port": "51234"
  },
  "evicted_session": {
    "cid": 3,
    "instance_ip": "10.0.1.10",
    "server_id": "devops-udp-1194",
    "internal_evict_port": 18094,
    "source_ip": "198.51.100.22",
    "connected_at": "2026-04-18T08:00:00Z"
  },
  "time_delta_seconds": 900
}
```

**Fields:**

| Field | Source | Purpose |
|-------|--------|---------|
| `vpn_group` | Current daemon/server config | Logical VPN group/session scope for this enforcement decision |
| `cn` | `CLIENT:CONNECT` env `common_name` | Identifies the shared credential |
| `new_session.server_id` | Current daemon/server config | Identifies the OpenVPN server process that accepted the new session |
| `new_session.internal_evict_port` | Current daemon/server config | Internal eviction port for the daemon that accepted the new session |
| `new_session.source_ip` | `CLIENT:CONNECT` env `untrusted_ip` | Attacker or legitimate user IP |
| `evicted_session.server_id` | Session record | Identifies the OpenVPN server process that owned the evicted session |
| `evicted_session.internal_evict_port` | Session record | Internal eviction port used to reach the owning daemon |
| `evicted_session.source_ip` | Stored from original `CLIENT:CONNECT` | Other party's IP |
| `evicted_session.connected_at` | Session record | How long the evicted session was active |
| `time_delta_seconds` | `now - evicted_session.connected_at` | Short delta + different IPs = strong credential sharing signal |

All data is already available: `untrusted_ip` and `untrusted_port` come from the `CLIENT:CONNECT` env variables, `connected_at`, `instance_ip`, `vpn_group`, `server_id`, and `internal_evict_port` come from the DynamoDB record. The daemon must add its own configured `vpn_group`, `server_id`, and `internal_evict_port` to new-session logs.

---

## Additional Uses

The DynamoDB table introduced for credential sharing prevention is a good starting point for additional features at low extra cost. The infrastructure (table, IAM, SDK integration) is already in place — extending it to new use cases requires minimal incremental effort.

### Fleet-wide Session Visibility

Session records contain `vpn_group`, `cn`, `instance_ip`, `server_id`, `internal_evict_port`, `cid`, and `connected_at`. Operators can query the table for a fleet-wide view of who is connected and on which instance/server — without SSM-ing into each instance and running `status 3`. A GSI on `instance_ip` allows per-instance queries, useful when draining an instance before scale-in. A GSI on `vpn_group` can be added if operators need frequent group-level inventory queries.

### Instance Heartbeat (not implemented, not required for eviction)

Each daemon writes a `heartbeat#<instance_ip>` record every `heartbeat_interval` (e.g. 30s). This is **not used by the eviction flow** — eviction always attempts the HTTP call regardless of heartbeat state, with retry and timeout handling.

Heartbeat is useful independently for fleet-wide instance liveness monitoring: operators can query the table to see which instances are alive without SSM-ing into each one. It can be added later as a separate feature if needed.

### Reauth Cache

The existing `--reauth-cache` stores successful reauth results in memory. Moving this to DynamoDB means a restarted daemon retains cached results for active sessions, surviving brief Cognito outages across restarts.

> **Note:** The benefit is marginal — reauth is always handled by the instance that owns the connection, so the cache is usually already warm. The main gain is resilience across daemon restarts.

---

## Required Changes (Option 3)

**Daemon (`internal/`)**

- New `SessionStore` interface in `internal/auth/` with two implementations:
  - In-memory (existing behaviour, used when `--dynamodb-table` is empty)
  - DynamoDB-backed (`internal/dynamostore/` package)
  - Interface: `Get(ctx, vpnGroup, cn)`, `Claim(ctx, vpnGroup, cn, new, expectedOld)`, `Release(ctx, vpnGroup, cn, expectedOwner)`
- `internal/auth/handler.go` — add `SessionStore` calls around connect/disconnect ownership decisions. Keep `cnToActiveCID` for local stale-state cleanup and status rebuild; it is still useful for local CIDs but must not be treated as the global ownership source.
- New internal HTTP endpoint (`/internal/evict/{server_id}/{cid}`) on a separate listener (`--internal-evict-port`)
- `internal/config/config.go` — new flags:
  - `--dynamodb-table` (table name; empty = in-memory fallback)
  - `--vpn-group` (logical VPN group/session scope; default `default`; stored in DynamoDB records and used in the session key)
  - `--server-id` (stable local OpenVPN server identifier stored in DynamoDB records; required when `--dynamodb-table` is set)
  - `--internal-evict-port` (stored in DynamoDB records; one per daemon process; ignored when `--dynamodb-table` is empty — listener does not start)
  - `--internal-evict-hmac-secret-id` (optional Secrets Manager or SSM secret/parameter ID; enables HMAC signing for daemon-to-daemon eviction)
- `instance_ip` source: the daemon's own IP for DynamoDB records and self-eviction detection must come from EC2 IMDS (`http://169.254.169.254/latest/meta-data/local-ipv4`). This is the same private IP used in the Lambda Router callback URL. Fetched once at startup via the AWS SDK IMDS client; fatal error if unavailable.
- Optional shared-HMAC support for eviction requests:
  - Sign outbound eviction requests with `X-Evict-Timestamp`, `X-Evict-Nonce`, and `X-Evict-Signature`
  - Verify inbound signatures before issuing `client-kill`
  - Reject timestamp skew and nonce replay
  - Allow current + previous secret during rotation
- New EMF metric: `EvictionRetryExhausted` with `Instance` dimension — emitted when the conditional PutItem retry cap (3) is exhausted. Signals pathological contention if it appears.
- New EMF metric: `SessionStoreError` with `Instance` and `Operation` dimensions — emitted on any DynamoDB failure (GetItem, PutItem, DeleteItem) during session store operations. Without this, DynamoDB unavailability silently degrades the credential sharing prevention control. Alertable — sustained errors mean cross-instance enforcement is offline.
- New EMF metric: `SingleSessionViolation` with `Instance`, `VPNGroup`, and `CN` dimensions — emitted on every eviction due to single-session enforcement. Alertable for credential sharing detection.
- Structured security event log on every eviction: `security_event=credential_sharing_suspected` with forensic context (source IPs, timestamps, time delta). Uses existing `CLIENT:CONNECT` env variables and session record data — no new data collection required. See [Security Event Logging](#security-event-logging).

**Terraform**

- New DynamoDB table resource (on-demand billing, TTL enabled on `ttl` attribute, optional GSI on `instance_ip` for fleet-wide queries)
- IAM policy additions: `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem`, `dynamodb:Query` on the table
- Optional IAM policy additions for HMAC hardening: `secretsmanager:GetSecretValue` or `ssm:GetParameter` on the configured eviction HMAC secret/parameter
- New variable `dynamodb_table_name` (empty = disabled, preserves current behaviour)
- New optional variable `internal_evict_hmac_secret_id` (empty = SG-only)
- Security group rule: self-referencing SG allowing TCP traffic on the configured internal eviction port range between VPN instances only

## Test Requirement: `client-kill` on Zombie UDP Session

The eviction design assumes that `client-kill` on a zombie UDP session (client gone, `ping-restart` not yet fired) terminates the OpenVPN-side session immediately and emits `>CLIENT:DISCONNECT` without waiting for `ping-restart`. This must be verified empirically before or during implementation.

**Procedure:**

1. Connect a UDP client, note CID from management socket
2. On the client machine: `iptables -I OUTPUT -p udp --dport 1194 -j DROP` (simulates disappearance — client alive but packets dropped)
3. In management socket: `client-kill <CID>`, note timestamp T1
4. Wait for `>CLIENT:DISCONNECT` event, note timestamp T2
5. Immediately after kill (before T2): run `status 3` — check if CID is still in `CLIENT_LIST`

**Interpretation:**

| Result | Meaning | Action |
|--------|---------|--------|
| T2 - T1 < 1s, CID gone from `status 3` | `client-kill` terminates zombie immediately | No additional work needed |
| T2 - T1 ≈ 120s, CID persists in `status 3` | `client-kill` waits for `ping-restart` | Add periodic `status 3` reconciliation (e.g. every 60s) as follow-up |
| No T2 event | Pathological — `client-kill` on zombie does not emit disconnect | Design problem — requires investigation |

**Do not implement periodic `status 3` reconciliation preemptively.** Only add it if the test confirms the `ping-restart` delay variant.
