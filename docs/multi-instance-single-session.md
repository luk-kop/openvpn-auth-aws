# Single-Session-Per-User in Multi-Instance Mode

## Current Limitation

`--single-session-per-user` (enabled by default) enforces one active VPN session per certificate CN by tracking a `CN → CID` mapping in an **in-memory store** local to each daemon instance.

In multi-instance (ASG) mode this means enforcement is **per-instance only**. If a user connects to instance A and then connects again to instance B, instance B has no knowledge of the existing session on instance A and cannot evict it. The user ends up with concurrent sessions on two different instances.

---

## Options

### Option 1: Accept the Limitation (recommended for most deployments)

The scenario where the same user simultaneously hits two different instances is uncommon. Under NLB load balancing, reconnects from the same source IP typically land on the same instance due to source-IP hashing. When it does happen, the user ends up with two concurrent sessions — which most deployments can tolerate.

**Effort:** none — the limitation is already documented.

**Trade-off:** strictness of single-session enforcement is degraded in multi-instance mode, but the practical impact is low.

### Option 2: NLB Sticky Sessions

Configure the NLB with source-IP stickiness so reconnects from the same client always route to the same instance. This covers the most common case (same user, same device reconnecting) without any daemon code changes.

**Effort:** Terraform-only change to the NLB target group.

**Trade-off:** does not help if the same user connects from two different IPs or devices simultaneously. Not a strict fix, but a cheap mitigation.

### Option 3: DynamoDB Shared Session Store

Replace the in-memory `cnToActiveCID` map with a DynamoDB table shared across all instances. Eviction is **event-driven** — triggered synchronously on `CLIENT:CONNECT`, same as today, with an extra network hop to the owning instance.

**Effort:** significant — new daemon package, internal HTTP endpoint, heartbeat goroutine, Terraform resources, new config flags, additional failure modes to handle.

**Trade-off:** the only true fix for strict cross-instance enforcement. The implementation complexity is justified if you also want the [additional benefits](#additional-uses) (fleet-wide session visibility, instance heartbeat, reauth cache) — the infrastructure cost is then shared across multiple features. If single-session enforcement is the sole goal, this is likely overengineering for most deployments.

> **DynamoDB overhead:** connect/disconnect events are infrequent — the added latency is ~1-5ms per `CLIENT:CONNECT`. At VPN traffic volumes, DynamoDB on-demand billing costs cents per month.

---

## Option 3 Design: DynamoDB Shared Session Store

### Connect Flow

```text
New CLIENT:CONNECT for alice@example.com on instance B
  │
  ├─ Check instance A heartbeat in DynamoDB — still alive?
  │
  ├─ Query DynamoDB for CN "alice@example.com"
  │    └─ Found: { instance_ip: "10.0.1.10", cid: 3 }
  │
  ├─ POST http://10.0.1.10:<internal-port>/internal/evict/3
  │    └─ Instance A sends `client-kill 3` to its local management socket
  │
  ├─ Write new session to DynamoDB: { cn, instance_ip: B, cid: new, connected_at, ttl }
  │
  └─ Proceed with normal auth flow (client-pending-auth → callback → client-auth)
```

No polling needed — eviction happens at connect time, consistent with existing single-instance behaviour.

### DynamoDB Table Design

Two record types in a single table, distinguished by a `pk` prefix:

**Session record** (one per active CN):

| Attribute | Type | Notes |
|-----------|------|-------|
| `pk` | String (PK) | `session#<cn>` |
| `instance_ip` | String | Private IP of the owning daemon instance |
| `cid` | Number | OpenVPN client ID on the owning instance |
| `connected_at` | String | ISO 8601 timestamp of the connect event |
| `ttl` | Number | Unix timestamp — DynamoDB TTL for stale entry cleanup |

**Heartbeat record** (one per daemon instance):

| Attribute | Type | Notes |
|-----------|------|-------|
| `pk` | String (PK) | `heartbeat#<instance_ip>` |
| `last_seen` | String | ISO 8601 timestamp of the last heartbeat write |
| `ttl` | Number | Unix timestamp — set to `now + 2 × heartbeat_interval` |

TTL on session records should be set to `now + hand_window + max_session_duration` (or a generous upper bound like 24h) so that entries are auto-expired if a daemon crashes without cleaning up.

### New Internal Endpoint

Each daemon exposes a VPC-internal HTTP endpoint:

```text
POST /internal/evict/{cid}
```

- Reachable only on a private port (separate listener, not behind the ALB)
- Receives the eviction request, sends `client-kill {cid}` to the local management socket
- Returns `200 OK` on success, `404` if the CID is not known locally

### Edge Cases

| Scenario | Behaviour |
|----------|-----------|
| Instance A heartbeat expired / missing | Skip HTTP eviction call — instance is gone. Old session times out via `ping-restart`. |
| Instance A alive but HTTP eviction fails | Log and continue. Old session times out via `ping-restart`. |
| DynamoDB write failure on new connect | Soft error — log, continue with auth. Enforcement degrades gracefully rather than blocking the connect. |
| Daemon crash without cleanup | Stale records removed automatically by TTL. |
| Simultaneous connects for the same CN | DynamoDB conditional writes (`ConditionExpression`) serialise eviction and prevent races. |

---

## Additional Uses

The same DynamoDB table can serve additional purposes at low extra cost — which is the main reason to choose Option 3 over simply accepting the limitation.

### Fleet-wide Session Visibility

Session records contain `cn`, `instance_ip`, `cid`, and `connected_at`. Operators can query the table for a fleet-wide view of who is connected and on which instance — without SSM-ing into each instance and running `status 3`. A GSI on `instance_ip` allows per-instance queries, useful when draining an instance before scale-in.

### Instance Heartbeat

Each daemon writes a `heartbeat#<instance_ip>` record every `heartbeat_interval` (e.g. 30s). Before making an HTTP eviction call, the connecting instance reads the heartbeat to determine whether the owning instance is still alive — avoiding unnecessary connection timeouts and making edge case handling deterministic.

### Reauth Cache

The existing `--reauth-cache` stores successful reauth results in memory. Moving this to DynamoDB means a restarted daemon retains cached results for active sessions, surviving brief Cognito outages across restarts.

> **Note:** The benefit is marginal — reauth is always handled by the instance that owns the connection, so the cache is usually already warm. The main gain is resilience across daemon restarts.

---

## Required Changes (Option 3)

**Daemon (`internal/`)**

- New `internal/dynamostore/` package implementing a shared store interface backed by DynamoDB (keeping the existing in-memory implementation for single-instance / local-dev mode)
- New internal HTTP endpoint (`/internal/evict/{cid}`) on a separate listener
- `internal/auth/handler.go` — replace direct `cnToActiveCID` operations with the store interface
- `internal/app/` — heartbeat writer goroutine
- `internal/config/config.go` — new flags:
  - `--dynamodb-table` (table name; empty = in-memory fallback)
  - `--internal-evict-port`
  - `--heartbeat-interval` (default `30s`)

**Terraform**

- New DynamoDB table resource (on-demand billing, TTL enabled, optional GSI on `instance_ip`)
- IAM policy additions: `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem`, `dynamodb:Query` on the table
- New variable `dynamodb_table_name` (empty = disabled, preserves current behaviour)
- Security group rule allowing inter-instance TCP traffic on the internal eviction port

## Backwards Compatibility

When `--dynamodb-table` is empty (the default), the daemon falls back to the existing in-memory store. Single-instance deployments and local development are unaffected.
