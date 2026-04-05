# Single-Session-Per-User in Multi-Instance Mode

## Current Limitation

`--single-session-per-user` (enabled by default) enforces one active VPN session per certificate CN by tracking a `CN → CID` mapping in an **in-memory store** local to each daemon instance.

In multi-instance (ASG) mode this means enforcement is **per-instance only**. If a user connects to instance A and then connects again to instance B, instance B has no knowledge of the existing session on instance A and cannot evict it. The user ends up with concurrent sessions on two different instances.

## Proposed Fix: DynamoDB Shared Session Store

Replace the in-memory `cnToActiveCID` map with a DynamoDB table shared across all instances. Eviction is **event-driven** — triggered synchronously on `CLIENT:CONNECT`, the same as today, with an extra network hop to the owning instance.

The same table can serve several additional purposes with minimal overhead (see [Additional Uses](#additional-uses)).

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

No polling is needed — eviction happens at connect time, consistent with the existing single-instance behaviour.

### DynamoDB Table Design

Two record types in a single table, distinguished by a `record_type` attribute:

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
| Instance A heartbeat expired / missing | Skip HTTP eviction call — instance is gone. The old OpenVPN session times out via `ping-restart`. |
| Instance A alive but HTTP eviction fails | Log and continue. Old session times out via `ping-restart`. |
| DynamoDB write failure on new connect | Soft error — log, continue with auth. Single-session enforcement degrades gracefully rather than blocking the connect. |
| Daemon crash without cleanup | Stale session and heartbeat records are removed automatically by TTL. |
| Simultaneous connects for the same CN | DynamoDB conditional writes (`ConditionExpression`) serialise the eviction and prevent races. |

---

## Additional Uses

The same DynamoDB table can serve additional purposes at low extra cost.

### Fleet-wide Session Visibility

Session records already contain `cn`, `instance_ip`, `cid`, and `connected_at`. Operators can query the table to get a fleet-wide view of who is connected and on which instance — without SSM-ing into each instance and running `status 3`. This is currently not possible at all in multi-instance mode.

A GSI on `instance_ip` allows per-instance queries (e.g. "which sessions are on this instance?"), useful when draining an instance before scale-in.

### Instance Heartbeat

Each daemon writes a `heartbeat#<instance_ip>` record every `heartbeat_interval` (e.g. 30s) with a TTL of `2 × heartbeat_interval`. Before making an HTTP eviction call, the connecting instance reads the heartbeat record:

- **Heartbeat present and recent** — instance is alive, proceed with the HTTP call
- **Heartbeat missing or TTL expired** — instance is gone, skip the HTTP call, clean up the stale session record

This avoids unnecessary connection timeouts during eviction and makes the edge case handling deterministic.

### Reauth Cache

The existing `--reauth-cache` stores successful reauth results in memory, keyed by username. Moving this to DynamoDB means:

- A restarted daemon still has cached results for active sessions (survives brief Cognito outages across restarts)
- A new instance that picks up a reconnecting user already has the cache entry

Reauth cache records can share the same table with a `pk` of `reauth#<username>` and a short TTL (`reneg-interval + 10m`, same as the current in-memory TTL).

> **Note:** The benefit here is marginal — reauth is always handled by the instance that owns the connection, so the cache is usually warm in single-instance mode. The main gain is resilience across daemon restarts.

---

## Required Changes

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
