# DynamoDB Global Session Ownership

> **Status: planned, not implemented**
>
> This document specifies an optional DynamoDB-backed mechanism for eventual
> single-session enforcement across multiple OpenVPN instances. It does not
> describe current runtime behavior.

## Summary

DynamoDB records the intended current owner and drives convergence toward one
active session. The session scope is configurable: an eventual owner per
session domain + identity, or an eventual owner per identity across every
daemon using the table. Enforcement uses periodic polling rather than direct
daemon-to-daemon eviction endpoints.

The feature is optional. When no DynamoDB table is configured, the daemon
keeps its current local session behavior and makes no DynamoDB calls.

The global store extends the daemon's availability-first local ownership model
across independent OpenVPN processes. Locally, identities are normalized with
Unicode-aware lowercase conversion. A new `CLIENT:CONNECT` starts an attempt
but never evicts an established session. The winner changes only after the new
client reaches `CLIENT:ESTABLISHED` (or an authoritative snapshot classifies it
as established). OpenVPN removes an exact-CN predecessor natively when
`duplicate-cn` is absent; the daemon issues `client-kill` after establishment
for case-only variants such as `Alice@example.com` and `alice@example.com`.

There is no `--single-session-per-user` flag in the current implementation, and
this design does not introduce one. DynamoDB does not replace local CID/CN
tracking.

The store also requires `--cn-cross-check=true`. The callback must bind the
certificate CN to the authenticated OIDC `email` claim before the normalized
CN can be treated as the global user identity. Enabling the table with CN
cross-check disabled is a startup configuration error.

The design intentionally provides eventual, not immediate, enforcement:

- ownership policy is `new-wins`;
- the default polling interval is **1 minute** with +/-20% jitter;
- during healthy operation, two sessions may coexist for approximately one
  polling interval after the new ownership claim succeeds;
- DynamoDB failures are **fail-open** and do not interrupt authentication or
  established VPN sessions.

### Behavioral contract: eventual new-wins

This feature deliberately mirrors OpenVPN's default per-process new-wins policy
across processes and instances, but with asynchronous eviction:

1. A fully authenticated new session is allowed to become established without
   waiting for the previous owner to disconnect.
2. The new session claims the DynamoDB ownership record.
3. The previous owner detects the different `owner_id` through polling and
   terminates its local OpenVPN session.
4. With DynamoDB available, polling running, and the management socket able to
   execute `client-kill`, the system converges to the current owner after the
   claim plus an ownership polling cycle.

At-most-one is therefore a **steady-state convergence target**, not an invariant
maintained at every instant. A short overlap is expected during normal
operation. During a DynamoDB outage, throttling, a stopped poller, or a failed
management-socket kill, the overlap has no fixed upper bound. The new session
remains available under the fail-open policy, and convergence resumes only
after the affected control-plane operation recovers.

In this design, "new" means the session whose ownership claim most recently
succeeded in DynamoDB. Under normal operation this is the newly established
session. If multiple sessions establish while DynamoDB is unavailable and
later retry concurrently, their original connection-time order is not
preserved; the last successful claim wins. Guaranteeing wall-clock connection
order across an outage would require a separate trusted ordering mechanism and
is not part of this design.

## When to Use DynamoDB

Enable this feature only when the required enforcement boundary contains more
than one independent owner of OpenVPN session state. DynamoDB is a distributed
coordination mechanism; it is not required merely because the deployment uses
WebAuth, Cognito, an NLB, or a daemon that can restart.

| Deployment or requirement | Use DynamoDB? | Reason |
|---|---|---|
| One OpenVPN process on one host, including one OpenVPN 2.7 multi-socket process serving both UDP and TCP, with `duplicate-cn` absent | No | OpenVPN handles exact-CN replacement and the daemon handles case-only variants after the replacement is established. |
| One OpenVPN process whose auth daemon restarts while OpenVPN remains running | No, not for single-session enforcement | OpenVPN still owns the live client set, and the daemon rebuilds local tracking from `status 3`. |
| Multiple OpenVPN processes on one host with separate daemons or otherwise separate local ownership state | Yes | OpenVPN duplicate-CN replacement is process-local; one process cannot evict a same-CN client owned by another process. |
| Multiple OpenVPN processes on one host managed by one supervisor that already provides reliable cross-runtime new-wins ownership | No for a host-local enforcement boundary | The supervisor is already the single coordinator. Use DynamoDB only if the boundary also includes other hosts or independent supervisors. |
| Multiple EC2 instances, VMs, containers, or daemon supervisors that may be active concurrently | Yes | Each participant has independent OpenVPN and in-memory state. DynamoDB provides the shared ownership record needed for eventual cross-instance eviction. |
| An Auto Scaling or rolling-replacement deployment in which old and new hosts can serve VPN clients at the same time | Yes | Even temporary host overlap creates more than one independent owner of session state. |
| Multiple independent VPN domains where one session in each domain is allowed | Yes, with `session-scope=domain`, but only when each domain itself spans independent owners | The domain key limits coordination to the intended boundary. A single-process domain does not benefit from DynamoDB. |
| One deployment-wide session should replace sessions in every participating VPN domain | Yes, with `session-scope=global`, when the scope contains more than one independent owner | All independent participants must coordinate on the same global ownership keyspace; one OpenVPN process already has one local same-CN client set. |
| NLB source-IP stickiness is enabled across multiple VPN instances | Yes, if cross-instance single-session behavior is required | Stickiness is routing affinity, not ownership enforcement; clients using another address or protocol can reach another owner. |

DynamoDB should **not** be created or enabled for this feature in these cases:

- the complete enforcement boundary is one OpenVPN process; local normalized
  new-wins already covers exact and case-only CN variants;
- all OpenVPN runtimes in the boundary already share one reliable in-process
  ownership coordinator and no other host or supervisor participates;
- the requirement is immediate eviction or a strict no-overlap `at-most-one`
  invariant; this polling and fail-open design intentionally provides neither;
- the intended use is persistence of pending WebAuth callbacks, OIDC tokens,
  reauth cache entries, or general user/session inventory; those are not
  provided by this table or protocol;
- `--cn-cross-check` cannot be enabled or the participants cannot agree on the
  same ownership identity and scope; startup rejects that configuration;
- no two independent owners can ever be active concurrently, including during
  deployment, failover, or replacement.

Do not enable `duplicate-cn` as a reason to add DynamoDB. This project requires
`duplicate-cn` to remain absent. The global store extends OpenVPN's local
new-wins behavior beyond one process; it does not replace or weaken the local
protection.

## Session Scope, Domain, and Identity

The `--session-scope` setting controls where distributed single-session
enforcement applies:

| Value | Ownership key | Semantics |
|---|---|---|
| `domain` | `session#domain#<session_domain>#<identity>` | Converge toward one active session for the identity in each session domain |
| `global` | `session#global#<identity>` | Converge toward one active session for the identity across every daemon using the table |

Neither setting has a default. When a DynamoDB table is configured, the
operator must explicitly choose `domain` or `global`. Domain scope also
requires `--session-domain`; global scope rejects `--session-domain` because
the value would not affect enforcement.

A session domain is an operator-defined logical enforcement boundary. All
daemons that should enforce one session among themselves use the same value.
It is independent of server, instance, environment, and Cognito group names.
The value must contain 1-64 lowercase ASCII letters, digits, or hyphens, and
must not start or end with a hyphen. Examples include `engineering`,
`prod-admin`, and `customer-42`. Values are validated without trimming or case
normalization.

With `global`, a new connection through any daemon using the table replaces
the user's existing connection represented by the same global ownership key.
The table and the operator's deployment choices therefore define the maximum
coordination boundary; the implementation does not impose an organization or
installation boundary.

Global scope is appropriate when one active connection per person is a
deployment-wide credential-sharing control. It has an operational trade-off:
a connection to a less privileged VPN can displace an existing session in a
more privileged VPN when both participate in the same global keyspace.

### Identity decision for v1

The v1 ownership identity is the normalized certificate CN. Reuse the existing
shared helper from `internal/auth/identity.go` for callback cross-checks, local
ownership indexes, and DynamoDB ownership-key generation:

```text
NormalizeIdentity(value):
  reject leading/trailing whitespace
  reject an empty value
  reject invalid UTF-8
  return lowercase(value)
```

This is treated as a user identity only because `--cn-cross-check=true`
requires the certificate CN to equal the authenticated OIDC `email` claim
(after both pass the same normalization) before `client-auth` is sent. Cognito `username` and
`cognito:username` are provider-specific API lookup identifiers and must not be
used for this comparison.

The current callback already normalizes both certificate CN and OIDC email with
this helper and compares the normalized results exactly. Whitespace surrounding
either value is invalid even when the two raw strings match. Normalization
failures deny the callback with the stable reason `invalid_identity`; valid
normalized values that differ use `cn_mismatch`. The browser response remains
generic and must not expose the rejected claim or certificate value.

Multiple certificates issued with the same email CN map to the same ownership
key. A certificate with a different CN cannot authenticate as that user because
the callback fails with `cn_mismatch`. Under these invariants, global scope
targets one active session per verified email/CN across all participating
daemons using the table after ownership polling and eviction converge.

A future identity mode may use a namespaced OIDC subject such as
`<issuer>#<sub>` if the platform later supports email aliases, email changes,
or multiple permitted certificate CN values for one person. Bare `sub` must
not be used across different issuers. This future mode is not part of the v1
implementation.

## Session Lifecycle

### Connect and authentication

`CLIENT:CONNECT` and the browser OIDC callback do not access DynamoDB. Pending
WebAuth sessions, callback state, `cid`, and `kid` remain local to the daemon.

The daemon creates global ownership only after receiving
`CLIENT:ESTABLISHED`. This prevents a client with only a valid certificate, or
a connection that fails OIDC, from displacing an authenticated session on a
different EC2 instance through the global ownership mechanism.

This matches the current availability-first local behavior: a new
`CLIENT:CONNECT` never evicts an established session. OpenVPN removes an exact
raw-CN predecessor natively after accepting the replacement. For a case-only
CN variant, the daemon selects the new CID only after establishment and then
requests removal of the older CID.

After `CLIENT:ESTABLISHED`, the daemon:

1. Resolves ownership identity with `NormalizeIdentity(cn)` after the
   successful CN/email cross-check.
2. Generates a cryptographically random `owner_id` for the connection.
3. Adds the established connection to the local ownership set in
   `claim-pending` state.
4. Writes the session record with `PutItem`, replacing the previous owner.
5. After a successful write, marks the local connection as `claimed` and polls
   it for ownership loss.

Replacing the record implements the `new-wins` policy. A failed or ambiguous
DynamoDB write is logged, but the VPN connection remains established and stays
`claim-pending`. The daemon retries the claim with bounded exponential backoff
and jitter while the OpenVPN session is still locally active, using the same
`owner_id` for every retry. A `claim-pending` session must not interpret the
previous stored owner as an ownership loss and kill itself before its own claim
has succeeded.

If the session disconnects while a claim is pending, further retries stop. If
an already in-flight claim subsequently succeeds, the daemon must issue the
normal conditional release for that `owner_id`; otherwise a disconnected
session could become a stale winning owner after a newer session was
established.

### Ownership polling

Each daemon checks every locally established `claimed` session once per polling
interval. Locally established `claim-pending` sessions follow the claim retry
path above instead of comparing themselves with the stored owner:

- default interval: 1 minute;
- jitter: +/-20%;
- reads: `BatchGetItem` with at most 100 keys per batch;
- consistency: `ConsistentRead=true`;
- duplicate ownership keys are deduplicated before each request and mapped back
  to every relevant local session;
- `UnprocessedKeys` are retried with bounded backoff and are never interpreted
  as missing records;
- scheduling: batches are spread across the interval rather than emitted as
  one burst;
- scope: only locally active session keys are read; the table is never
  scanned.

One polling cycle performs these steps:

1. Take a snapshot of the locally active sessions in the daemon's polling set.
2. Build and deduplicate their scope-dependent ownership keys, retain the
   reverse mapping to local sessions, and split the keys into batches of at
   most 100.
3. Read each batch from DynamoDB with strong consistency. Retry throttled and
   unprocessed keys with bounded backoff before classifying a key as genuinely
   missing.
4. Compare each local session with the returned ownership record:
   - matching `owner_id`: keep the local session active;
   - different `owner_id`: terminate the local session with `HALT`;
   - missing record: attempt a conditional ownership claim;
   - DynamoDB timeout, throttling, or service error: emit diagnostics and keep
     the local session active under the fail-open policy.
5. Keep an eviction candidate tracked until `CLIENT:DISCONNECT` or an
   authoritative `status 3` snapshot confirms that the CID is absent. A failed
   or unconfirmed local kill remains scheduled for reconciliation.

The open lease proposal described below may add one more check for records
whose `lease_until` is approaching its refresh threshold. It would perform a
conditional refresh only near that threshold, not on every one-minute cycle.

When the stored `owner_id` differs from the local session's `owner_id`, the
daemon has lost ownership. It sends the following command to its local
OpenVPN management socket:

```text
client-kill <cid> HALT
```

`HALT` prevents the displaced client from automatically reconnecting and
creating an eviction loop. `SUCCESS:` proves that OpenVPN accepted the command;
it does not prove that the CID has disconnected. The daemon retains the session
in its polling/reconciliation set until `CLIENT:DISCONNECT` or authoritative
absence from `status 3`. If `client-kill` fails or removal remains unconfirmed,
the daemon retries or reconciles during a later cycle without a tight loop and
emits `GlobalSessionKillFailed` for command failures.

If a record is missing, the daemon attempts a conditional `PutItem` with
`attribute_not_exists(pk)`. If another session wins the claim, the loser sees
the new owner during the next poll and terminates its local connection.

### Reauthentication

On `CLIENT:REAUTH`, the daemon conditionally updates `last_reauth_at` and any
liveness/cleanup timestamps required by the final TTL refresh policy. The
condition must require the current `owner_id`; a displaced owner must not
extend the record.

If the condition reports a different owner, the daemon terminates the local
session immediately with `client-kill <cid> HALT`. A DynamoDB service error is
fail-open and follows the normal reauth policy.

### Open design question: TTL refresh policy

> **Status: to be discussed; no decision has been made.**

The proposed model separates logical liveness from physical cleanup:

- `lease_until` determines whether the ownership record is logically active;
- DynamoDB `ttl` is a later deadline used only to physically remove orphaned
  data;
- conditional `Release` remains the primary cleanup path after a normal
  disconnect;
- `new-wins` does not require an expired record to be physically deleted before
  a new owner can replace it.

Readers must not use the presence of a DynamoDB item as proof that its session
is active. They evaluate `lease_until` first and ignore an expired lease for
inventory purposes. DynamoDB TTL deletion is asynchronous, so it cannot be the
logical ownership deadline. TTL remains useful because a record left by a
crashed daemon would otherwise remain indefinitely.

The current reauth-only refresh described above is insufficient when a valid
session can remain connected for more than 24 hours without reauth, for example
with `reneg-sec=0`. DynamoDB may then asynchronously delete the ownership
record while the VPN tunnel remains active. A missing record can be reclaimed,
but there is a window in which distributed single-session enforcement no
longer represents the active connection.

One candidate is to reuse the one-minute ownership polling loop without writing
on every poll:

```text
if stored lease_until < now + refresh_threshold:
    conditionally set lease_until = now + lease_horizon
    set ttl = lease_until + cleanup_grace_period
```

The discussed initial values are a 12-hour refresh threshold and a 24-hour
lease horizon, with jitter around the threshold to spread writes. The cleanup
grace period must be long enough that normal DynamoDB TTL deletion delay does
not affect correctness; its exact value is undecided. Only a daemon that still
tracks the connection as locally active may attempt the refresh. The update
must require the local session's current `owner_id`; a displaced or
disconnected owner must not extend the lease. After disconnect, the session
leaves the polling set and normal conditional `Release` remains the primary
cleanup path.

This candidate avoids a separate refresh timer and avoids one write per
one-minute poll. The threshold, lease horizon, cleanup grace period, jitter,
interaction with reauth, expired-lease claim semantics, and missing-record
recovery behavior remain open decisions and require capacity and failure-mode
validation before implementation.

### Disconnect

On `CLIENT:DISCONNECT`, the daemon issues a conditional `DeleteItem` requiring
the local `owner_id`.

This prevents a delayed disconnect from an old connection from deleting the
record of a newer connection. A failed conditional delete is a no-op. A
DynamoDB service error is logged and the TTL eventually removes the stale
record.

### Lifecycle concurrency

Claim, retry, reauth, disconnect, recovery, and CID reuse can race. Store
results must be applied only if they still belong to the same local connection
generation.

Use a per-CID state machine, generation token, or an equivalent serialization
boundary. DynamoDB calls must not block the management event reader. A stale or
late network result must not mutate ownership, release a record, or terminate a
newer OpenVPN connection that reused the same CID.

### Daemon restart and recovery

After rebuilding local connections from OpenVPN management `status 3`, the
daemon reads their ownership records with strongly consistent reads:

- matching `instance_id + server_id + runtime_id + cid`: adopt the stored
  `owner_id` and resume polling;
- different owner: terminate the recovered local session with `HALT`;
- missing record: attempt a conditional ownership claim;
- DynamoDB error: keep the connection active and retry in a later poll.

`cid` is unique only within one running OpenVPN process and may be reused after
an OpenVPN restart. Recovery must therefore never adopt a record using only
`instance_id + server_id + cid`.

The exact derivation of `runtime_id` remains an implementation blocker. A
management-socket device/inode/change-time identifier is insufficient because
metadata changes can alter change time without an OpenVPN restart. Evaluate a
stable process-generation identity, potentially based on boot identity plus
the OpenVPN peer PID and process start time, in the target environment. Until
that identity is validated, restart recovery must not claim that it can safely
adopt a previous ownership record.

## Callback Routing Boundary

DynamoDB does not participate in initial WebAuth callback routing or persist
pending sessions. A pending session remains bound to the originating OpenVPN
process and management socket. Multi-instance callback affinity continues to
be provided by the Lambda Router.

Failure handling and user experience for an unavailable callback target are
documented in
[Lambda Router Proxy](lambda-router-proxy.md#503-service-unavailable).

## DynamoDB Data Model

The design uses one Standard table without secondary indexes.

| Attribute | Type | Description |
|---|---|---|
| `pk` | String, partition key | Scope-dependent ownership key described above |
| `owner_id` | String | Random identifier unique to one established connection |
| `session_scope` | String | `domain` or `global` |
| `identity` | String | Certificate CN normalized by the shared helper and verified against OIDC `email` |
| `session_domain` | String | Logical enforcement boundary; present only for domain-scoped records |
| `cn` | String | Original certificate CN |
| `normalized_cn` | String | Validated lowercase CN used in the key |
| `instance_id` | String | EC2 instance that owns the connection |
| `server_id` | String | Local OpenVPN runtime identifier |
| `runtime_id` | String | Stable OpenVPN process-generation identity; exact derivation remains unresolved |
| `cid` | Number | OpenVPN client ID within the runtime |
| `source_ip` | String | Client address from `untrusted_ip` |
| `connected_at` | String | RFC 3339 establishment time |
| `last_reauth_at` | String | RFC 3339 time of the last successful reauth |
| `lease_until` | Number | Proposed logical liveness deadline; included only if the final refresh policy requires leases |
| `ttl` | Number | Physical-cleanup deadline derived from the final refresh policy; never an ownership deadline |

The table does not contain OIDC tokens, ALB headers, callback state, `kid`,
client private keys, or user profiles.

## Daemon Interfaces and Configuration

Introduce a `GlobalSessionStore` interface with these logical operations:

- `Claim` writes or conditionally claims ownership;
- `GetBatch` reads ownership for local sessions;
- `Refresh` conditionally refreshes the current owner's liveness and cleanup
  timestamps according to the final TTL policy;
- `Release` conditionally removes the current owner's record.

The DynamoDB implementation is constructed only when a table is configured.
Otherwise no poller is started.

Startup validation rejects DynamoDB configuration when
`--cn-cross-check=false`, the resolved instance ID is empty or still uses the
`local-dev` placeholder, `--server-id` is empty, or the session scope/domain
combination is invalid. Supplying either session option without a table is also
an error; local CN-based enforcement remains active without DynamoDB.

The following table explicitly distinguishes existing configuration from new
configuration introduced by this design:

| Status | CLI flag | Environment variable | Default | Description |
|---|---|---|---|---|
| New | `--dynamodb-session-table` | `VPN_AUTH_DYNAMODB_SESSION_TABLE` | empty | Table name; empty disables the feature |
| New | `--session-poll-interval` | `VPN_AUTH_SESSION_POLL_INTERVAL` | `1m` | Poll interval, valid range `30s` to `5m` |
| New | `--session-scope` | `VPN_AUTH_SESSION_SCOPE` | none | Distributed enforcement scope: `domain` or `global`; required when the table is configured |
| New | `--session-domain` | `VPN_AUTH_SESSION_DOMAIN` | none | Logical enforcement boundary; required only with `--session-scope=domain` |
| New | `--server-id` | `VPN_AUTH_SERVER_ID` | empty | Stable runtime identifier; required when DynamoDB is enabled |
| Existing, extended use | `--instance-id` | `VPN_AUTH_INSTANCE_ID` | `local-dev` | Existing EMF dimension; additionally identifies the ownership record |

`--instance-id` already exists for EMF metrics, and production cloud-init
passes the EC2 instance ID. This design reuses that resolved value for session
ownership. When the store is enabled, `local-dev` is rejected to prevent two
hosts from sharing a placeholder owner identity. Tests and non-EC2 deployments
must provide a unique explicit value.

`runtime_id` is not configurable. It is calculated only after identifying the
connected OpenVPN process generation. Its exact derivation must be resolved and
validated before restart adoption is implemented.

The session configuration matrix is:

| Table | Session scope | Session domain | Result |
|---|---|---|---|
| absent | absent | absent | DynamoDB ownership disabled; local enforcement unchanged |
| absent | set | any | Startup error |
| configured | absent | any | Startup error |
| configured | `global` | absent | Valid |
| configured | `global` | set | Startup error |
| configured | `domain` | valid | Valid |
| configured | `domain` | absent or invalid | Startup error |

## Terraform and IAM

Terraform exposes these variables:

| Variable | Default | Meaning |
|---|---|---|
| `dynamodb_session_store_enabled` | `false` | Enable global session ownership |
| `dynamodb_session_store_existing_table_name` | `null` | Name of an externally managed table |
| `dynamodb_session_store_existing_table_arn` | `null` | ARN of the same externally managed table |

The validation and creation rules are:

- disabled: both external-table variables must be `null` and no resources or
  IAM permissions are created;
- enabled with both external-table variables `null`: create a Standard,
  on-demand table named from `project_name`, with TTL on `ttl`;
- enabled with both external-table variables set: use that table and create
  only IAM wiring;
- setting only one external-table variable is a Terraform validation error.

An externally managed table must preserve the strongly consistent read and
conditional-write semantics required by this protocol for every participant.
The v1 design does not claim correctness for a multi-Region eventual-consistency
topology and must not accept one as equivalent to the specified single-region
coordination model.

Terraform passes the effective table name to the daemon and grants access to
the effective table ARN. The created table ARN and effective table name are
exported as outputs.

The EC2 role receives only these table-level actions:

- `dynamodb:BatchGetItem`
- `dynamodb:GetItem`
- `dynamodb:PutItem`
- `dynamodb:UpdateItem`
- `dynamodb:DeleteItem`
- `dynamodb:DescribeTable`

The Terraform switch remains mechanically independent of
`multi_instance_mode` because multiple independent OpenVPN processes can exist
on one host and rolling replacement can temporarily create multiple hosts.
Operators should nevertheless enable the table only for a case identified in
[When to Use DynamoDB](#when-to-use-dynamodb).

## Observability

Add the following metrics:

- `GlobalSessionOwnershipLost`
- `GlobalSessionStoreError`, with an operation dimension
- `GlobalSessionPollDuration`
- `GlobalSessionPollThrottled`
- `GlobalSessionKillFailed`

Metrics use `SessionScope` as a bounded dimension. Domain-scoped metrics also
use `SessionDomain`; operators must keep the configured domain set small and
controlled.

Every ownership loss produces a structured security log containing the CN,
session scope, session domain when applicable, local and stored owners, CID,
available source addresses, and the time between connections.

CN must not be a CloudWatch metric dimension because it creates unbounded
cardinality.

## Capacity and Cost

For 600 continuously active clients and a one-minute interval:

- average read rate: 10 strongly consistent reads per second;
- monthly reads: approximately 25.92 million read request units for items up
  to 4 KiB;
- minimum API calls: six `BatchGetItem` calls per cycle when all 600 sessions
  are local to one daemon;
- with multiple daemons, calls per cycle are
  `sum(ceil(local_active_sessions / 100))` across the fleet;
- writes from establish, reauth, and disconnect are small relative to reads.

On-demand capacity is the default because it avoids burst and provisioning
management. If provisioned capacity is introduced later, polling batches must
remain distributed across the interval to prevent short read bursts from
being throttled.

## Failure Semantics

| Scenario | Behavior |
|---|---|
| DynamoDB read timeout | Log and emit metric; keep session active |
| Initial ownership write fails or is ambiguous | Keep the session active in `claim-pending`; retry with the same `owner_id` and bounded backoff |
| DynamoDB throttling | Back off with jitter; keep session active |
| Ownership changed | Kill local session with `HALT` |
| Local `client-kill` write fails | Keep session in polling set and retry next cycle |
| Ownership record missing | Attempt conditional claim |
| Conditional claim lost | Detect winner during the next poll |
| Conditional release lost | No-op; the newer owner remains intact |
| Daemon crashes | Record expires through TTL unless replaced earlier |

The mechanism is an availability-first security control. It must not be
documented as immediate or strictly consistent single-session enforcement.

During a DynamoDB outage, global single-session enforcement is completely
unavailable: multiple instances can keep or establish sessions for the same
ownership key until the store recovers, one retried claim becomes the last
successful owner, and polling plus local eviction converges. Authentication and
existing tunnels continue to work. Operators must treat sustained
`GlobalSessionStoreError` or throttling alarms as loss of this security control,
not merely reduced observability. The statement that the old session is
eventually removed is conditional on DynamoDB, the ownership poller, and the
old owner's management-socket kill path recovering; it is not an unconditional
time-bounded guarantee.

## Implementation Phases

### Phase 1: Domain-scoped ownership

- Reuse the completed shared identity normalization and authenticated local
  new-wins behavior unchanged.
- Add `GlobalSessionStore`, DynamoDB implementation, new configuration, table,
  IAM, and domain-scoped keys.
- Write ownership after `CLIENT:ESTABLISHED`; implement `claim-pending` retry,
  conditional refresh, and release.
- Keep the feature disabled by default.

### Phase 2: Polling and recovery

- Add the distributed poller with one-minute jittered scheduling and batched,
  strongly consistent reads.
- Add `runtime_id`, management-reconnect recovery, `HALT` eviction retry,
  fail-open metrics, logs, and alarms.
- Validate behavior and capacity with 600 simulated active sessions.

### Phase 3: Global scope

- Add `--session-scope=global` and global keys.
- Test cross-domain displacement and document the privilege-boundary trade-off.
- Keep session scope explicit, with no default.

Lambda Router failure UX has been implemented independently and is documented
in [Lambda Router Proxy](lambda-router-proxy.md#503-service-unavailable).

## Test Plan

The feature must not be enabled until all required unit, protocol, integration,
and infrastructure scenarios pass:

1. A disabled store performs no DynamoDB calls.
2. Failed OIDC and connections without `CLIENT:ESTABLISHED` do not change
   DynamoDB ownership; existing local duplicate-CN behavior remains unchanged.
3. A newly established session replaces the previous owner.
4. With DynamoDB and the management socket healthy, the previous owner receives
   `client-kill <cid> HALT` within one poll cycle after the new ownership claim
   succeeds.
5. CN values differing only by case share one ownership key; values with
   leading/trailing whitespace are rejected by the shared normalization helper.
6. Store startup fails when `--cn-cross-check` is disabled, `--instance-id`
   still has the `local-dev` placeholder value, or `--server-id` is empty.
7. Empty or whitespace-surrounded CN/email values are rejected with
   `invalid_identity`; valid normalized values that differ use `cn_mismatch`.
8. With `domain` scope, the same identity can own one session in each session
   domain without cross-domain eviction.
9. With `global` scope, a session established through another participating
   daemon replaces the previous owner.
10. A delayed disconnect cannot delete the new owner's record.
11. Reauth refreshes liveness and cleanup timestamps according to the final TTL
    policy only for the current owner.
12. Simultaneous claims converge to one owner.
13. Restart recovery adopts a matching record and kills a session owned
   elsewhere.
14. Recovery refuses to adopt a record with the same CID but a different
    management-socket `runtime_id`.
15. Timeout, throttling, and service errors remain fail-open.
16. A failed `client-kill HALT` remains scheduled and is retried on the next
    poll without a tight loop.
17. Polling 600 sessions deduplicates keys, handles partial responses,
    `UnprocessedKeys`, and throttling, and produces about 10 reads per second
    without a single 600-read burst.
18. DynamoDB Local or LocalStack integration tests cover conditional claim,
    refresh, release, and two competing daemon instances.
19. Startup validation covers every row in the session configuration matrix,
    including the strict session-domain format.
20. A unique explicit `instance_id` supports local tests; an empty value or the
    `local-dev` placeholder causes startup failure only when the store is
    enabled.
21. Terraform rejects incomplete external-table configuration and creates no
    DynamoDB IAM permissions when the feature is disabled.
22. A failed or ambiguous initial claim leaves the established session in
    `claim-pending`; it is not killed merely because the table still contains
    the previous owner.
23. After DynamoDB recovers, a `claim-pending` session retries with the same
    `owner_id`, becomes `claimed`, and causes the previous owner to be evicted
    through the normal polling path.
24. Disconnecting a `claim-pending` session stops further retries; if an
    in-flight claim completes afterward, its conditional release cannot delete
    a different newer owner.
25. When multiple sessions establish during a DynamoDB outage, recovery
    converges on the last successful DynamoDB claim without asserting their
    original wall-clock connection order.
26. A sustained DynamoDB or management-socket failure keeps both sessions
    active and emits the documented alerts; the test must not assert a bounded
    convergence time while the dependency remains unavailable.
27. A delayed DynamoDB result for an older local generation cannot mutate,
    release, or kill a newer connection that reused the same CID.
28. The supported OpenVPN version and client set confirm that
    `client-kill <cid> HALT` is followed by `CLIENT:DISCONNECT` or authoritative
    absence; command `SUCCESS:` alone is not treated as removal.

## Explicit Non-Goals

- Immediate cross-instance eviction.
- A daemon-to-daemon HTTP endpoint.
- SQS, EventBridge, DynamoDB Streams, or SSM-based control messages.
- User storage or Cognito replacement.
- Persistent pending WebAuth sessions.
- Storage of OIDC tokens or authentication secrets.
