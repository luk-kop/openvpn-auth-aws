# Entra Graph Reauth Design

This document sketches a possible future design for reauth-time group checks
against Microsoft Entra ID through Microsoft Graph. It is not implemented today.

The current daemon can authorize callback/connect from ALB-forwarded claims and
can re-check Cognito users/groups on `CLIENT:REAUTH`. It cannot re-query Entra
ID during reauth. This design describes what would be needed to add that path.

## Goal

Support active-session revocation when the source of truth for VPN membership is
an Entra ID group and the deployment does not want to sync that group into
Cognito groups.

The desired behavior:

1. User authenticates through ALB OIDC or Cognito federation.
2. Callback captures a stable Entra user identifier from `x-amzn-oidc-data`.
3. User connects if callback authorization succeeds.
4. On `CLIENT:REAUTH`, the daemon queries Microsoft Graph.
5. If the Entra account is disabled, missing, or no longer a member of the
   required Entra group, the daemon denies reauth and OpenVPN disconnects the
   session.

## Proposed Flags

Keep callback group authorization separate from reauth authorization:

```text
--groups-source=jwt-claim
--groups-claim=<callback-group-claim>
```

Add a reauth checker:

```text
--reauth-checker=cognito-api|entra-graph|disabled
--entra-tenant-id=<tenant-id>
--entra-client-id=<app-client-id>
--entra-client-secret-secret-id=<aws-secrets-manager-id>
--entra-user-id-claim=oid
--entra-required-group-id=<entra-group-object-id>
--entra-graph-timeout=3s
--entra-graph-cache-ttl=60s
```

Notes:

- `--entra-required-group-id` must be an Entra object ID, not a display name.
- `--entra-user-id-claim` must point at a stable identifier captured during the
  callback. For direct Entra OIDC this is commonly `oid`. For Cognito
  federation it might be a mapped readable custom attribute such as
  `custom:entra_oid`; this must be verified with `--oidc-debug-claims`.
- A future implementation should avoid overloading `--groups-source`; callback
  authorization and reauth authorization are different events with different
  available data.

## Callback Requirements

The callback path must store the Entra user object ID on the session. Reauth
does not receive a fresh JWT, so the daemon must persist the identifier captured
at callback time.

Required session data:

```text
cid
kid
certificate CN / email
cognito lookup username, when applicable
entra user object ID
authenticated timestamp
```

If `--reauth-checker=entra-graph` is enabled and the configured
`--entra-user-id-claim` is absent, callback should fail loudly. Otherwise reauth
would have no stable key to query Graph.

## Graph Calls

Use Microsoft Graph application permissions and client credentials. Do not use
delegated `/me` endpoints because reauth is a daemon-side event without an
interactive signed-in user.

Recommended account status check:

```http
GET https://graph.microsoft.com/v1.0/users/{id}?$select=id,accountEnabled
```

`accountEnabled=false` should deny reauth. Missing user should deny reauth.

Recommended group membership check:

```http
POST https://graph.microsoft.com/v1.0/users/{id}/checkMemberGroups
Content-Type: application/json

{
  "groupIds": ["<entra-required-group-id>"]
}
```

Microsoft documents `checkMemberGroups` as transitive and limited to 20 group
IDs per request. For this daemon, one required group is enough for an MVP.

Expected decision:

- response contains `<entra-required-group-id>`: allow group check
- response does not contain it: deny with `not in required group`
- Graph error / timeout: fail closed unless an explicit cache policy allows a
  recent known-good result

## Permissions

The Graph app registration would need application permissions. Exact least
privilege must be verified during implementation, but likely candidates are:

- `User.Read.All` for reading `id` and `accountEnabled`
- `GroupMember.Read.All` or `Directory.Read.All` for group membership checks

These require admin consent in the Entra tenant.

Store the Graph client secret in AWS Secrets Manager. Do not pass it directly in
Terraform user-data or systemd units.

## Caching And Failure Mode

Graph should not be called without timeouts and caching. Reauth is on the
OpenVPN critical path.

Suggested defaults:

```text
--entra-graph-timeout=3s
--entra-graph-cache-ttl=60s
```

Cache key:

```text
entra_user_object_id + entra_required_group_id
```

Cache value:

```text
account_enabled
in_required_group
checked_at
expires_at
```

Default failure behavior should be fail closed:

- Graph timeout: deny
- Graph 5xx: deny
- Graph 429: deny
- malformed response: deny

An optional known-good cache policy could allow reauth during a short Graph
outage, similar to the existing Cognito reauth cache. If added, it must be
explicitly documented as a security trade-off because removals from the Entra
group may not take effect until cache expiry.

## Latency And Revocation

The maximum revocation delay is approximately:

```text
Graph propagation delay + cache TTL + OpenVPN reneg-sec
```

If fast revocation is required, lower `reneg-sec` and keep
`--entra-graph-cache-ttl` short. Very short TTLs increase Graph traffic and make
VPN reauth more sensitive to Graph latency and rate limits.

## Direct Entra OIDC vs Cognito Federation

Direct ALB `authenticate-oidc` with Entra is the cleanest fit (see
[`direct-entra-oidc.md`](direct-entra-oidc.md)):

- no Cognito federated user lifecycle
- callback claims come directly from Entra userInfo/token flow
- `oid` is easier to reason about after verification with OIDC debug logging

Cognito federation can still work, but only if the Entra object ID is mapped
into a readable Cognito attribute that ALB forwards in `x-amzn-oidc-data`.
Without that mapped stable ID, Graph reauth cannot reliably identify the Entra
user.

## Why Not Put This In `groups-source`

`--groups-source` currently describes callback/connect authorization. Reauth is
a different lifecycle event:

- callback has ALB headers and OIDC claims
- reauth has only OpenVPN management data and stored session state

Mixing both into one flag would make the behavior hard to reason about. A
separate `--reauth-checker` keeps the contract explicit.

## Risks

- Graph outage can disconnect active VPN sessions.
- Graph rate limits can affect reauth reliability.
- Incorrect user ID mapping can deny valid users or allow stale sessions.
- Entra app permissions require tenant admin consent and careful secret
  handling.
- National cloud endpoints may need configuration if the tenant is not in the
  global Microsoft Graph cloud.
- This makes the daemon provider-aware. Keep the implementation isolated behind
  an interface so Cognito and Entra checks do not become tangled.

## Implementation Sketch

Introduce a reauth checker interface:

```go
type ReauthChecker interface {
	CheckReauth(ctx context.Context, session Session) (ReauthResult, error)
}
```

Implementations:

- `CognitoReauthChecker`
- `EntraGraphReauthChecker`
- `SkipReauthChecker`

The Entra implementation owns:

- client credentials token acquisition
- Graph HTTP client
- timeout handling
- cache
- account status check
- group membership check
- metrics and structured logs

## References

- Microsoft Graph `checkMemberGroups`: https://learn.microsoft.com/en-us/graph/api/directoryobject-checkmembergroups?view=graph-rest-1.0
- Microsoft Graph user resource (`accountEnabled`): https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
- AWS ALB OIDC authentication: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
