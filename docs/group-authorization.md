# Group Authorization and OIDC Claims

This document describes how the daemon authorizes users with `--required-group`,
how claim-based group checks work, and how to inspect the real claims forwarded
by ALB/Cognito.

See also:

- [`configuration.md`](configuration.md) — full flag and environment variable
  reference for `--groups-source`, `--groups-claim`, and the OIDC debug flags.
- [`cognito-federation.md`](cognito-federation.md) — federated IdP setup,
  including the SAML/OIDC attribute mapping patterns that surface a group
  claim in `x-amzn-oidc-data`.
- [`direct-entra-oidc.md`](direct-entra-oidc.md) — possible future ALB
  `authenticate-oidc` mode that uses Entra directly without Cognito federation.
- [`entra-graph-reauth.md`](entra-graph-reauth.md) — possible future design for
  reauth-time group checks directly against Microsoft Graph.

## Group Sources

`--required-group` is the canonical access-control setting. When it is empty,
the daemon does not perform a group check, regardless of the configured group
source.

The daemon supports two group sources:

| Source | Flags | Behavior |
|---|---|---|
| Cognito API | `--groups-source=cognito-api` | Production default. Callback/connect checks use Cognito Admin APIs. Reauth group checks also use Cognito Admin APIs when `--check-required-group-on-reauth=true`. |
| JWT claim | `--groups-source=jwt-claim --groups-claim=<claim>` | Callback/connect reads groups from a top-level claim in `x-amzn-oidc-data`. Reauth cannot use JWT claims because `CLIENT:REAUTH` does not include a fresh ALB JWT. |

`--groups-claim` is accepted but ignored in `cognito-api` mode. The daemon logs
the effective group configuration at startup, including `claim_ignored=true`
when a claim is configured but ignored by `cognito-api`.

`jwt-claim` mode cannot be combined with
`--check-required-group-on-reauth=true`. If reauth-time group revocation is
required, use `--groups-source=cognito-api`.

> **External IdP warning:** reauth does not re-query Entra ID, Azure AD, Okta,
> SAML, or any upstream IdP, and it does not parse fresh IdP group claims. If
> groups exist only in IdP claims or a mapped claim such as `custom:groups`,
> changes are reflected only after a new ALB/Cognito login refreshes
> `x-amzn-oidc-data`. Reauth-time group revocation requires Cognito API mode and
> group membership represented in Cognito groups.

## Claim-Based Mode

Claim-based group checks read only the configured top-level claim from
`x-amzn-oidc-data`. The daemon does not use `x-amzn-oidc-accesstoken` as a
production group source; access-token decoding is diagnostic only.

Claim names are case-sensitive. `--groups-claim=cognito:groups` is different
from `--groups-claim=Cognito:Groups`.

Dotted paths are not supported. `--groups-claim=realm_access.roles` means a
literal top-level claim named `realm_access.roles`, not `{ "realm_access":
{ "roles": [...] } }`.

If the configured claim is absent while `--required-group` is set, the callback
is denied with client reason `group claim not present` and metric label
`group_denied`.

Do not assume native Cognito groups are available as `cognito:groups` in
`x-amzn-oidc-data`. In the tested native-Cognito flow, `cognito:groups` was not
present in the ALB-forwarded userInfo claims. For claim-based group checks, first
verify the real ALB-forwarded claim shape with `--oidc-debug-claims`, then set
`--groups-claim` to the exact claim that exists.

For federated IdPs, a common pattern is to map IdP groups to a Cognito custom
attribute such as `custom:groups`, ensure the app client can read that
attribute, verify it appears in `x-amzn-oidc-data`, and then set:

```text
--groups-source=jwt-claim
--groups-claim=custom:groups
```

## Group Claim Parser

When `--groups-source=jwt-claim` is enabled, the configured claim is parsed as a
list of group names using these rules:

1. JSON array: keep string elements, trim whitespace, and drop empty results.
   Non-string elements are ignored.
2. String that parses as a valid JSON array: parse it and apply the array rules.
3. String starting with `[` and ending with `]` that is not a valid JSON array:
   reject as no groups. It does not fall through to CSV parsing.
4. String containing commas: split on `,`, trim each element, and drop empty
   results. If every element is empty after trimming, return no groups.
5. Non-empty string: treat as one group name.
6. Missing claim, `null`, empty string, whitespace-only string, bool, number,
   object, or any other unsupported value: no groups.

String values are trimmed once before applying the string rules. Group
comparison remains exact and case-sensitive.

Examples:

```json
{ "groups": ["vpn-users", "admins"] }
```

```json
{ "groups": "vpn-users, admins" }
```

```json
{ "groups": "[\"vpn-users\", \"admins\"]" }
```

```json
{ "groups": "vpn-users" }
```

The non-JSON shape `"[vpn-users, admins]"` is rejected. If group names can
contain commas, the claim must be a JSON array because CSV cannot distinguish
one group named `foo,bar` from two groups named `foo` and `bar`.

## OIDC Debug Claims

`--oidc-debug-claims` is a controlled diagnostic mode for real ALB/Cognito/IdP
integrations. It logs structured metadata about OIDC headers on every callback.
Keep it disabled outside investigations.

Safe mode logs:

- Whether `x-amzn-oidc-data`, `x-amzn-oidc-accesstoken`, and
  `x-amzn-oidc-identity` are present, plus their lengths.
- `x-amzn-oidc-data` JWT header fields `kid`, `alg`, `signer`, and `typ` when
  present.
- Claim names, JSON types, and value lengths.
- Full capped values only for the configured `--groups-claim` plus the
  group-like allowlist: `cognito:groups`, `groups`, and `roles`.
- Access-token claim names and types when the access token looks like a JWT.
  Safe mode never logs access-token claim values, including group-like values.
- `x-amzn-oidc-identity` as a salted SHA-256 prefix, not as the raw value. The
  salt is generated once per daemon startup and kept in memory only, so the
  same identity yields a stable hash within one daemon process but a different
  hash after a restart or in a different instance. This is deliberate — it lets
  operators correlate records within a debug session without producing a
  cross-restart identifier.

Values are capped at 2048 bytes. Truncated values get the suffix
`<truncated,total_bytes=X>` appended inline.

Safe mode never logs raw JWT strings, raw access-token strings, cookies,
authorization codes, or secrets.

`--oidc-debug-claims-unsafe` implies `--oidc-debug-claims` and logs full decoded
payload values, still capped and still without raw token strings. It can expose
PII and must not be enabled in production. The daemon emits a startup warning
with `event=oidc_debug_unsafe_enabled` when unsafe mode is enabled.

OIDC debug logging has no rate limit by design.

## Terraform and ALB Scope

Terraform configures ALB/Cognito OAuth scope as:

```text
openid email profile
```

`email` is required for the daemon's default CN/email cross-check. `profile`
helps standard OIDC profile claims and mapped custom attributes appear through
Cognito userInfo and then in ALB-forwarded `x-amzn-oidc-data`.

`profile` is not a reliable path to native Cognito `cognito:groups`. ALB
forwards userInfo-derived claims, not the ID token, and native Cognito group
membership was not observed in `x-amzn-oidc-data` in this repo's tested native
Cognito flow.

The Cognito user pool client must allow `profile` before ALB can request it.
Apply the Cognito app-client scope change before applying ALB listener rule
scope changes.

Existing ALB/Cognito sessions keep the scope that was active when the
`AWSELBAuthSessionCookie-*` cookie was issued. New claims may not appear until
the user signs in again or the ALB auth session expires.

## Operational Verification

Before relying on claim-based group checks in production:

1. Enable `--oidc-debug-claims` in a controlled environment.
2. Complete a real browser callback through ALB and Cognito.
3. Inspect the logged `x-amzn-oidc-data` claim names, types, and group-like
   values.
4. Set `--groups-claim` to the exact top-level claim that appears in
   `x-amzn-oidc-data`.
5. Verify that users outside `--required-group` are denied.
6. Remember that claim-based checks reflect the ALB/Cognito session cookie.
   Claim changes may not appear until the user logs out, signs in again, or the
   `AWSELBAuthSessionCookie-*` session expires.
7. If revocation during an existing VPN session is required, use
   `--groups-source=cognito-api`, enable `--check-required-group-on-reauth`, and
   keep Cognito Admin API access configured.
