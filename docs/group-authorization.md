# Group Authorization and OIDC Claims

## Table of Contents

- [Group Sources](#group-sources)
- [Claim-Based Mode](#claim-based-mode)
- [Group Claim Parser](#group-claim-parser)
- [OIDC Debug Claims](#oidc-debug-claims)
- [Terraform and ALB Scope](#terraform-and-alb-scope)
- [Operational Verification](#operational-verification)

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

Set `--required-group` to the exact value observed in the configured claim. For
Entra groups synchronized from AD DS, Cognito/Entra mappings can emit
UUID/object-id-like values instead of group display names. Cloud-only Entra
groups may emit display names, but do not configure from the portal display name
unless `--oidc-debug-claims` confirms that exact value appears in the claim.
In observed Cognito/Entra mappings, multiple groups were emitted as a bracketed
CSV string such as `"[uuid1, uuid2]"`, while a single group was emitted as a
plain string such as `"uuid1"`.

## Group Claim Parser

When `--groups-source=jwt-claim` is enabled, the configured claim is parsed as a
list of group names using these rules:

1. JSON array: keep string elements, trim whitespace, and drop empty results.
   Non-string elements are ignored.
2. String that parses as a valid JSON array: parse it and apply the array rules.
3. String starting with `[` and ending with `]` that is not a valid JSON array:
   compatibility fallback for observed Cognito/Entra mappings with multiple
   groups, only when the inner content contains a comma. Remove the outer
   brackets, split the inner content on `,`, trim each element, and drop empty
   results. If there is no comma, or if every element is empty after trimming,
   return no groups.
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

```json
{ "groups": "[vpn-users, admins]" }
```

The bracketed CSV string shape is a compatibility path for multi-group mappings
observed in the field; a single group should appear as a plain string such as
`"vpn-users"`, not `"[vpn-users]"`. JSON arrays and JSON-array-as-string values
are still preferred. If group names can contain commas, the claim must be a JSON
array because CSV and bracketed CSV cannot distinguish one group named `foo,bar`
from two groups named `foo` and `bar`.

## OIDC Debug Claims

`--oidc-debug-claims` is a controlled diagnostic mode for real ALB/Cognito/IdP
integrations. It logs structured metadata and capped claim values from OIDC
headers on every callback. Keep it disabled outside investigations.

When enabled, it logs:

- Whether `x-amzn-oidc-data`, `x-amzn-oidc-accesstoken`, and
  `x-amzn-oidc-identity` are present, plus their lengths.
- JWT header fields `kid`, `alg`, `signer`, and `typ` when present.
- Per-claim name, JSON `type`, and capped `value`. JSON-format logs also
  include raw value `len` in the aggregate claims map.
- `x-amzn-oidc-identity` as a salted SHA-256 prefix, not as the raw value. The
  salt is generated once per daemon startup and kept in memory only, so the
  same identity yields a stable hash within one daemon process but a different
  hash after a restart or in a different instance. This is deliberate — it lets
  operators correlate records within a debug session without producing a
  cross-restart identifier.

Values are capped at 2048 bytes. Truncated values get the suffix
`<truncated,total_bytes=X>` appended inline.

With `--log-format=json`, JWT diagnostics are emitted as aggregate records:

- `oidc_debug_headers`
- `oidc_debug_data`
- `oidc_debug_accesstoken`

With `--log-format=text`, JWT diagnostics are emitted as flat records to keep
`journalctl` output readable:

- `oidc_debug_headers`
- `oidc_debug_data_header`
- `oidc_debug_data_claim`
- `oidc_debug_accesstoken_header`
- `oidc_debug_accesstoken_claim`

After callback `state` verification succeeds, OIDC debug records include the
verified `sid`. If `state` is missing or invalid, these records use `sid=""`
because the daemon cannot trust or extract a session ID.

Example text-format investigation for `--groups-source=jwt-claim`:

```text
level=INFO msg="groups source configured" source=jwt-claim claim=custom:groups reauth_group_check=false claim_ignored=false
level=WARN msg="oidc debug claim logging enabled; lab/debug only, do not enable in production" event=oidc_debug_enabled
level=DEBUG msg=oidc_debug_headers sid=sid_example oidc_data_present=true oidc_data_len=1338 accesstoken_present=true accesstoken_len=1089 identity_present=true identity_len=36 identity_hash=0123456789abcdef
level=DEBUG msg=oidc_debug_data_header sid=sid_example header_alg=ES256 header_kid=alb-key-id header_signer=arn:aws:elasticloadbalancing:region:account:loadbalancer/app/example/abc123 header_typ=JWT
level=DEBUG msg=oidc_debug_data_claim sid=sid_example name=custom:groups type=string value="[group-id-1, group-id-2]"
level=DEBUG msg=oidc_debug_data_claim sid=sid_example name=email type=string value=user@example.com
level=DEBUG msg=oidc_debug_data_claim sid=sid_example name=username type=string value=IdP_user@example.com
level=DEBUG msg=oidc_debug_accesstoken_claim sid=sid_example name=cognito:groups type=array value="[\"userpool_IdP\"]"
```

The configured claim is the top-level `custom:groups` value from
`x-amzn-oidc-data`. The `cognito:groups` value shown in the access token is
diagnostic only; it is not used by `--groups-source=jwt-claim`.

If the configured `--required-group` does not exactly match a parsed claim
value, the group-check diagnostic shows the parsed count but `matched=false`:

```text
level=DEBUG msg="callback: jwt claim group check" sid=sid_example groups_source=jwt-claim claim=custom:groups claim_present=true groups_count=2 required_group_hash=aaaaaaaaaaaaaaaa matched=false
level=WARN msg="callback: user not in required group" sid=sid_example group=group-id-1-typo email=user@example.com
```

After setting `--required-group` to the exact observed value, the same callback
shape should match and authenticate:

```text
level=DEBUG msg="callback: jwt claim group check" sid=sid_example groups_source=jwt-claim claim=custom:groups claim_present=true groups_count=2 required_group_hash=bbbbbbbbbbbbbbbb matched=true
level=INFO msg="callback: auth success" sid=sid_example email=user@example.com
level=INFO msg=established cid=3
```

Malformed JWTs still use the token-level prefix with an error field such as
`token_error`, `header_error`, or `payload_error`. In JSON format that is the
aggregate `oidc_debug_data` / `oidc_debug_accesstoken` record; in text format
header errors are logged on `*_header`, while payload errors use the token-level
record name.

OIDC debug logging never logs raw JWT strings, raw access-token strings,
cookies, authorization codes, or secrets. It can expose PII and access-token
claims, so it must not be enabled in production. The daemon emits a startup
warning with `event=oidc_debug_enabled` when this mode is enabled.

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
