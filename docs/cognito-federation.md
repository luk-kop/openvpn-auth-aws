# Cognito User Types and Federation

## Table of Contents

- [Cognito User Types](#cognito-user-types)
- [Cognito Internal vs External IdP](#cognito-internal-vs-external-idp)
- [SAML-Specific Considerations](#saml-specific-considerations)
- [Attribute Mapping Requirement](#attribute-mapping-requirement)
- [End-to-End SAML Federation Walkthrough](#end-to-end-saml-federation-walkthrough)
- [Group Resolution for Federated Users (Consolidated)](#group-resolution-for-federated-users-consolidated)
- [CN Cross-Check and Federated Users](#cn-cross-check-and-federated-users)
- [Daemon Configuration for External IdP](#daemon-configuration-for-external-idp)
- [AWS Documentation References](#aws-documentation-references)

This document explains the difference between native and federated Cognito users, how each type interacts with the auth daemon, and what configuration is required to support external identity providers.

## Cognito User Types

### Native (internal) users

Native users are created directly in the Cognito User Pool — either via the AWS Console, CLI, or self-service sign-up. In this project the user pool is configured with `username_attributes = ["email"]`, which means:

- Users can sign in with their email address
- The Cognito `email` attribute is present and verified
- The internal Cognito `Username` is **not guaranteed** to be the email address
- In observed production users, Cognito stored a UUID-like internal `Username` and exposed the same value as `sub`
- `UserStatus` is `CONFIRMED` for active accounts
- The certificate CN (email) should match the `email` attribute, not the internal Cognito `Username`

This is the default and fully supported configuration.

### Federated (external IdP) users

Federated users authenticate through an external identity provider (SAML, OIDC, Google, Azure AD, Okta, etc.) linked to the Cognito User Pool. When a federated user logs in for the first time, Cognito automatically creates an account in the User Pool with the following properties:

| Property | Native user | Federated user |
|---|---|---|
| Cognito username | implementation-specific; in observed production users this was a UUID-like internal identifier | `{ProviderName}_{identifier}` (e.g. `Google_1234567890`, `MySAML_user@corp.com`) |
| `UserStatus` | `CONFIRMED` | `EXTERNAL_PROVIDER` |
| `sub` in JWT | Cognito UUID; in observed native users it matched `Username` | Cognito UUID |
| `email` in JWT | from Cognito attribute | from IdP attribute mapping (see below) |
| `username` in ALB-forwarded JWT | internal Cognito `Username`; in observed production users this was a UUID-like identifier | `{ProviderName}_{identifier}` or Cognito UUID-style username |

The Cognito username for federated users always follows the format `{ProviderName}_{identifier}` — this cannot be changed. The `{identifier}` part depends on the provider type:

| Provider type | `{ProviderName}` | `{identifier}` source |
|---|---|---|
| Google | `Google` | Google `sub` claim (numeric ID) |
| Facebook | `Facebook` | Facebook `id` claim |
| Login with Amazon | `LoginWithAmazon` | Amazon `user_id` claim |
| Sign in with Apple | `SignInWithApple` | Apple `sub` claim |
| OIDC (custom) | your configured IdP name | `sub` claim from the IdP |
| SAML 2.0 | your configured IdP name | `NameID` from SAML assertion (often email) |

Examples: `Google_1234567890`, `MySAML_user@corp.com`, `MyOIDCIdP_abc123`.

The `AdminGetUser` API requires this full value as the `Username` parameter for federated accounts; passing an email address returns `UserNotFoundException`.

## Cognito Internal vs External IdP

### Internal IdP (Cognito user pool)

The default configuration (`supported_identity_providers = ["COGNITO"]` in Terraform). Users authenticate with a username and password stored in the Cognito User Pool. No external system is involved.

### External (federated) IdP

An external IdP is linked to the Cognito User Pool. Supported types:

| Type | Examples |
|---|---|
| Social | Google, Facebook, Amazon, Apple |
| OIDC | Okta, Auth0, any OIDC-compliant provider |
| SAML 2.0 | Azure AD (legacy), ADFS, PingIdentity, Okta SAML |
| Microsoft (OIDC) | Azure AD / Entra ID (modern) |

When a user authenticates via an external IdP, the IdP sends user attributes (claims) to Cognito. Cognito must be configured to map those attributes onto the User Pool user's attributes — this is called **attribute mapping**.

## SAML-Specific Considerations

SAML 2.0 providers have several nuances that do not apply to OIDC or social providers.

### NameID format and Cognito username

Cognito derives the federated Cognito username from the SAML `NameID` assertion value: `{ProviderName}_{NameID}`. The NameID format configured in the SAML IdP determines what that identifier looks like:

| NameID format | Cognito username example | Notes |
|---|---|---|
| Email (`emailAddress`) | `MySAML_user@corp.com` | Contains email, but mutable — see warning below |
| Persistent (`persistent`) | `MySAML_a3f7b2...` | Opaque GUID, stable across sessions |
| Transient (`transient`) | `MySAML_<random>` | **Never use** — changes every login, creates a new Cognito user each time |
| Unspecified | IdP-dependent | Often email in practice |

**AWS warning:** Using an email address as the SAML NameID is discouraged. If a user changes their email at the IdP, Cognito cannot match them to their existing profile — the user loses access and their Cognito record must be manually deleted and recreated. Use a stable, immutable identifier (employee GUID, UUID, employee number) as the NameID whenever possible.

Additionally, Cognito's SAML NameID matching is **case-sensitive**, even if the user pool is configured as case-insensitive. A user who logs in with `Carlos@example.com` one session and `carlos@example.com` the next will be treated as two different users.

### SP-initiated vs IdP-initiated flows

Only **SP-initiated** flows work with this daemon. The auth flow starts with the browser redirect triggered by OpenVPN's `WEB_AUTH::` URL, which lands on the ALB at `/callback/{server}/{proto}?state=<blob>`. The ALB then drives the Cognito hosted UI, which in turn drives the SAML AuthnRequest to the IdP.

**IdP-initiated** SSO (where the user clicks a tile in their corporate IdP portal and an unsolicited SAML assertion arrives at Cognito's ACS URL) is **not supported** by this flow. The daemon expects a callback request with a valid HMAC-signed `state` parameter scoped to an in-memory pending session. Without that state, the session cannot be resolved and the callback is rejected before JWT validation runs.

This is an ALB + Cognito design constraint, not a daemon limitation — the Cognito hosted UI only issues SP-initiated SAMLRequests.

### SAML attribute mapping for email

SAML IdPs use non-standard URN attribute names. The email attribute name varies by IdP:

| IdP | SAML email attribute name |
|---|---|
| ADFS / Azure AD (SAML) | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| Shibboleth / eduGAIN | `urn:oid:0.9.2342.19200300.100.1.3` (`mail`) |
| Okta (SAML) | typically `email` or a custom attribute |
| PingIdentity | IdP-specific, check IdP configuration |

Example Terraform for a SAML provider:

```hcl
resource "aws_cognito_identity_provider" "my_saml" {
  user_pool_id  = aws_cognito_user_pool.this.id
  provider_name = "MySAML"
  provider_type = "SAML"

  provider_details = {
    MetadataURL = "https://idp.corp.com/saml/metadata"
    # or: MetadataFile = file("saml-metadata.xml")
  }

  attribute_mapping = {
    # Cognito attribute = SAML attribute name from IdP
    email    = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    username = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
  }
}
```

### Impact on CN cross-check and AdminGetUser

Two separate JWT claims serve two separate purposes — and they have different configuration requirements:

| Claim | Value (SAML example) | Used for | Requires extra config? |
|---|---|---|---|
| `claims.Email` | `user@corp.com` | CN cross-check | **Yes** — requires `email` attribute mapping in Terraform |
| `username` | `MySAML_user@corp.com` | `AdminGetUser` lookup through ALB callback | No extra daemon config, but this is what ALB actually forwarded in production logs |

**CN cross-check** (`--cn-cross-check`) compares `claims.Email` against the certificate CN. `claims.Email` is only populated if the Cognito `attribute_mapping` maps the IdP's email attribute (e.g. the ADFS URN above) to the Cognito `email` attribute. Without this mapping the callback fails before reaching the cross-check.

**`AdminGetUser`** requires the full Cognito username. In this project's ALB callback flow, the observed `x-amzn-oidc-data` payload contained `username` and did **not** contain `cognito:username`. The daemon therefore uses `cognito:username` when present and falls back to `username`. No separate attribute mapping is needed for this lookup key.

## Attribute Mapping Requirement

Each external IdP uses its own attribute names. The daemon requires the `email` attribute to be present in the ALB JWT (`claims.Email`). Without it, the callback fails at JWT claim extraction with `"missing or empty email claim"`.

The mapping must be configured explicitly in Terraform for each external IdP:

```hcl
resource "aws_cognito_identity_provider" "google" {
  user_pool_id  = aws_cognito_user_pool.this.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id        = var.google_client_id
    client_secret    = var.google_client_secret
    authorize_scopes = "email openid profile"
  }

  attribute_mapping = {
    email    = "email"   # IdP attribute name → Cognito attribute name
    username = "sub"     # required: maps IdP user ID to Cognito username seed
  }
}
```

The `email` key on the left is the Cognito attribute name. The value (`"email"`) is the attribute name as sent by the IdP. This varies by provider:

| IdP | Email attribute name (right-hand side) |
|---|---|
| Google | `email` |
| Azure AD / Entra ID (OIDC) | `email` or `preferred_username` |
| Okta (OIDC) | `email` |
| ADFS (SAML) | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| Generic SAML | depends on the IdP configuration |

Without the `email` attribute mapping, `claims.Email` in the ALB JWT is empty and all federated users are rejected at the callback before any group or CN checks are performed.

> **Summary of what requires configuration vs what is automatic:**
> - `email` attribute mapping → **required** for CN cross-check (`claims.Email`). Must be configured explicitly for each IdP in Terraform.
> - ALB-forwarded lookup key for `AdminGetUser` → in observed production traffic for the native-Cognito flow this was `username`, not `cognito:username`. The daemon now supports both, preferring `cognito:username` and falling back to `username`.
> - Cognito User Pool group membership → in observed production traffic for the native-Cognito flow, it did **not** automatically appear in either `x-amzn-oidc-data` or `x-amzn-oidc-accesstoken`. Group membership was therefore verified through the Cognito Admin API. External IdP federation may differ and must be verified empirically.

## End-to-End SAML Federation Walkthrough

This section traces a single VPN connect from browser redirect through `client-auth`, for a SAML-federated user. It does not re-describe mechanics covered above (NameID, attribute mapping, Admin API vs claims) — it shows how they combine in one concrete flow.

**Scenario:** Corporate SAML IdP (`MySAML`) is linked to Cognito. The user has certificate CN `alice@corp.com`, the IdP emits `NameID=alice@corp.com` and the `emailaddress` SAML attribute, and the Cognito provider is configured with `email` and `username` attribute mapping. The required group is `vpn-users`, resolved via the Cognito Admin API (default mode).

1. **OpenVPN client.** `CLIENT:CONNECT` arrives on the management socket.
2. **Daemon.** Creates `PendingSession{SID}`, HMAC-signs the state blob, and sends `client-pending-auth` with `WEB_AUTH::,<callback-url>?state=<blob>`.
3. **OpenVPN client.** Opens the URL in the user's browser.
4. **Browser → ALB.** `GET /callback/{server}/{proto}?state=<blob>`.
5. **ALB (Cognito authenticate action).** No session cookie, so 302 to the Cognito hosted UI.
6. **Browser → Cognito.** Hosted UI shows "Sign in with MySAML".
7. **Cognito → IdP.** SP-initiated SAML `AuthnRequest`.
8. **IdP.** User authenticates (password, MFA, etc.).
9. **IdP → Cognito.** SAML Response posted to the Cognito ACS URL:
   - `NameID: alice@corp.com`
   - `.../emailaddress: alice@corp.com`
10. **Cognito.** First login auto-creates the user (`Username: MySAML_alice@corp.com`, `UserStatus: EXTERNAL_PROVIDER`, `email: alice@corp.com` via attribute mapping). Subsequent logins reuse the same user.
11. **Cognito → ALB.** OAuth2 code exchange returns the ID and access tokens.
12. **ALB.** Sets the session cookie, re-invokes the original request, and constructs the ES256-signed `x-amzn-oidc-data` JWT.
13. **ALB → Daemon.** `GET /callback/{server}/{proto}?state=<blob>` with headers:
    - `x-amzn-oidc-data: <ES256 JWT>`
    - `x-amzn-oidc-accesstoken: <Cognito access token>`
    - `x-amzn-oidc-identity: <Cognito sub>`
14. **Daemon (callback server).** State HMAC verified → `SID` → session looked up and atomically moved `PENDING` → `PROCESSING`.
15. **Daemon.** JWT header parsed (`kid`, `signer`). `signer == --alb-arn`, so ES256 is verified against the ALB public key fetched for `kid` (and `exp` is checked).
16. **Daemon.** Extracts claims:
    - `email: alice@corp.com`
    - `username: MySAML_alice@corp.com`
    - `cognito:username`: absent in this SAML flow
    - `sub: <Cognito UUID>`
17. **Daemon (CN cross-check).** Certificate CN `alice@corp.com` equals `claims.Email` → pass.
18. **Daemon (group resolution).** Default mode: `AdminGetUser("MySAML_alice@corp.com")` returns `UserStatus=EXTERNAL_PROVIDER`, `Enabled=true`. `AdminListGroupsForUser(...)` returns `[vpn-users]` → required group satisfied.
19. **Daemon.** Session `PROCESSING` → `AUTHORIZED`. The Cognito lookup username `MySAML_alice@corp.com` is stored on the session for later reauth.
20. **Daemon → OpenVPN.** `client-auth` plus push directives.
21. **OpenVPN.** Tunnel established. Later TLS renegotiations trigger `CLIENT:REAUTH`, which reuses the stored lookup username (not the certificate CN) for `AdminGetUser`.

Key differences vs a native-Cognito flow:

- Step 10: Cognito auto-provisions the user on first federated login; the username is always `MySAML_<NameID>`, not an email and not a UUID.
- Step 16: `cognito:username` is typically absent in the ALB-forwarded SAML JWT — the daemon falls back to `username`, which already contains `MySAML_alice@corp.com`.
- Step 18: `AdminGetUser` must receive the full `MySAML_alice@corp.com` value. Passing just `alice@corp.com` returns `UserNotFoundException`.
- Step 19: The stored lookup username (not CN) is what makes reauth work correctly for federated users across TLS renegotiations.

If the SAML provider instead emitted a persistent NameID (`MySAML_a3f7b2...`), steps 10, 16, 18, 19 would all use that opaque identifier as the username — step 17 (CN cross-check) still depends only on the separately-mapped `email` attribute and is unaffected.

## Group Resolution for Federated Users (Consolidated)

Group membership resolution is split across three mechanisms in this project. This section collects them in one place and states which works for federated users and under what conditions. For the IdP-side attribute-mapping details, see [SAML attribute mapping for email](#saml-attribute-mapping-for-email) above and the Terraform example in [`docs/architecture-design.md`](architecture-design.md).

| Mode | Flag | What the daemon does | Works for federated users? |
|---|---|---|---|
| Cognito Admin API (default) | `--groups-source=cognito-api` (default) | On callback/connect, `AdminListGroupsForUser` with the Cognito username from claims (`cognito:username` → fallback `username`). On reauth, group membership is checked only when `--check-required-group-on-reauth` is enabled. | **Yes.** Works with any federated IdP as long as ALB forwards a usable Cognito username. Production default. |
| JWT claim (operator-chosen) | `--groups-source=jwt-claim --groups-claim=<claim>` | On callback/connect, reads the top-level claim named `<claim>` from `x-amzn-oidc-data` and parses its value (JSON array, CSV, bracketed CSV, single string, or JSON array encoded as a string — see `docs/configuration.md#group-claim-parser`). Reauth cannot use JWT claims because no new ALB JWT is available on `CLIENT:REAUTH`; this mode cannot be combined with `--check-required-group-on-reauth=true`. | Only if the configured claim is explicitly present in the ALB-forwarded JWT. Native `cognito:groups` is typically absent in `x-amzn-oidc-data` — requires an explicit mapping (see below). |

### How to get group claims into the forwarded JWT for federated users

Two options, neither of which happens automatically:

1. **Attribute mapping from IdP → Cognito `custom:groups` exposed via userInfo.** The IdP emits a groups attribute (SAML: e.g. `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups`; OIDC: a `groups` claim). Map it to a custom Cognito attribute such as `custom:groups`, make sure the app client's read attributes include it, and the ALB `authenticate-cognito` action will forward it in `x-amzn-oidc-data`. Then set `--groups-source=jwt-claim --groups-claim=custom:groups`. See `docs/architecture-design.md` for a Terraform snippet and the 2048-char custom-attribute limit caveat.

2. **Pre-token generation Lambda trigger.** A Cognito pre-token Lambda can inject any claim name (including `cognito:groups`) into the ID token by reading IdP claims or by calling `AdminListGroupsForUser` internally. This requires the Cognito Essentials or Plus feature plan (`user_pool_tier = "ESSENTIALS"`) with event version V2_0 or V3_0; the Lite plan does not support access token customization. Verify the resulting claim shape with `--oidc-debug-claims` before depending on it — ALB forwards claims from Cognito's userInfo endpoint, not the ID token.

If neither is configured, claim-based group checks will always fail for federated users — use the default Cognito Admin API path instead.

### Trade-offs

| Concern | Cognito Admin API | Claim-based (`--groups-claim=<claim>`) |
|---|---|---|
| Extra AWS API call per connect | Yes (~10–50 ms) | No |
| IdP outage tolerance | Improved by `--reauth-cache` for reauth | N/A (claims already in token) |
| IAM permissions required | `cognito-idp:AdminGetUser`, `cognito-idp:AdminListGroupsForUser` | None for callback group checks. Reauth still needs `cognito-idp:AdminGetUser`, and also `cognito-idp:AdminListGroupsForUser` if `--check-required-group-on-reauth` is enabled. |
| Works out of the box for federated users | Yes | No — requires explicit mapping or Lambda trigger |
| Reflects group changes in IdP | Next connect; next reauth only when `--check-required-group-on-reauth` is enabled | Next federated login (Cognito refreshes attributes) |
| Compatible with Cognito native groups | Yes | Only if native group membership is explicitly exposed through the configured ALB-forwarded claim |

For any new federated deployment, start with the Cognito Admin API path. Move to claim-based checks only after verifying that the exact claim configured with `--groups-claim` is actually present in the ALB-forwarded JWT for that IdP (see [What Must Be Verified For External IdP](#what-must-be-verified-for-external-idp)).

## CN Cross-Check and Federated Users

The daemon's `--cn-cross-check` flag (enabled by default) compares the OpenVPN certificate CN against `claims.Email` from the ALB JWT:

```
cert CN = user@example.com
claims.Email = user@example.com  ← from IdP attribute mapping
→ check passes
```

For this to work with federated users, three conditions must all be true:

1. The external IdP provides an email attribute.
2. The Cognito attribute mapping maps it to the Cognito `email` attribute (see above).
3. The email address from the IdP matches the email used in the OpenVPN certificate CN.

If conditions 1 or 2 are not met, the callback fails with `"jwt validation failed"` (empty email claim). If condition 3 is not met — for example, the IdP provides `user@idp-domain.com` but the certificate CN is `user@corp.com` — the callback fails with `"Certificate Mismatch"`.

`username` / `cognito:username` is **not** used for the CN cross-check and cannot be: it would never match an email address in the certificate.

## Daemon Configuration for External IdP

The current Terraform module (`supported_identity_providers = ["COGNITO"]`) supports native users only. To add an external IdP, extend the Cognito module with an `aws_cognito_identity_provider` resource and configure `attribute_mapping` as shown above.

In addition, update the Cognito User Pool client to accept the new IdP:

```hcl
resource "aws_cognito_user_pool_client" "this" {
  # ...
  supported_identity_providers = ["COGNITO", "Google"]  # add IdP name here
}
```

### What Must Be Verified For External IdP

For external IdP federation, the exact ALB-forwarded claims must be verified empirically in a real callback flow. Do not assume they will match the native-Cognito flow.

At minimum, verify:

1. Which identifier claims appear in `x-amzn-oidc-data`
   Examples to check: `username`, `cognito:username`, `sub`, `email`
2. Which identifier claim works as the `AdminGetUser` / `AdminListGroupsForUser` lookup key
3. Whether any group claims appear in either:
   - `x-amzn-oidc-data`
   - `x-amzn-oidc-accesstoken`
4. Whether those group claims are native Cognito groups, custom mapped claims, or absent entirely

Recommended validation procedure:

1. Create a federated test user and add it to the required Cognito group
2. Run one successful browser callback through the ALB
3. Log and inspect:
   - forwarded request headers
   - raw `x-amzn-oidc-data` claims
   - raw `x-amzn-oidc-accesstoken` claims
4. Test `AdminGetUser` manually with each candidate identifier until the correct lookup key is confirmed
5. Only then decide whether group checks should use:
   - Cognito Admin API
   - forwarded JWT claims
   - custom mapped claims exposed through the exact claim configured with `--groups-claim`

Until that verification is done, the safe default for external IdP deployments is to assume that group membership may need to be resolved through the Cognito Admin API rather than through ALB-forwarded claims.

### Daemon flags for federated deployments

The auth daemon supports federated users by storing the Cognito lookup username from callback claims and by treating `EXTERNAL_PROVIDER` users as enabled during Cognito checks.

| Path | Federated behavior |
|---|---|
| Callback group check | Uses `cognito:username` when present and falls back to `username` for `AdminGetUser` / `AdminListGroupsForUser` |
| Reauth | Uses the Cognito lookup username stored at callback time, not the certificate CN. Reauth checks account existence/enabled status by default; it checks group membership only when `--check-required-group-on-reauth` is enabled. |
| User status | Accepts both `CONFIRMED` and `EXTERNAL_PROVIDER` users when the account is enabled |

The default Cognito Admin API path is the recommended production mode when the forwarded claims contain a usable Cognito username. Claim-based group checks are available only for the callback/connect decision, and only when the configured `--groups-claim` is present in the ALB-forwarded JWT:

```
--groups-source=jwt-claim
--groups-claim=<verified claim name>
```

Group membership is then read from that top-level claim in `x-amzn-oidc-data` instead of the Cognito API during callback handling. In observed ALB traffic, native `cognito:groups` was not present in `x-amzn-oidc-data`, so claim-based group checks require explicit token customization or userInfo-visible attribute mapping (for example, `custom:groups` forwarded through the app client). The exact forwarded claim shape must be verified with `--oidc-debug-claims` before relying on this mode. Claim names are case-sensitive and the parser accepts JSON arrays, CSV strings, bracketed CSV strings, single strings, and JSON arrays encoded as strings — see [`docs/configuration.md#group-claim-parser`](configuration.md#group-claim-parser). In observed Cognito/Entra mappings, multiple groups were emitted as a bracketed CSV string such as `"[uuid1, uuid2]"`, while a single group was emitted as a plain string such as `"uuid1"`. For Entra groups synchronized from AD DS, Cognito/Entra mappings can emit UUID/object-id-like values instead of display names; set `--required-group` to the exact value observed in the claim. Cloud-only Entra groups may emit display names, but this must still be verified from the debug logs.

This mode does not make reauth claim-based. `CLIENT:REAUTH` is an OpenVPN management event, not a browser callback, so there is no fresh ALB JWT to inspect. The daemon enforces this at startup: `--groups-source=jwt-claim` cannot be combined with `--check-required-group-on-reauth=true`. If reauth group enforcement is required, set `--groups-source=cognito-api` (the default) and `--check-required-group-on-reauth`, and keep Cognito Admin API access configured.

> **Warning for Entra ID / external IdP groups:** reauth does not re-query Entra
> ID, Azure AD, Okta, SAML, or any upstream IdP, and it does not parse fresh IdP
> group claims. If group membership exists only in IdP claims or in a mapped
> `custom:groups` claim, changes are reflected only after a new ALB/Cognito
> login refreshes `x-amzn-oidc-data`. Reauth-time group revocation requires
> `--groups-source=cognito-api`, `--check-required-group-on-reauth=true`, and
> group membership represented in Cognito groups. A possible future alternative
> is a dedicated Microsoft Graph reauth checker; see
> [Entra Graph Reauth Design](entra-graph-reauth.md).

## AWS Documentation References

| Topic | URL |
|---|---|
| Third-party IdP overview (social, OIDC, SAML) | https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-identity-federation.html |
| SAML IdP with Cognito (NameID, ADFS, Shibboleth) | https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-saml-idp.html |
| OIDC IdP with Cognito (Okta, OneLogin, Salesforce) | https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html |
| Attribute mapping (IdP attributes → Cognito attributes) | https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-specifying-attribute-mapping.html |
| AdminGetUser API reference | https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminGetUser.html |
| Linking federated users to existing profiles | https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-identity-federation-consolidate-users.html |

---

### Flag matrix: native vs federated IdP

| Configuration | Native users | Federated users |
|---|---|---|
| Default (no extra flags) | Full support | Full support when ALB forwards a Cognito lookup username |
| `--required-group` set | Enforced on callback/connect; also enforced on reauth only with `--check-required-group-on-reauth` | Enforced on callback/connect through Cognito Admin API; also enforced on reauth only with `--check-required-group-on-reauth` |
| `--groups-source=jwt-claim --groups-claim=<claim>` | Callback/connect only; supported when the configured claim is present in `x-amzn-oidc-data` | Callback/connect only; supported when the configured claim is present in `x-amzn-oidc-data` |
| `--cognito-skip-reauth` | Supported, but skips reauth account-status checks | Supported, but skips reauth account-status checks |
| `--groups-source=jwt-claim` + `--cognito-skip-reauth` | Supported, with both trade-offs above | Supported, with both trade-offs above |
