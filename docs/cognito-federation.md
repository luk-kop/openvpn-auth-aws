# Cognito User Types and Federation

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
   - custom mapped claims such as `custom:groups`

Until that verification is done, the safe default for external IdP deployments is to assume that group membership may need to be resolved through the Cognito Admin API rather than through ALB-forwarded claims.

### Daemon flags for federated deployments

The auth daemon has two known issues affecting federated users that are not yet fixed (see `CODE_REVIEW_EXTERNAL.md`):

| Issue | Affected path | Workaround |
|---|---|---|
| `UserStatus = EXTERNAL_PROVIDER` causes reauth denial | Reauth | `--cognito-skip-reauth` |
| `AdminGetUser` lookup fails for federated users | Callback (group check), Reauth | `--cognito-groups-from-claims` + `--cognito-skip-reauth` |

Until the fixes described in `CODE_REVIEW_EXTERNAL.md` are implemented, the only fully working configuration for deployments with an external IdP is:

```
--cognito-groups-from-claims=true
--cognito-skip-reauth=true
```

This bypasses both broken paths at the cost of not verifying user account status on TLS renegotiation. Group membership is read from JWT claims instead of the Cognito API, which requires those claims to be present in the ALB-forwarded token. In observed ALB traffic, `cognito:groups` was not present by default, so claim-based group checks require explicit claim mapping such as `custom:groups`.

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

| Configuration | Native users | Federated users (pre-fix) | Federated users (post-fix) |
|---|---|---|---|
| Default (no extra flags) | ✅ full support | ✗ reauth fails | ✅ full support |
| `--required-group` set | ✅ full support | ✗ callback + reauth fail | ✅ full support |
| `--cognito-groups-from-claims` | ✅ | ✗ reauth fails | ✅ |
| `--cognito-skip-reauth` | ✅ (no reauth check) | ✗ callback fails if `--required-group` set | ✅ (no reauth check) |
| `--cognito-groups-from-claims` + `--cognito-skip-reauth` | ✅ (no reauth check) | ✅ (no reauth check) | ✅ (no reauth check) |
