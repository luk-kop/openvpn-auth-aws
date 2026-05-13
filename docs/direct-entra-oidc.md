# Direct Entra OIDC

## Table of Contents

- [Why Consider This](#why-consider-this)
- [Target Flow](#target-flow)
- [Expected Daemon Model](#expected-daemon-model)
- [ALB Configuration Shape](#alb-configuration-shape)
- [Claims And Groups](#claims-and-groups)
- [Reauth Options](#reauth-options)
- [Comparison With Cognito Federation](#comparison-with-cognito-federation)
- [Recommended MVP](#recommended-mvp)
- [Open Questions](#open-questions)
- [References](#references)

This document describes a possible future deployment mode where ALB authenticates
directly against Microsoft Entra ID with `authenticate-oidc`, without Cognito in
the login path. It is not implemented in the current Terraform modules.

## Why Consider This

For Entra-first environments, Cognito federation adds an extra identity layer:

```text
ALB authenticate-cognito -> Cognito federation -> Entra ID -> Cognito user profile -> daemon
```

This creates operational questions that are not always useful for a VPN:

- Cognito creates persistent `EXTERNAL_PROVIDER` users on first federated login.
- Entra lifecycle changes do not automatically delete or disable those Cognito
  users.
- Reauth group checks through Cognito only work when VPN access is represented
  as Cognito group membership.
- Mapping Entra group claims into Cognito and then into ALB-forwarded claims can
  be harder to reason about than using Entra directly.

Direct Entra OIDC removes that middle layer:

```text
ALB authenticate-oidc -> Entra ID -> x-amzn-oidc-data -> daemon
```

This can be a better fit when Entra is the real source of truth for users and
groups.

## Target Flow

1. OpenVPN client starts a browser-based auth flow.
2. Browser reaches the ALB callback URL.
3. ALB `authenticate-oidc` redirects the user to Entra ID.
4. Entra authenticates the user and returns OIDC tokens to ALB.
5. ALB calls the configured token/userInfo endpoints and forwards
   `x-amzn-oidc-data`, `x-amzn-oidc-accesstoken`, and `x-amzn-oidc-identity` to
   the daemon.
6. The daemon validates the ALB-signed JWT and checks callback authorization.
7. Reauth is handled separately because `CLIENT:REAUTH` does not contain fresh
   ALB/OIDC headers.

## Expected Daemon Model

Callback/connect authorization fits the existing claim-based group model:

```text
--groups-source=jwt-claim
--groups-claim=<verified-entra-claim>
```

The exact claim must be verified with `--oidc-debug-claims` in a real ALB/Entra
callback. Do not assume `groups`, `roles`, or `oid` are present until observed in
`x-amzn-oidc-data`.

The daemon also needs a stable user identifier for reauth if a future Microsoft
Graph checker is enabled. For Entra, that should usually be the user object ID
claim (`oid`) if it is available in the forwarded claims.

## ALB Configuration Shape

Terraform would need a new ALB auth mode that uses `authenticate_oidc` instead
of `authenticate_cognito`.

Conceptually, the listener rule needs:

```hcl
authenticate_oidc {
  authorization_endpoint = "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize"
  token_endpoint         = "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token"
  user_info_endpoint     = "https://graph.microsoft.com/oidc/userinfo"
  issuer                 = "https://login.microsoftonline.com/<tenant-id>/v2.0"
  client_id              = var.entra_client_id
  client_secret          = var.entra_client_secret
  scope                  = "openid email profile"
  session_timeout        = var.alb_auth_session_timeout
}
```

This is illustrative. Verify the exact Entra issuer and userInfo endpoint for
the tenant and cloud before implementation.

Store the OIDC client secret securely. Do not put the raw secret directly in
Terraform state unless that trade-off is explicitly accepted. A production
implementation should prefer Secrets Manager or another controlled secret
delivery path where possible.

## Claims And Groups

Direct Entra OIDC avoids Cognito federated user lifecycle, but it does not remove
the need to verify claims.

Important caveats:

- ALB forwards userInfo-derived claims in `x-amzn-oidc-data`; it does not
  forward the ID token to the daemon.
- Entra group claims can be large.
- Entra may emit group overage indicators instead of a complete group list when
  the user has many groups.
- Application roles may be easier to handle than raw group IDs for some
  deployments.
- Group display names are not stable identifiers. Prefer object IDs or app role
  values.

For callback-only authorization, use the claim parser described in
[`group-authorization.md`](group-authorization.md). For example:

```text
--groups-source=jwt-claim
--groups-claim=roles
```

or:

```text
--groups-source=jwt-claim
--groups-claim=groups
```

Only use a claim after `--oidc-debug-claims` confirms it appears in
`x-amzn-oidc-data` with the expected shape.

## Reauth Options

Direct Entra OIDC does not make reauth claim-based. OpenVPN `CLIENT:REAUTH` is a
management event and does not include fresh ALB/OIDC headers.

There are three practical options:

1. **No reauth group check.** Use callback/connect authorization plus
   `--max-session-duration` to cap session lifetime. This is simplest.
2. **Force periodic reconnect.** Keep ALB session timeout and VPN session
   duration short enough that users re-enter the browser flow regularly.
3. **Microsoft Graph reauth checker.** Store the Entra user object ID at
   callback time and query Graph on reauth for account status and group
   membership. See [Entra Graph Reauth Design](entra-graph-reauth.md).

If active-session revocation from Entra groups is a hard requirement, option 3
is the only direct-Entra model that checks the current state during reauth.

## Comparison With Cognito Federation

| Concern | Cognito Federation | Direct Entra OIDC |
|---|---|---|
| Login broker | Cognito delegates to Entra | ALB delegates directly to Entra |
| Persistent Cognito federated users | Yes | No |
| Cognito groups for reauth | Available if maintained | Not available |
| Entra group claims on callback | Must pass through Cognito/userInfo mapping | Comes from Entra/ALB OIDC flow, subject to userInfo behavior |
| Reauth-time Entra revocation | Requires Cognito group sync or a new Graph checker | Requires a Graph checker |
| Terraform complexity | Existing mode | New ALB auth mode required |
| IdP-specific daemon logic | Not needed for Cognito API mode | Needed only if Graph reauth checker is enabled |

## Recommended MVP

For a first direct-Entra experiment:

1. Add a Terraform auth mode: `alb_auth_mode = "cognito" | "oidc"`.
2. Configure ALB `authenticate_oidc` for Entra.
3. Enable `--oidc-debug-claims`.
4. Verify `email`, stable user ID (`oid` or equivalent), and candidate group
   claim in `x-amzn-oidc-data`.
5. Run callback authorization with:

   ```text
   --groups-source=jwt-claim
   --groups-claim=<verified-claim>
   ```

6. Keep reauth simple at first:
   - no group check on reauth,
   - use `--max-session-duration`,
   - document that revocation waits until reconnect/session expiry.
7. Add the Graph reauth checker only if active-session revocation is required.

## Open Questions

- Which Entra claim is reliably present in ALB-forwarded `x-amzn-oidc-data` for
  the stable user object ID?
- Are groups, roles, or app roles the better authorization signal for the
  target tenant?
- How does the tenant handle users with many group memberships and overage?
- Should Terraform support both Cognito and OIDC auth modes in one module, or
  should direct OIDC be a separate module?
- How should client secrets be delivered to ALB without unnecessarily exposing
  them in Terraform state?
- Is active-session revocation required, or is max session duration sufficient?

## References

- AWS ALB user authentication: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
- Microsoft identity platform OIDC: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
- Microsoft Graph reauth design for this project: [Entra Graph Reauth Design](entra-graph-reauth.md)
