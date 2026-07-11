# Direct OIDC Authentication Through ALB

> **Status: planned, not implemented**
>
> This document defines a provider-neutral implementation plan for using an
> Application Load Balancer `authenticate-oidc` action instead of Cognito.
> Current Terraform modules use `authenticate-cognito` only.

## Goal

Allow the platform to authenticate directly against an OIDC-compliant identity
provider such as Microsoft Entra ID, Okta, or Keycloak:

```text
OpenVPN client
  -> WEB_AUTH callback
  -> ALB authenticate-oidc
  -> external OIDC provider
  -> ALB-signed x-amzn-oidc-data
  -> auth daemon
  -> client-auth / client-deny
```

Cognito remains the default and continues to be supported. Direct OIDC is an
explicit alternative deployment mode, not a fallback within one request.

## ALB Authentication Modes

Terraform exposes one top-level mode:

```hcl
alb_auth_mode = "cognito" # cognito | oidc
```

The value controls the authentication action in both callback deployment
paths:

- static callback target groups in single-instance mode;
- Lambda Router target group in multi-instance mode.

Exactly one authentication action is configured on each callback listener
rule:

- `cognito` creates `authenticate_cognito`;
- `oidc` creates `authenticate_oidc`.

The subsequent forward action and callback routing are unchanged.

### OIDC configuration

OIDC mode requires:

| Terraform input | Description |
|---|---|
| `oidc_issuer` | Exact issuer identifier |
| `oidc_authorization_endpoint` | HTTPS authorization endpoint |
| `oidc_token_endpoint` | HTTPS token endpoint |
| `oidc_user_info_endpoint` | HTTPS UserInfo endpoint |
| `oidc_client_id` | OIDC application client ID |
| `oidc_client_secret` | OIDC application client secret, sensitive |
| `oidc_scope` | Requested scopes; default `openid email profile` |
| `alb_auth_session_timeout` | ALB browser session lifetime |

The IdP application must allow this redirect URI:

```text
https://<alb-domain>/oauth2/idpresponse
```

The issuer and endpoints must satisfy ALB OIDC requirements. Endpoint DNS must
be publicly resolvable and endpoint certificates must chain to a publicly
trusted CA. ALB must have IPv4 connectivity to the IdP endpoints.

Terraform validation rejects:

- OIDC inputs when `alb_auth_mode="cognito"`;
- missing or empty required OIDC inputs in OIDC mode;
- non-HTTPS endpoint URLs;
- unsupported auth mode values.

## Client Secret Handling

The OIDC client secret is required by the ALB listener action. Treat it as a
sensitive deployment input:

- mark Terraform variables and outputs as `sensitive`;
- do not print the value in plans, logs, cloud-init, or daemon configuration;
- use encrypted remote Terraform state with restricted IAM access;
- supply the value from the deployment secret-management workflow rather than
  committing it to `.tfvars`;
- document that the ELB API and Terraform state still need access to the raw
  value when configuring `authenticate_oidc`.

Secret rotation updates the listener action with the new client secret. The
rollout must preserve the existing ALB authentication session cookie behavior
and be tested with both new and existing browser sessions.

## Daemon Behavior

The daemon continues to trust the ALB boundary, not tokens signed directly by
the external IdP. After successful OIDC authentication, ALB forwards:

- `x-amzn-oidc-data`: UserInfo-derived claims in a JWT signed by ALB;
- `x-amzn-oidc-identity`: the UserInfo `sub` value;
- `x-amzn-oidc-accesstoken`: the access token returned by the IdP.

The existing ALB JWT validation remains mandatory:

1. Validate the ALB ES256 signature.
2. Require the configured ALB ARN in the `signer` header.
3. Validate expiry.
4. Parse the required UserInfo claims.
5. Compare certificate CN with the OIDC `email` claim when
   `--cn-cross-check=true`.
6. Apply group or role authorization.

The daemon must not validate the external IdP ID token because ALB does not
forward that token to targets. It must not call the IdP authorization or token
endpoints.

## Claims and Authorization

Direct OIDC mode requires claim-based callback authorization:

```text
--groups-source=jwt-claim
--groups-claim=<verified-claim>
```

The exact group claim is provider- and tenant-specific. Candidate claims such
as `groups`, `roles`, or application roles must not be assumed to exist.
Before enabling authorization in production:

1. Enable restricted OIDC claim debugging in a test environment.
2. Capture the keys and shapes present in `x-amzn-oidc-data`.
3. Confirm `email`, `sub`, and the selected authorization claim.
4. Test users with no groups, one group, multiple groups, and group-overage
   behavior where the provider supports it.
5. Configure stable group IDs or role values, not display names.

OIDC debug logs must redact token values and must not be enabled permanently in
production.

## Reauthentication

`CLIENT:REAUTH` does not contain fresh ALB or OIDC headers. The existing
Cognito `AdminGetUser` and `AdminListGroupsForUser` calls are not valid in
direct OIDC mode.

The first implementation uses this policy:

- callback/connect authorization uses ALB-forwarded claims;
- reauth confirms local session ownership and lifetime but performs no IdP API
  call;
- native OpenVPN `session-timeout` provides the hard maximum session duration;
- after disconnect or session expiry, the user completes a new browser OIDC
  flow;
- `--check-required-group-on-reauth=true` is rejected in direct OIDC mode;
- Cognito-specific reauth flags and user-pool configuration are rejected or
  ignored only where explicitly documented; they must not silently call
  Cognito.

Add an explicit daemon identity-provider mode instead of treating
`--cognito-skip-reauth` as the production OIDC solution:

```text
--identity-provider=cognito # cognito | oidc
```

Future provider-specific reauth checkers, such as Microsoft Graph, must use a
separate interface and configuration. They are outside the first direct OIDC
release.

## DynamoDB Session Ownership

The optional DynamoDB global session store is independent of the ALB auth
mode. Its v1 identity remains the normalized certificate CN verified against
the OIDC `email` claim.

Therefore direct OIDC with DynamoDB requires:

```text
--cn-cross-check=true
```

The provider's technical username must not replace CN. If a future deployment
supports email aliases or multiple valid CN values for one person, a later
identity mode may use namespaced `<issuer>#<sub>` ownership keys.

## IAM and Network Changes

In direct OIDC mode:

- remove Cognito user-pool requirements from the callback listener modules;
- do not grant `cognito-idp:AdminGetUser` or
  `cognito-idp:AdminListGroupsForUser` solely for authentication;
- Cognito VPC endpoints are not required by the daemon;
- ALB requires outbound IPv4 connectivity to the configured OIDC endpoints;
- callback daemon and Lambda Router security-group behavior remains unchanged.

The deployment documentation must show the required network path for both
internet-facing and internal ALBs. An internal ALB without suitable outbound
connectivity cannot complete direct OIDC authentication.

## Observability

Add stable dimensions or fields identifying the auth mode without including
tenant-specific secrets:

- `AuthMode=cognito|oidc` on authentication metrics;
- startup log containing mode, issuer host, requested scope, and claim name;
- callback rejection reasons for missing `email`, missing `sub`, missing group
  claim, and malformed claim type;
- no client ID, client secret, access token, signed state, or full JWT in logs.

Existing callback routing, upstream-unavailable, and ALB JWT validation metrics
continue to apply.

## Test Plan

### Terraform

1. Cognito mode produces only `authenticate_cognito` actions.
2. OIDC mode produces only `authenticate_oidc` actions in single- and
   multi-instance deployments.
3. Missing OIDC fields, mixed Cognito/OIDC inputs, invalid mode, and non-HTTPS
   endpoints fail validation.
4. Plans and outputs do not display the client secret.
5. OIDC mode does not grant unnecessary Cognito Admin API permissions.

### Daemon

1. Valid ALB-signed OIDC claims complete callback authentication.
2. Invalid ALB signature or signer is rejected independently of the IdP.
3. Missing or mismatched `email` fails CN cross-check.
4. Configured group/role claims support string and array formats already
   accepted by the claim parser.
5. Missing, malformed, and overage-style claims fail closed with stable reason
   codes.
6. OIDC mode never invokes the Cognito checker.
7. Reauth succeeds according to local policy without an IdP call and remains
   bounded by OpenVPN `session-timeout`.
8. Reauth group checking is rejected at startup in the first OIDC release.

### AWS integration

1. Register the ALB `/oauth2/idpresponse` URL in a test IdP application.
2. Complete login, callback, `client-auth`, and tunnel establishment.
3. Verify the actual `x-amzn-oidc-data` claim set and selected group/role claim.
4. Test logout, expired ALB session, expired daemon state, denied group, and
   disabled IdP user behavior.
5. Test OIDC client-secret rotation.
6. Test direct OIDC through both static callback routing and Lambda Router.
7. Confirm reconnect after `session-timeout` starts a fresh browser flow.

## Rollout

1. Implement the auth-mode configuration without changing the Cognito default.
2. Add Terraform tests for both listener-rule variants.
3. Validate one OIDC provider in a non-production AWS environment.
4. Record the observed ALB-forwarded claims in provider-specific documentation.
5. Run the complete OpenVPN connect, callback, reauth, timeout, and reconnect
   suite.
6. Enable OIDC mode for a pilot VPN group.
7. Add additional providers only after validating their UserInfo claim shape
   and lifecycle behavior.

## Non-Goals for the First Release

- Direct daemon-to-IdP authorization-code exchange.
- ID-token validation by the daemon.
- Automatic OIDC discovery from `/.well-known/openid-configuration` in
  Terraform.
- Provider-specific Graph/API reauth checks.
- Dynamic provider selection per request.
- SAML directly on ALB; SAML remains possible through a compatible OIDC broker
  or Cognito federation.

## Related Documentation

- [Direct Entra OIDC](direct-entra-oidc.md)
- [Entra Graph Reauth](entra-graph-reauth.md)
- [Group Authorization and OIDC Claims](group-authorization.md)
- [DynamoDB Global Session Ownership](dynamodb-session-store.md)
- [AWS ALB user authentication](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html)
