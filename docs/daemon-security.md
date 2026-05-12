# Daemon Security Features

Security controls implemented in the auth daemon, grouped by the attack they mitigate.

## Layered Security Model

This project intentionally uses a layered VPN authentication model:

```text
OpenVPN profile possession
  -> TLS client certificate + tls-crypt
  -> OpenVPN management-client-auth hold
  -> signed WebAuth callback state
  -> ALB/Cognito OIDC authentication
  -> certificate CN to OIDC email cross-check
  -> Cognito group authorization
  -> reauth/session lifetime enforcement
```

The client certificate is the first identity signal. The browser OIDC flow is the interactive user authorization step. A successful connection requires both: a valid OpenVPN client profile and a successful authenticated callback.

For the detailed OpenVPN management-message and callback flow, see [OpenVPN WebAuth Protocol](webauth-protocol.md).

Key properties:

- **Client profile possession is required.** The generated client profile includes a TLS client certificate and private key. The server expects a certificate-derived `common_name`; certificate-less connects are denied by the daemon.
- **`tls-crypt` protects the OpenVPN control channel.** It encrypts and authenticates the TLS control channel with a shared static key, reducing unauthenticated exposure before the TLS/auth flow.
- **No static VPN password is required.** The server uses `auth-user-pass-optional` so clients do not need `auth-user-pass`; identity comes from the certificate CN and authorization comes from OIDC.
- **OpenVPN cannot complete auth without the daemon.** `management-client-auth` puts the client into pending authentication, and the daemon must send `client-auth <cid> <kid>` before the tunnel is established.
- **The WebAuth callback is bound to daemon state.** The `state` parameter in the `WEB_AUTH::` URL is HMAC-signed and expires after the configured handshake window.
- **The callback must be authenticated by ALB/Cognito.** The daemon verifies the ALB-signed OIDC JWT before accepting a callback.
- **Certificate identity is bound to browser identity.** With `--cn-cross-check=true`, the certificate CN must match the OIDC `email` claim.
- **Authorization is separate from authentication.** `--required-group` restricts access to a Cognito group, and optional reauth group checks can remove access after group membership changes.
- **Session controls limit stale access.** Pending sessions expire, optional maximum session duration can kill long-lived tunnels, and OpenVPN duplicate-CN protection prevents concurrent sessions for the same CN within one server process.

This is deliberately more conservative than an SSO-only or certificate-less OpenVPN design. The certificate gates entry into the OpenVPN auth flow, while OIDC decides whether the human using that certificate may establish the tunnel.

---

## 1. WebAuth Client Capability Check

**Code:** `internal/auth/handler.go` — `handleConnect`

Before starting an auth session the daemon checks that the connecting client announces WebAuth support via the `IV_SSO` environment variable (sent by OpenVPN from the client's `push-peer-info`):

```text
IV_SSO must contain "webauth" or "openurl"
```

Clients that do not advertise this capability are denied immediately with `client-deny` and reason `"client does not support WebAuth"`. This prevents clients from connecting without going through the browser-based OIDC flow.

**Default:** always enforced, not configurable.

---

## 2. Certificate CN Presence Check

**Code:** `internal/auth/handler.go` — `handleConnect`

A connecting client must have a non-empty `common_name` in the OpenVPN environment (derived from the TLS client certificate). Connections with a missing CN are denied immediately.

**Default:** always enforced, not configurable.

---

## 3. HMAC-Signed State Blob

**Code:** `internal/auth/state.go`, `internal/secrets/`

The `state` parameter embedded in the WebAuth URL (`WEB_AUTH::`) is a signed blob:

```text
base64url(json({ sid, iat, exp })) . HMAC-SHA256(payload)
```

On callback, the daemon verifies the HMAC before touching the session store. A request with a forged, tampered, or replayed state is rejected before any session lookup occurs. The HMAC key is either a static secret or fetched once at startup from AWS Secrets Manager (`--hmac-secret-secret-id`).

The payload includes:

- `sid` — random session ID (16 bytes, cryptographically random)
- `iat` — issued-at timestamp
- `exp` — expiry timestamp (set to `hand_window` seconds from issue)

**Default:** always enforced. Key source: `--hmac-secret` (static), `--hmac-secret-secret-id` (AWS Secrets Manager), or a random startup key when neither static source is configured. A random startup key is process-local and in-memory only: daemon restarts invalidate in-flight state blobs, and separate daemon instances cannot verify each other's state values.

---

## 4. State Expiry

**Code:** `internal/auth/state.go` — `DecodeState`

After HMAC verification, the daemon checks `exp` against the current time. An expired state blob is rejected even if the signature is valid. This limits the replay window to `hand_window` seconds.

**Default:** always enforced. Window controlled by `--hand-window` (default `300s`).

---

## 5. ALB JWT Signature Validation (ES256)

**Code:** `internal/cognito/albkeys.go`, `internal/callback/`

The callback endpoint requires the `x-amzn-oidc-data` header injected by the ALB after a successful Cognito authentication. The daemon:

1. Extracts the `kid` from the JWT header
2. Fetches the corresponding ECDSA public key from `https://public-keys.auth.elb.<region>.amazonaws.com/<kid>`
3. Verifies the ES256 signature

A callback without this header, or with an invalid/expired JWT, is rejected with `403 Forbidden` and the session is denied.

**Default:** always enforced, not configurable.

---

## 6. CN Cross-Check

**Flag:** `--cn-cross-check` / `VPN_AUTH_CN_CROSS_CHECK`

After validating the ALB JWT, the daemon compares the `email` claim from `x-amzn-oidc-data` against the certificate CN. If they do not match, the callback returns `403 Certificate Mismatch` and the session is denied with reason `cn_mismatch`.

This prevents a scenario where a user with a valid certificate for one identity authenticates via OIDC as a different identity.

> **Federated Cognito note:** keep this check enabled when the external IdP provides an email attribute, Cognito maps it to the `email` claim, and that email matches the certificate CN. Disable it only for deployments where the IdP cannot provide a stable email claim that matches certificate issuance policy. `username` / `cognito:username` is not used for this check and may have a provider-specific form such as `providerName_externalId`. See [Cognito Federation](cognito-federation.md) for details.

**Default:** `true` (enabled).

---

## 7. Required Group Check

**Flag:** `--required-group` / `VPN_AUTH_REQUIRED_GROUP`

After a successful callback, the daemon verifies that the authenticated user is a member of the configured group. By default (`--groups-source=cognito-api`), it calls Cognito `AdminListGroupsForUser`. With `--groups-source=jwt-claim`, it reads group membership from the top-level claim named by `--groups-claim` in the ALB-forwarded `x-amzn-oidc-data` JWT. Users not in the group are denied with `client-deny`.

When empty, group membership is not checked and any authenticated Cognito user can connect.

**Default:** empty in the daemon, which disables group enforcement. Terraform sets `required_group = "vpn-users"` by default for deployed infrastructure.

---

## 8. Group Check on Reauth

**Flag:** `--check-required-group-on-reauth` / `VPN_AUTH_CHECK_REQUIRED_GROUP_ON_REAUTH`

By default, the group check only runs at initial authentication. When this flag is enabled, group membership is re-verified on every `CLIENT:REAUTH` (TLS renegotiation) through the Cognito Admin API. Users removed from the required group are disconnected at the next renegotiation cycle (`reneg-sec`). Claim-based group checks cannot run on reauth because there is no fresh ALB JWT during `CLIENT:REAUTH`; the daemon rejects `--groups-source=jwt-claim` combined with `--check-required-group-on-reauth=true` at startup.

**Default:** `false` (disabled — group is only checked at connect time).

---

## 9. Duplicate CN Policy

**OpenVPN config:** `duplicate-cn` must be absent.

OpenVPN rejects duplicate certificate CNs by default within a single server process. The `duplicate-cn` directive disables that protection and is unsupported for production deployments of this project.

The daemon keeps local `CN -> CID` tracking only as defensive cleanup for stale local state. It is not a replacement for OpenVPN's default duplicate-CN behavior and is not a global single-session security control across UDP/TCP daemons or multiple EC2 instances.

---

## 10. Session TTL and Auth Timeout

**Flag:** `--auth-timeout` / `VPN_AUTH_AUTH_TIMEOUT`

Pending sessions (awaiting browser completion) are reaped after `--auth-timeout` seconds. A session that is never completed (user abandons the browser flow) is cleaned up automatically — it cannot linger and be replayed later.

**Default:** `270s` (`4m30s`).

---

## 11. Max Session Duration

**Flag:** `--max-session-duration` / `VPN_AUTH_MAX_SESSION_DURATION`

Enforces a hard time limit on established VPN sessions. Uses two independent mechanisms:

- **Hard timer** — a goroutine sends `client-kill` after the configured duration
- **Reauth backstop** — on each `CLIENT:REAUTH`, if the duration has elapsed, `client-deny` is sent without calling Cognito

When `0` (default), session duration is unlimited.

**Default:** `0` (disabled).

---

## 12. Management Socket Authentication

**OpenVPN config:** `management /run/openvpn/management.sock unix /path/to/management-pw`

The OpenVPN management socket is protected by a password file. The daemon sends the password on connect (`ENTER PASSWORD:`). Without the correct password the daemon cannot issue `client-auth`, `client-deny`, or `client-kill` commands.

**Default:** always required by the OpenVPN server config. Managed via the PKI secret in AWS Secrets Manager.

---

## Summary Table

| Feature | Flag | Default | What it prevents |
|---------|------|---------|-----------------|
| WebAuth capability check | — | on | Clients bypassing browser auth |
| CN presence check | — | on | Anonymous / certificate-less connects |
| HMAC state signing | `--hmac-secret` / `--hmac-secret-secret-id` | on | State forgery and replay |
| State expiry | `--hand-window` | 300s | Long-lived replay window |
| ALB JWT validation (ES256) | — | on | Forged or tampered OIDC callbacks |
| CN cross-check | `--cn-cross-check` | on | Identity mismatch between cert and OIDC |
| Required group | `--required-group` | empty (Terraform: `vpn-users`) | Unauthorised Cognito users |
| Required group check on reauth | `--check-required-group-on-reauth` | off | Revoked access persisting after group removal |
| Duplicate CN policy | OpenVPN config (`duplicate-cn` absent) | on | Concurrent sessions per CN in one OpenVPN process |
| Session TTL | `--auth-timeout` | 270s | Abandoned pending sessions accumulating |
| Max session duration | `--max-session-duration` | off | Indefinitely long sessions |
| Management socket auth | OpenVPN config | on | Unauthorised management commands |
