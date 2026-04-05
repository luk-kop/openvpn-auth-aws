# Daemon Security Features

Security controls implemented in the auth daemon, grouped by the attack they mitigate.

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

On callback, the daemon verifies the HMAC before touching the session store. A request with a forged, tampered, or replayed state is rejected before any session lookup occurs. The HMAC key is either a static secret or fetched from AWS Secrets Manager (`--secrets-manager-secret-id`).

The payload includes:

- `sid` — random session ID (16 bytes, cryptographically random)
- `iat` — issued-at timestamp
- `exp` — expiry timestamp (set to `hand_window` seconds from issue)

**Default:** always enforced. Key source: `--hmac-secret` (static) or `--secrets-manager-secret-id` (AWS Secrets Manager).

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

> **Note:** This check should be disabled (`--cn-cross-check=false`) when using federated Cognito identities, because the certificate CN is the user's email but the Cognito username has the form `providerName_externalId`. See [Cognito Federation](cognito-federation.md) for details.

**Default:** `true` (enabled).

---

## 7. Required Group Check

**Flag:** `--required-group` / `VPN_AUTH_REQUIRED_GROUP`

After a successful callback, the daemon calls Cognito `AdminListGroupsForUser` to verify the authenticated user is a member of the configured group. Users not in the group are denied with `client-deny`.

When empty, group membership is not checked and any authenticated Cognito user can connect.

**Default:** `"vpn-users"` (as set in the Terraform `required_group` variable).

---

## 8. Group Check on Reauth

**Flag:** `--check-groups-on-reauth` / `VPN_AUTH_CHECK_GROUPS_ON_REAUTH`

By default, the group check only runs at initial authentication. When this flag is enabled, group membership is re-verified on every `CLIENT:REAUTH` (TLS renegotiation). Users removed from the required group are disconnected at the next renegotiation cycle (`reneg-sec`).

**Default:** `false` (disabled — group is only checked at connect time).

---

## 9. Single Session Per User

**Flag:** `--single-session-per-user` / `VPN_AUTH_SINGLE_SESSION_PER_USER`

Enforces one active VPN session per certificate CN. When a new connect arrives for a CN that already has an active session, the old session is evicted:

- Pending session → `client-deny` for the old CID
- Established session → `client-kill ... HALT` for the old CID, so the replaced device does not auto-reconnect into an eviction loop

> **Multi-instance limitation:** enforcement is per-instance only. See [Single-Session-Per-User in Multi-Instance Mode](multi-instance-single-session.md) for details and a proposed fix.

**Default:** `true` (enabled).

---

## 10. Session TTL and Auth Timeout

**Flag:** `--auth-timeout` / `VPN_AUTH_AUTH_TIMEOUT`

Pending sessions (awaiting browser completion) are reaped after `--auth-timeout` seconds. A session that is never completed (user abandons the browser flow) is cleaned up automatically — it cannot linger and be replayed later.

**Default:** `300s`.

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
| HMAC state signing | `--hmac-secret` / `--secrets-manager-secret-id` | on | State forgery and replay |
| State expiry | `--hand-window` | 300s | Long-lived replay window |
| ALB JWT validation (ES256) | — | on | Forged or tampered OIDC callbacks |
| CN cross-check | `--cn-cross-check` | on | Identity mismatch between cert and OIDC |
| Required group | `--required-group` | `vpn-users` | Unauthorised Cognito users |
| Group check on reauth | `--check-groups-on-reauth` | off | Revoked access persisting after group removal |
| Single session per user | `--single-session-per-user` | on | Concurrent sessions per CN (single-instance only) |
| Session TTL | `--auth-timeout` | 300s | Abandoned pending sessions accumulating |
| Max session duration | `--max-session-duration` | off | Indefinitely long sessions |
| Management socket auth | OpenVPN config | on | Unauthorised management commands |
