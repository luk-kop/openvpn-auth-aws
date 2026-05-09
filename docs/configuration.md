# Configuration

All flags can be set via environment variables with `VPN_AUTH_` prefix.

## Daemon Flags

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--management-socket` | `VPN_AUTH_MANAGEMENT_SOCKET` | `/run/openvpn/management.sock` | Path to OpenVPN management socket |
| `--management-password-file` | `VPN_AUTH_MANAGEMENT_PASSWORD_FILE` | `/etc/openvpn/management-pw` | File containing management password |
| `--callback-url` | `VPN_AUTH_CALLBACK_URL` | — | Full callback URL including path (e.g. `https://vpn-auth.example.com/callback/01/udp`). The daemon appends `?state=...` and nothing else. Required. |
| `--callback-port` | `VPN_AUTH_CALLBACK_PORT` | `8080` | Port the daemon listens on for ALB-forwarded `GET /callback` requests |
| `--alb-arn` | `VPN_AUTH_ALB_ARN` | — | ALB ARN used to validate the `signer` field in ALB JWTs. If absent, JWT signature validation is skipped (dev/test only). Always set in production. |
| `--alb-public-key-base-url` | `VPN_AUTH_ALB_PUBLIC_KEY_BASE_URL` | — | Base URL for fetching ALB public keys. Default: `https://public-keys.auth.elb.{region}.amazonaws.com` (derived from `--aws-region`). Override for AWS China partition (e.g. `https://public-keys.auth.elb.cn-north-1.amazonaws.com.cn`). |
| `--hmac-secret` | `VPN_AUTH_HMAC_SECRET` | — | HMAC secret for signing state blobs |
| `--hmac-secret-secret-id` | `VPN_AUTH_HMAC_SECRET_SECRET_ID` | — | AWS Secrets Manager secret ID containing the HMAC secret for signing state blobs. Mutually exclusive with `--hmac-secret`; fetched once at daemon startup. |
| `--aws-region` | `AWS_REGION` | `eu-west-1` | AWS region |
| `--cognito-user-pool-id` | `VPN_AUTH_COGNITO_USER_POOL_ID` | — | Cognito User Pool ID |
| `--cognito-issuer-url` | `VPN_AUTH_COGNITO_ISSUER_URL` | — | Cognito issuer URL for JWT `iss` field validation |
| `--cognito-groups-from-claims` | `VPN_AUTH_COGNITO_GROUPS_FROM_CLAIMS` | `false` | Read group membership from ALB JWT claims instead of calling `AdminListGroupsForUser`. Use in local dev with `alb-mock`. |
| `--cognito-skip-reauth` | `VPN_AUTH_COGNITO_SKIP_REAUTH` | `false` | Skip Cognito `AdminGetUser` call on `CLIENT:REAUTH` (dev/test only) |
| `--required-group` | `VPN_AUTH_REQUIRED_GROUP` | — | Required Cognito group for VPN access |
| `--hand-window` | `VPN_AUTH_HAND_WINDOW` | `5m` | OpenVPN `hand-window` — time allowed for the full TLS handshake including auth. Must match the OpenVPN server config |
| `--auth-timeout` | `VPN_AUTH_AUTH_TIMEOUT` | `4m30s` | How long the daemon waits for the browser auth callback. Must be less than `--hand-window` so `AUTH_FAILED` reaches the client before it self-restarts |
| `--reneg-interval` | `VPN_AUTH_RENEG_INTERVAL` | `1h` | OpenVPN `reneg-sec` value. Used to compute reauth cache TTL (`reneg-interval + 10m`) |
| `--reconnect-max-interval` | `VPN_AUTH_RECONNECT_MAX_INTERVAL` | `5s` | Max backoff between management socket reconnect attempts |
| `--shutdown-grace-period` | `VPN_AUTH_SHUTDOWN_GRACE_PERIOD` | `5m` | Grace period for in-flight session draining during graceful shutdown |
| `--cn-cross-check` | `VPN_AUTH_CN_CROSS_CHECK` | `true` | Require ALB JWT email claim to match the certificate CN |
| `--check-groups-on-reauth` | `VPN_AUTH_CHECK_GROUPS_ON_REAUTH` | `false` | Check required group during `CLIENT:REAUTH` |
| `--reauth-cache` | `VPN_AUTH_REAUTH_CACHE` | `false` | Allow cached reauth decisions during IdP outage. When enabled, a successful reauth result is stored in memory keyed by username (CN for native users, Cognito lookup username for federated users). The cache entry TTL is `reneg-interval + 10m`. On the next reauth for the same user, if the Cognito call fails and a cache entry exists, the daemon allows the reauth from cache instead of denying. The cache entry is also consulted when `--reauth-timeout` elapses. Does not bypass group checks if `--check-groups-on-reauth` is set. |
| `--reauth-timeout` | `VPN_AUTH_REAUTH_TIMEOUT` | `5s` | Timeout for Cognito calls during `CLIENT:REAUTH` |
| `--max-session-duration` | `VPN_AUTH_MAX_SESSION_DURATION` | `0` | Maximum VPN session duration (`0` to disable). After this time, the client is forcibly disconnected. Typical values: `8h`, `10h`, `12h`. Must be `0` or `>= 1m`. When `reneg-sec=0`, this is the only enforcement mechanism for session limits. Enforcement uses two independent mechanisms: (1) a **hard timer** — a goroutine started at authentication sends `client-kill` when the duration elapses; (2) a **reauth backstop** — on every `CLIENT:REAUTH`, if the session has already exceeded its duration, the daemon sends `client-deny` without calling Cognito. Both paths emit the `SessionExpired` metric with a `Reason` dimension (`hard_timer` or `reauth_backstop`). |
| `--emf-metrics` | `VPN_AUTH_EMF_METRICS` | `false` | Emit CloudWatch EMF metrics to stdout |
| `--emf-interval` | `VPN_AUTH_EMF_INTERVAL` | `10s` | Interval for EMF heartbeat metrics (`0` to disable heartbeat only) |
| `--log-format` | `VPN_AUTH_LOG_FORMAT` | `text` | Log output format: `text` or `json` |
| `--templates-dir` | `VPN_AUTH_TEMPLATES_DIR` | — | Path to custom HTML templates directory. Overrides built-in templates. Must contain both `success.html` and `error.html`. |
| `--server-name` | `VPN_AUTH_SERVER_NAME` | — | Human-readable server name exposed to HTML templates via `{{ .ServerName }}` |
| `--instance-id` | `VPN_AUTH_INSTANCE_ID` | `local-dev` | Instance identifier used in EMF metrics |

See `--help` for the full list.

### HMAC Secret From AWS Secrets Manager

Store the signing key as a plain Secrets Manager `SecretString` value. The value must be at least 16 bytes:

```bash
aws secretsmanager create-secret \
  --name openvpn-auth-aws/hmac-state \
  --secret-string "$(openssl rand -base64 32)"
```

Start the daemon with the secret ID instead of `--hmac-secret`:

```bash
openvpn-auth-daemon \
  --hmac-secret-secret-id openvpn-auth-aws/hmac-state \
  --aws-region eu-west-1 \
  --callback-url https://vpn-auth.example.com/callback/01/udp \
  --cognito-user-pool-id eu-west-1_Example \
  --cognito-issuer-url https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Example
```

The same configuration can be provided via environment variables:

```bash
export VPN_AUTH_HMAC_SECRET_SECRET_ID=openvpn-auth-aws/hmac-state
export AWS_REGION=eu-west-1
```

The daemon fetches the secret once at startup. Its IAM role must allow `secretsmanager:GetSecretValue` on that secret ARN.

If neither `--hmac-secret` nor `--hmac-secret-secret-id` is set, the daemon generates a random HMAC key at startup. State signing remains enabled, but the key is process-local and in-memory only. Restarting the daemon invalidates in-flight browser auth callbacks, and multiple daemon instances cannot verify each other's state values. Use a static source in production or any deployment where callbacks can return after a restart or to a different daemon instance.

### Forward Proxy For Daemon Egress

The daemon does not have a dedicated `--proxy-url` flag. Runtime proxying uses the standard Go/AWS SDK environment variables:

```bash
HTTPS_PROXY=http://proxy.example.com:3128
HTTP_PROXY=http://proxy.example.com:3128
NO_PROXY=localhost,127.0.0.1,169.254.169.254
```

Set these in `/etc/openvpn-auth/env` when running under the provided systemd unit, because the service loads that file with `EnvironmentFile=/etc/openvpn-auth/env`:

```ini
VPN_AUTH_CALLBACK_URL=https://vpn-auth.example.com/callback/01/udp
VPN_AUTH_HMAC_SECRET_SECRET_ID=openvpn-auth-aws/hmac-state
AWS_REGION=eu-west-1

HTTPS_PROXY=http://proxy.example.com:3128
HTTP_PROXY=http://proxy.example.com:3128
NO_PROXY=localhost,127.0.0.1,169.254.169.254
```

For AWS service calls, `HTTPS_PROXY` is the critical setting because AWS endpoints use HTTPS. The proxy must allow outbound HTTPS, typically via `CONNECT`, to the endpoints the enabled features require:

| Feature | Endpoint pattern |
|---|---|
| HMAC secret from Secrets Manager | `secretsmanager.<region>.amazonaws.com` |
| Cognito reauth/group checks | `cognito-idp.<region>.amazonaws.com` |
| ALB JWT public key validation | `public-keys.auth.elb.<region>.amazonaws.com` |

Keep the EC2 Instance Metadata Service address (`169.254.169.254`) in `NO_PROXY` when using instance-role credentials. Otherwise credential lookup can fail or be sent to the proxy. Also include local addresses such as `localhost` and `127.0.0.1`; OpenVPN management uses a Unix socket, but local admin tooling and health checks should not be proxied.

Authenticated proxy URLs are supported by Go's HTTP transport:

```bash
HTTPS_PROXY=http://proxy-user:proxy-pass@proxy.example.com:3128
```

Be careful with this form in systemd environment files because the proxy password becomes readable to users who can read that file or inspect the unit environment.

External references:

- [AWS SDK for Go v2: Customize the HTTP Client](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-http.html)
- [Go `net/http`: DefaultTransport and proxy environment variables](https://pkg.go.dev/net/http#DefaultTransport)
- [AWS CLI proxy environment variable guidance](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-proxy.html)

## Lambda Router Environment Variables

The Lambda Router (used in multi-instance mode) is configured via environment variables set by Terraform:

| Variable | Required | Default | Description |
|---|---|---|---|
| `VPC_CIDR` | yes | — | CIDR VPC for IP validation (e.g. `10.0.0.0/16`) |
| `DAEMON_PORT_UDP` | no | `8080` | Daemon port for UDP listeners |
| `DAEMON_PORT_TCP` | no | `8081` | Daemon port for TCP listeners |
| `UPSTREAM_TIMEOUT` | no | `10s` | HTTP timeout to upstream daemon (`time.ParseDuration` format) |
| `OIDC_HEADERS` | no | `["x-amzn-oidc-data","x-amzn-oidc-accesstoken","x-amzn-oidc-identity"]` | JSON array of OIDC header names to forward to daemon |
| `LOG_LEVEL` | no | `info` | Log level: `debug`, `info`, `warn`, `error` |

See [Lambda Router](lambda-router-proxy.md) for architecture, security model, and troubleshooting.

## Dev vs Production Flag Matrix

| Config | Behavior |
|--------|----------|
| `--alb-arn` set | Validate ALB JWT signature + `signer` field |
| `--alb-arn` absent | Skip JWT signature validation (dev/test only) |
| `--cognito-groups-from-claims` absent | Resolve groups via `AdminListGroupsForUser` |
| `--cognito-groups-from-claims` set | Read groups directly from ALB JWT claims |
| `--cognito-skip-reauth` absent | Reauth calls Cognito `AdminGetUser` |
| `--cognito-skip-reauth` set | Skip Cognito API call on reauth (dev/test only) |

| `--cognito-user-pool-id` omitted | Use static identity checker automatically — no AWS credentials needed |

In production: set `--alb-arn` and `--cognito-user-pool-id`, leave both `--cognito-*` flags unset.
In local dev: omit `--alb-arn` and `--cognito-user-pool-id`, set `--cognito-groups-from-claims` and `--cognito-skip-reauth`.

**Startup validation:** The daemon will refuse to start if `--alb-arn` is set without `--cognito-user-pool-id` or `--cognito-issuer-url` (production misconfiguration), if `--required-group` is set without `--cognito-user-pool-id` and `--cognito-groups-from-claims` (group enforcement without a backend to check against), if `--hmac-secret` is provided but shorter than 16 bytes, or if both `--hmac-secret` and `--hmac-secret-secret-id` are set.

## Logging

The daemon uses structured logging via Go's `log/slog`. Output format is controlled by `--log-format`:

- **`text`** (default) — human-readable, good for terminal and docker-compose:
  ```
  time=2026-03-13T12:00:00Z level=INFO msg=connect cid=3 kid=1 cn=john@example.com
  ```

- **`json`** — machine-parseable, good for CloudWatch Logs Insights:
  ```json
  {"time":"2026-03-13T12:00:00Z","level":"INFO","msg":"connect","cid":"3","kid":"1","cn":"john@example.com"}
  ```

### Callback log levels

The callback endpoint (`GET /callback`) is reachable through the ALB, so it receives invalid requests from browser retries, expired bookmarks, and scanners. Log levels are tuned to avoid noise while keeping operationally important events visible.

| Log message | Level | Reason |
| --- | --- | --- |
| `callback: invalid state` | INFO | Normal rejection — expired state, browser retry, scanner. High volume expected. |
| `callback: session not found` | INFO | Session already reaped (TTL expired). Diagnostic, not alarming. |
| `callback: session not pending` | INFO | Replay of an already-processed callback. |
| `callback: missing x-amzn-oidc-data header` | WARN | Request bypassed ALB or ALB misconfigured — should not happen in production. |
| `callback: failed to parse JWT header` | WARN | Malformed token, possible tampering. |
| `callback: failed to fetch ALB public key` | ERROR | AWS infrastructure issue, retryable. Requires attention. |
| `callback: ALB JWT validation failed` | WARN | Forged, expired, or wrong-ALB token. |
| `callback: failed to parse JWT claims` | WARN | Malformed claims (dev mode only). |
| `callback: CN cross-check failed` | WARN | Certificate CN does not match authenticated identity. |
| `callback: group check error` | ERROR | Cognito API failure during group lookup. |
| `callback: user not in required group` | WARN | Authenticated user lacks required group — may indicate revoked access. |
| `callback: auth success` | INFO | Successful authentication. |

**Design principle:** INFO for expected rejections from external input, WARN for events that indicate misconfiguration or unauthorized access, ERROR for infrastructure failures that need operator attention. Observability for all rejection paths is covered by the `CallbackRejected` metric (see below) — logs don't need to carry the full alerting burden.

## EMF Metrics

CloudWatch Embedded Metric Format (EMF) output is disabled by default (`--emf-metrics=false`). When enabled, the daemon emits JSON metrics to stdout that CloudWatch Logs agent can parse into CloudWatch Metrics automatically.

- `--emf-metrics=true` — enables EMF counter metrics (see table below)
- `--emf-interval` — controls heartbeat metric interval (SocketConnected, StoredSessions). Set to `0` to disable heartbeat while keeping counter metrics.

### Available metrics

All metrics are emitted under the `VPNAuth` namespace with `InstanceId` as the primary dimension. Metrics with a `Reason` column also emit a second dimension set `[InstanceId, Reason]` for filtering.

| Metric | Type | Reason dimension | Description |
| --- | --- | --- | --- |
| `SocketConnected` | gauge | — | Management socket connectivity (0/1), emitted on heartbeat interval |
| `StoredSessions` | gauge | — | Number of in-memory sessions, emitted on heartbeat interval |
| `AuthAttempt` | counter | — | `CLIENT:CONNECT` received and session created |
| `AuthSuccess` | counter | — | Callback verification passed, `client-auth` sent |
| `AuthDenied` | counter | `timeout`, `no_webauth`, `missing_common_name`, `url_too_long`, `internal_error` | Auth denied via `client-deny` (handler-level rejections) |
| `CallbackRejected` | counter | see below | HTTP callback rejected (all error paths in `handleCallback`) |
| `ReauthSuccess` | counter | — | `CLIENT:REAUTH` allowed |
| `ReauthDenied` | counter | `missing_common_name`, `user_not_found`, `user_disabled`, `group_denied`, `cognito_error`, `session_untracked` | Reauth denied |
| `ReauthCacheHit` | counter | — | Reauth allowed from cache (Cognito unavailable) |
| `CallbackReceived` | counter | — | Any callback request received (before validation) |
| `TokenExchangeError` | counter | *(reason)* | Token exchange or identity provider error (defined but not yet emitted) |
| `SessionExpired` | counter | `hard_timer`, `reauth_backstop` | Session forcibly terminated after exceeding `--max-session-duration`. `hard_timer` = expiry goroutine sent `client-kill`; `reauth_backstop` = expired session detected during `CLIENT:REAUTH` |

### CallbackRejected reasons

`CallbackRejected` tracks every rejection path in the callback handler. The reason is a stable, low-cardinality string — never a dynamic error message.

| Reason | HTTP status | Description |
| --- | --- | --- |
| `missing_state` | 400 | No `state` query parameter |
| `invalid_state` | 400 | State HMAC verification failed or expired |
| `session_not_found` | 404 | Session ID from state not in store (expired/reaped) |
| `session_not_pending` | 409 | Session already processed (replay) |
| `missing_oidc_header` | 403 | `x-amzn-oidc-data` header absent |
| `invalid_jwt_header` | 403 | JWT header segment malformed |
| `public_key_fetch_failed` | 503 | Could not fetch ALB public key (retryable) |
| `jwt_validation_failed` | 403 | ES256 signature, signer ARN, or expiry check failed |
| `invalid_jwt_claims` | 403 | JWT claims parse error (dev mode) |
| `cn_mismatch` | 403 | JWT email does not match certificate CN |
| `group_check_error` | 403 | Cognito API error during group lookup |
| `group_denied` | 403 | User not in required group |

For production with CloudWatch agent, enable with:

```bash
--emf-metrics=true --emf-interval=10s --log-format=json
```

## HTML Templates

The callback server renders styled HTML pages for authentication success and error responses. Templates are embedded in the binary at build time — no external files needed.

### Built-in Templates

Two templates are compiled into the binary via `//go:embed`:

- `success.html` — shown after successful authentication (displays email, "You can close this window")
- `error.html` — shown for all error cases (session expired, access denied, certificate mismatch, etc.)

Both include inline CSS with dark mode support, responsive layout, and zero JavaScript.

### Custom Templates

To override the built-in templates, use `--templates-dir`:

```bash
openvpn-auth-daemon --templates-dir /etc/openvpn-auth/templates/
```

Requirements:
- The directory must contain both `success.html` and `error.html` (all-or-nothing override)
- Templates are parsed with Go's `html/template` package

The daemon validates templates at startup and refuses to start if any are missing or contain syntax errors.

### Template Variables

**`success.html`:**

| Variable | Type | Description |
|----------|------|-------------|
| `{{ .Email }}` | string | Authenticated user's email address |
| `{{ .SessionID }}` | string | Internal session ID (useful for support/debugging) |
| `{{ .Hostname }}` | string | OS hostname of the daemon server (`os.Hostname()`) |
| `{{ .ServerName }}` | string | Human-readable name set via `--server-name` (empty if not configured) |

**`error.html`:**

| Variable | Type | Description |
|----------|------|-------------|
| `{{ .Title }}` | string | Error title (e.g. "Access Denied", "Session Expired") |
| `{{ .Message }}` | string | Human-readable error description |
| `{{ .StatusCode }}` | int | HTTP status code (e.g. 400, 403, 404, 503) |
| `{{ .SessionID }}` | string | Internal session ID, empty if not yet resolved |
| `{{ .Hostname }}` | string | OS hostname of the daemon server (`os.Hostname()`) |
| `{{ .ServerName }}` | string | Human-readable name set via `--server-name` (empty if not configured) |

In Docker:

```yaml
volumes:
  - ./my-templates:/etc/openvpn-auth/templates:ro
```
