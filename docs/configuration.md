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
| `--hmac-secret` | `VPN_AUTH_HMAC_SECRET` | — | HMAC secret for signing state blobs |
| `--aws-region` | `AWS_REGION` | `eu-west-1` | AWS region |
| `--cognito-user-pool-id` | `VPN_AUTH_COGNITO_USER_POOL_ID` | — | Cognito User Pool ID |
| `--cognito-issuer-url` | `VPN_AUTH_COGNITO_ISSUER_URL` | — | Cognito issuer URL for JWT `iss` field validation |
| `--cognito-groups-from-claims` | `VPN_AUTH_COGNITO_GROUPS_FROM_CLAIMS` | `false` | Read group membership from ALB JWT claims instead of calling `AdminListGroupsForUser`. Use in local dev with `alb-mock`. |
| `--cognito-skip-reauth` | `VPN_AUTH_COGNITO_SKIP_REAUTH` | `false` | Skip Cognito `AdminGetUser` call on `CLIENT:REAUTH` (dev/test only) |
| `--required-group` | `VPN_AUTH_REQUIRED_GROUP` | — | Required Cognito group for VPN access |
| `--hand-window` | `VPN_AUTH_HAND_WINDOW` | `5m` | OpenVPN `hand-window` — time allowed for the full TLS handshake including auth. Must match the OpenVPN server config |
| `--auth-timeout` | `VPN_AUTH_AUTH_TIMEOUT` | `4m30s` | How long the daemon waits for the browser auth callback. Must be less than `--hand-window` so `AUTH_FAILED` reaches the client before it self-restarts |
| `--cn-cross-check` | `VPN_AUTH_CN_CROSS_CHECK` | `true` | Require ALB JWT email claim to match the certificate CN |
| `--check-groups-on-reauth` | `VPN_AUTH_CHECK_GROUPS_ON_REAUTH` | `false` | Check required group during `CLIENT:REAUTH` |
| `--reauth-cache` | `VPN_AUTH_REAUTH_CACHE` | `false` | Allow cached reauth decisions during IdP outage |
| `--reauth-timeout` | `VPN_AUTH_REAUTH_TIMEOUT` | `5s` | Timeout for Cognito calls during `CLIENT:REAUTH` |
| `--single-session-per-user` | `VPN_AUTH_SINGLE_SESSION_PER_USER` | `true` | Enforce one active VPN session per certificate CN |
| `--emf-metrics` | `VPN_AUTH_EMF_METRICS` | `false` | Emit CloudWatch EMF metrics to stdout |
| `--emf-interval` | `VPN_AUTH_EMF_INTERVAL` | `10s` | Interval for EMF heartbeat metrics (`0` to disable heartbeat only) |
| `--log-format` | `VPN_AUTH_LOG_FORMAT` | `text` | Log output format: `text` or `json` |
| `--instance-id` | `VPN_AUTH_INSTANCE_ID` | `local-dev` | Instance identifier used in EMF metrics |

See `--help` for the full list.

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

**Startup validation:** The daemon will refuse to start if `--alb-arn` is set without `--cognito-user-pool-id` (production misconfiguration), or if `--required-group` is set without `--cognito-user-pool-id` and `--cognito-groups-from-claims` (group enforcement without a backend to check against).

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

## EMF Metrics

CloudWatch Embedded Metric Format (EMF) output is disabled by default (`--emf-metrics=false`). When enabled, the daemon emits JSON metrics to stdout that CloudWatch Logs agent can parse into CloudWatch Metrics automatically.

- `--emf-metrics=true` — enables EMF counter metrics (AuthAttempt, AuthSuccess, AuthDenied, etc.)
- `--emf-interval` — controls heartbeat metric interval (SocketConnected, StoredSessions). Set to `0` to disable heartbeat while keeping counter metrics.

For production with CloudWatch agent, enable with:

```bash
--emf-metrics=true --emf-interval=10s --log-format=json
```
