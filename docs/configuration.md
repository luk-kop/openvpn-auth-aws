# Configuration

All flags can be set via environment variables with `VPN_AUTH_` prefix.

## Daemon Flags

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--management-socket` | `VPN_AUTH_MANAGEMENT_SOCKET` | `/run/openvpn/management.sock` | Path to OpenVPN management socket |
| `--management-password-file` | `VPN_AUTH_MANAGEMENT_PASSWORD_FILE` | `/etc/openvpn/management-pw` | File containing management password |
| `--api-gateway-url` | `VPN_AUTH_API_GATEWAY_URL` | — | Public API Gateway base URL (no trailing slash) |
| `--callback-port` | `VPN_AUTH_CALLBACK_PORT` | `8080` | Port the daemon listens on for Lambda POST /callback |
| `--instance-ip` | `VPN_AUTH_INSTANCE_IP` | — | Private IP embedded in the signed state blob so Lambda can reach this instance. Auto-detected from EC2 IMDS if empty; must be set explicitly in local/Docker environments |
| `--hmac-secret` | `VPN_AUTH_HMAC_SECRET` | — | HMAC secret for signing state values (local dev) |
| `--hmac-secret-arn` | `VPN_AUTH_HMAC_SECRET_ARN` | — | Secrets Manager ARN for HMAC secret (production) |
| `--aws-region` | `AWS_REGION` | `eu-west-1` | AWS region |
| `--cognito-user-pool-id` | `VPN_AUTH_COGNITO_USER_POOL_ID` | — | Cognito User Pool ID |
| `--cognito-client-id` | `VPN_AUTH_COGNITO_CLIENT_ID` | — | Cognito app client ID |
| `--cognito-redirect-uri` | `VPN_AUTH_COGNITO_REDIRECT_URI` | — | OAuth2 redirect URI registered in Cognito |
| `--required-group` | `VPN_AUTH_REQUIRED_GROUP` | — | Required Cognito group for VPN access |
| `--use-local-mocks` | `VPN_AUTH_USE_LOCAL_MOCKS` | `false` | In-memory store + static identity (no AWS) |
| `--hand-window` | `VPN_AUTH_HAND_WINDOW` | `5m` | OpenVPN hand-window — must be ≥ `--auth-timeout` |
| `--auth-timeout` | `VPN_AUTH_AUTH_TIMEOUT` | `5m` | How long the daemon waits for the browser auth callback |
| `--cn-cross-check` | `VPN_AUTH_CN_CROSS_CHECK` | `true` | Require token email claim to match the certificate CN |
| `--check-groups-on-reauth` | `VPN_AUTH_CHECK_GROUPS_ON_REAUTH` | `false` | Check required group during `CLIENT:REAUTH` |
| `--reauth-cache` | `VPN_AUTH_REAUTH_CACHE` | `false` | Allow cached reauth decisions during IdP outage |
| `--reauth-timeout` | `VPN_AUTH_REAUTH_TIMEOUT` | `5s` | Timeout for Cognito calls during `CLIENT:REAUTH` |
| `--single-session-per-user` | `VPN_AUTH_SINGLE_SESSION_PER_USER` | `true` | Enforce one active VPN session per certificate CN |
| `--emf-metrics` | `VPN_AUTH_EMF_METRICS` | `false` | Emit CloudWatch EMF metrics to stdout |
| `--emf-interval` | `VPN_AUTH_EMF_INTERVAL` | `10s` | Interval for EMF heartbeat metrics (`0` to disable heartbeat only) |
| `--log-format` | `VPN_AUTH_LOG_FORMAT` | `text` | Log output format: `text` or `json` |
| `--instance-id` | `VPN_AUTH_INSTANCE_ID` | `local-dev` | Instance identifier used in EMF metrics |

See `--help` for the full list.

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
- `--emf-interval` — controls heartbeat metric interval (SocketConnected, InFlightSessions). Set to `0` to disable heartbeat while keeping counter metrics.

For production with CloudWatch agent, enable with:

```bash
--emf-metrics=true --emf-interval=10s --log-format=json
```
