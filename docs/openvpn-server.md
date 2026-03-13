# OpenVPN Server Configuration

## Required Directives

The server config must include these directives for the auth daemon to work:

```text
management /run/openvpn/management.sock unix /path/to/management-pw
management-client-auth
management-hold
auth-user-pass-optional
setenv IV_SSO webauth
```

| Directive | Purpose |
|-----------|---------|
| `management` | Enables the management interface on a Unix socket with password auth |
| `management-client-auth` | Delegates client authentication to the management interface (daemon) |
| `management-hold` | Holds OpenVPN startup until daemon sends `hold release` |
| `auth-user-pass-optional` | Allows connection without username/password — identity comes from TLS certificate CN |
| `setenv IV_SSO webauth` | Announces WebAuth support to clients via `IV_SSO` environment variable |

## Recommended Settings

### Verbosity

Set `verb 3` (or higher) to see client connect/disconnect events in OpenVPN logs:

```text
verb 3
```

With `verb 2`, disconnect events are **not logged** by OpenVPN, though the daemon still receives them via the management interface. This can make debugging difficult.

### Keepalive and Disconnect Detection

```text
keepalive 10 120
```

This sets `ping 10` and `ping-restart 120`:
- Server pings client every 10 seconds
- Server considers client dead after 120 seconds of silence

With UDP, there is no connection teardown like TCP. Client disconnects are detected in two ways:

1. **Clean shutdown** — client sends an explicit exit notification (`cc-exit` protocol flag). Disconnect is immediate.
2. **Force kill** (e.g. double Ctrl+C, network drop, crash) — client disappears without notification. Server waits for `ping-restart` timeout (120s with the above config) before sending `>CLIENT:DISCONNECT` to the daemon.

The daemon logs disconnect events as they arrive:
```
time=2026-03-13T12:05:00Z level=INFO msg=disconnect cid=3
```

If you don't see a disconnect log after a client disappears, wait for the `ping-restart` timeout.

### Renegotiation and Reauth

```text
reneg-sec 3600
```

Controls how often OpenVPN renegotiates the TLS session. Each renegotiation triggers `>CLIENT:REAUTH` on the management interface. The daemon handles this by checking the user's identity in Cognito — **no browser interaction required**.

The reauth flow:

1. OpenVPN triggers TLS renegotiation after `reneg-sec` seconds
2. Sends `>CLIENT:REAUTH,CID,KID` to management interface
3. Daemon calls Cognito `AdminGetUser` to verify user still exists, is enabled, and (optionally) is in the required group
4. Sends `client-auth-nt` (continue tunnel) or `client-deny` (disconnect user)

This means:
- **User disabled in Cognito** — disconnected at next renegotiation (within `reneg-sec`)
- **User removed from required group** — disconnected if `--check-groups-on-reauth=true`
- **Cognito unavailable** — denied by default, or allowed from cache if `--reauth-cache=true`

Daemon logs for reauth:

```
time=...Z level=INFO msg=reauth cid=0 cn=john@example.com
time=...Z level=INFO msg="reauth allowed" cid=0 cn=john@example.com
```

The lab setup uses `reneg-sec 600` (10 minutes) for faster testing. For production, `reneg-sec 3600` (1 hour) is typical.

The daemon's `--reneg-interval` should match this value (used for reauth cache TTL calculation).

## Client Config

Minimal client config for WebAuth:

```text
client
dev tun
proto udp
remote <server-ip> 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3

<ca>
... CA certificate ...
</ca>

<cert>
... client certificate (CN = user email) ...
</cert>

<key>
... client private key ...
</key>
```

Notes:
- **No `auth-user-pass`** — authentication happens via browser (OIDC), not username/password
- **Certificate CN** should match the user's email in Cognito (used for CN cross-check when `--cn-cross-check=true`)
- Client must support WebAuth (OpenVPN 2.6+ with `IV_SSO` or `IV_PROTO` flags)

## Management Interface Protocol

The daemon communicates with OpenVPN via the management interface using these commands:

| Command | When | Purpose |
|---------|------|---------|
| `hold release` | On connect / `>HOLD:` | Release OpenVPN from management hold |
| `client-pending-auth CID KID "WEB_AUTH::URL" TIMEOUT` | `>CLIENT:CONNECT` | Send WebAuth URL to client |
| `client-auth CID KID` + `END` | Callback success | Allow client connection |
| `client-auth-nt CID KID` | `>CLIENT:REAUTH` success | Allow renegotiation (no tunnel changes) |
| `client-deny CID KID "reason"` | Auth failure | Deny client with reason |
| `client-kill CID` | Session eviction | Kill established connection |
