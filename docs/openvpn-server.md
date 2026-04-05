# OpenVPN Server Configuration

## Tested Version

This project is tested with **OpenVPN CE 2.6.19** (installed from the [official OpenVPN repository](https://build.openvpn.net/debian/openvpn/release/2.6)). The version is pinned and configurable:

| Environment | How to change | Default |
|-------------|---------------|---------|
| Docker lab | `OPENVPN_VERSION` build arg in `lab/Dockerfile.openvpn` | `2.6.19` |
| Terraform | `openvpn_version` variable in `terraform/variables.tf` | `"2.6.19"` |

**Minimum required:** OpenVPN 2.6+ — earlier versions do not support the `IV_SSO webauth` mechanism used for browser-based authentication.

## Required Directives

The server config must include these directives for the auth daemon to work:

```text
management /run/openvpn/management.sock unix /path/to/management-pw
management-client-auth
management-hold
auth-user-pass-optional
setenv IV_SSO webauth
hand-window 300
```

| Directive | Purpose |
|-----------|---------|
| `management` | Enables the management interface on a Unix socket with password auth |
| `management-client-auth` | Delegates client authentication to the management interface (daemon) |
| `management-hold` | Holds OpenVPN startup until daemon sends `hold release` |
| `auth-user-pass-optional` | Allows connection without username/password — identity comes from TLS certificate CN |
| `setenv IV_SSO webauth` | Announces WebAuth support to clients via `IV_SSO` environment variable |
| `hand-window` | Time (seconds) allowed for the full TLS handshake including browser-based auth. Must match `--hand-window` on the daemon. Default is 60s which is too short for browser auth — set to 300s or more |

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

### Interaction with `--max-session-duration`

When `--max-session-duration` is set, the daemon enforces a hard time limit on established sessions via two mechanisms:

1. **Hard timer** — after `client-auth` succeeds, the daemon starts a timer that sends `client-kill` after the configured duration, regardless of `reneg-sec`.
2. **Reauth backstop** — on each `CLIENT:REAUTH`, the daemon checks whether the session has exceeded `max-session-duration` and sends `client-deny` with reason `"session expired"` if so.

If `reneg-sec=0` (renegotiation disabled), no `CLIENT:REAUTH` events are sent, so the hard timer is the **only** enforcement mechanism. When `reneg-sec > 0`, both mechanisms are active — whichever fires first terminates the session.

On management reconnect (daemon restart, socket drop, or OpenVPN restart), the daemon queries `status 3` and rebuilds expiry tracking from the live OpenVPN state. If a session has already exceeded its limit, it is killed immediately. If OpenVPN restarted (empty `status 3`), all timers are cleaned up and clients must reconnect. See [Architecture — Management Socket Reconnect](architecture.md#management-socket-reconnect-and-session-tracking) for the full scenario matrix.

## NAT Masquerade (nftables)

The EC2 instance is configured at boot (via cloud-init) to NAT VPN client traffic using nftables. This allows VPN clients to reach resources in the VPC or the internet through the server's primary network interface.

**What cloud-init does:**

1. Enables IP forwarding via sysctl (`net.ipv4.ip_forward = 1`).
2. Creates an nftables NAT table with a `postrouting` masquerade rule for both the UDP and TCP VPN client CIDRs:
   ```
   table ip nat {
     chain postrouting {
       type nat hook postrouting priority 100;
       ip saddr <udp_client_cidr> oifname <primary_iface> masquerade
       ip saddr <tcp_client_cidr> oifname <primary_iface> masquerade
     }
   }
   ```
3. Saves the ruleset to `/etc/nftables.conf` and enables the `nftables` systemd service so rules are restored on reboot.

The primary interface is detected dynamically at boot from the default route (`ip route show default`), so the config works regardless of whether the NIC is named `eth0`, `ens5`, etc.

> **Note:** nftables is used in preference to iptables. Ubuntu 24.04 (Noble) ships with nftables as the native firewall framework; iptables on that platform is a compatibility shim over the nftables backend anyway.

## Pushed Routes

> **Note:** Only split-tunnel mode is supported by the current Terraform code. Full-tunnel (`push "redirect-gateway def1"`) is not wired up — to redirect all client traffic through the VPN you would need to extend the cloud-config template manually.

VPN clients receive no routes by default (split-tunnel). To push routes, set the `pushed_routes` Terraform variable — a list of CIDRs that are injected as `push "route ..."` directives into both the UDP and TCP OpenVPN server configs at plan time.

```hcl
pushed_routes = ["10.0.0.0/16", "10.1.0.0/24"]
```

This generates, for each listener:

```text
push "route 10.0.0.0 255.255.0.0"
push "route 10.1.0.0 255.255.255.0"
```

> **Note:** Pushing routes does not automatically open EC2 security group rules for that traffic — the two are configured independently (see below).

## EC2 Security Group Rules for Forwarded Traffic

The EC2 instance has a catch-all egress rule (`0.0.0.0/0`) for internet-bound traffic (AWS API calls, apt, etc.). For forwarded VPN client traffic, use the `ec2_sg_rules` variable to add **explicit, protocol-scoped** ingress and/or egress rules. This is intentionally separate from `pushed_routes` — you can push a broad route to clients while restricting what the EC2 instance is actually permitted to forward.

```hcl
ec2_sg_rules = {
  ingress = [
    {
      description = "ICMP from VPC"
      cidr_ipv4   = "10.0.0.0/16"
      ip_protocol = "icmp"
      from_port   = -1
      to_port     = -1
    },
  ]
  egress = [
    {
      description = "HTTPS to VPC"
      cidr_ipv4   = "10.0.0.0/16"
      ip_protocol = "tcp"
      from_port   = 443
      to_port     = 443
    },
    {
      description = "SSH to VPC"
      cidr_ipv4   = "10.0.0.0/16"
      ip_protocol = "tcp"
      from_port   = 22
      to_port     = 22
    },
    {
      description = "ICMP to VPC"
      cidr_ipv4   = "10.0.0.0/16"
      ip_protocol = "icmp"
      from_port   = -1
      to_port     = -1
    },
  ]
}
```

`ingress` is optional and defaults to `[]`. `egress` defaults to a single catch-all rule (`0.0.0.0/0`, all protocols) required for internet-bound traffic (AWS API calls, apt, etc.) — override it if you want stricter outbound control.

To allow all protocols to a CIDR (e.g. a fully-trusted private network), set `ip_protocol = "-1"` and omit `from_port`/`to_port`:

```hcl
ec2_sg_rules = {
  egress = [
    {
      description = "All outbound"
      cidr_ipv4   = "0.0.0.0/0"
      ip_protocol = "-1"
    },
    {
      description = "All traffic to trusted private subnet"
      cidr_ipv4   = "10.0.0.0/16"
      ip_protocol = "-1"
    },
  ]
}
```

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
push-peer-info
setenv IV_SSO webauth

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
- **OpenVPN 2.x CLI** is recommended to include `push-peer-info` and `setenv IV_SSO webauth` so the client sends WebAuth support metadata to the server consistently in the tested CLI flow
- Client must support WebAuth (OpenVPN 2.6+ with `IV_SSO` or `IV_PROTO` flags)
- **`push-peer-info`** causes the client to send additional environment variables to the server on connect. The daemon logs the following fields on every `connect` event:

  | Log field | Source variable | Always sent | Requires `push-peer-info` |
  |-----------|----------------|:-----------:|:-------------------------:|
  | `ip` | `untrusted_ip` | ✅ | — |
  | `port` | `untrusted_port` | ✅ | — |
  | `plat` | `IV_PLAT` | ✅ | — |
  | `ver` | `IV_VER` | ✅ | — |
  | `gui_ver` | `IV_GUI_VER` / `IV_UI_VER` | ✅¹ | — |
  | `hwaddr` | `IV_HWADDR` | — | ✅ |
  | `plat_ver` | `IV_PLAT_VER` | — | ✅ |
  | `ssl` | `IV_SSL` | — | ✅ |

  ¹ `IV_GUI_VER` is set by the client UI via `--setenv`; always present in OpenVPN GUI and OpenVPN3/Linux.

  **OpenVPN3/Linux limitations:** OpenVPN3 core library (used by `openvpn3-linux` and OpenVPN Connect) does **not** send `IV_HWADDR`, `IV_PLAT_VER`, or `IV_SSL` — even with `push-peer-info` enabled. These fields will always be empty for OpenVPN3 clients. This is a known limitation of the OpenVPN3 core library, not a configuration issue. Full peer info is only available from OpenVPN 2.x clients (e.g. OpenVPN GUI on Windows, Tunnelblick on macOS).

  Example log — **OpenVPN 2.7.1 / Windows GUI** (full peer info):
  ```
  msg=connect cid=0 kid=1 cn=user@example.com ip=203.0.113.42 port=57050 hwaddr=ac:74:b1:49:9b:75 plat=win plat_ver=10.0.26200,amd64 ver=2.7.1 gui_ver=OpenVPN_GUI_11.62.0.0 ssl=OpenSSL_3.6.1_27_Jan_2026
  ```

  Example log — **OpenVPN3 3.11.6 / Linux** (limited peer info):
  ```
  msg=connect cid=2 kid=1 cn=user@example.com ip=203.0.113.42 port=55288 hwaddr="" plat=linux plat_ver="" ver=3.11.6 gui_ver=OpenVPN3/Linux/v27 ssl=""
  ```

## OpenVPN3 Linux CLI

OpenVPN3 Linux (`openvpn3-linux`) works with this project out of the box. Run without `sudo` — OpenVPN3 uses D-Bus and separates privileges internally.

```bash
# Connect
openvpn3 session-start --config client.ovpn

# List active sessions
openvpn3 sessions-list

# View logs (attach to running session)
openvpn3 log --config client.ovpn

# View logs with debug verbosity
openvpn3 log --config client.ovpn --log-level 6

# Disconnect
openvpn3 session-manage --config client.ovpn --disconnect
```

> **Note:** After `session-start`, the browser opens for OIDC authentication and may print a message (e.g. `Opening in existing browser session.`) to the terminal. The shell prompt is already available — press Enter if it appears stuck.

## Management Interface Protocol

The daemon communicates with OpenVPN via the management interface using these commands:

| Command | When | Purpose |
|---------|------|---------|
| `hold release` | On connect / `>HOLD:` | Release OpenVPN from management hold |
| `client-pending-auth CID KID "WEB_AUTH::URL" TIMEOUT` | `>CLIENT:CONNECT` | Send WebAuth URL to client |
| `client-auth CID KID` + `END` | Callback success | Allow client connection |
| `client-auth-nt CID KID` | `>CLIENT:REAUTH` success | Allow renegotiation (no tunnel changes) |
| `client-deny CID KID "reason"` | Auth failure | Deny client with reason |
| `client-kill CID [HALT]` | Session eviction | Kill established connection; `HALT` stops the client without auto-reconnect |
