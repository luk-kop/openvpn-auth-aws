# Troubleshooting

## Useful Commands

### Cloud-init

```bash
# Watch cloud-init progress in real time
tail -f /var/log/cloud-init-output.log

# Check cloud-init status
cloud-init status --wait

# View cloud-init errors only
grep -i -E 'error|warning|failed' /var/log/cloud-init-output.log
```

### OpenVPN

```bash
# Check OpenVPN server status
systemctl status openvpn-server@udp openvpn-server@tcp

# View OpenVPN logs (syslog/journal)
journalctl -u openvpn-server@udp -f
journalctl -u openvpn-server@tcp -f

# View both OpenVPN and auth daemon logs together
journalctl -u openvpn-server@udp -u openvpn-auth-udp -f

# Check OpenVPN configs
cat /etc/openvpn/server/udp.conf
cat /etc/openvpn/server/tcp.conf

# Verify PKI files are present
ls -la /etc/openvpn/server/
```

### Auth Daemon

```bash
# Check daemon status
systemctl status openvpn-auth-udp openvpn-auth-tcp

# View daemon logs
journalctl -u openvpn-auth-udp -f
journalctl -u openvpn-auth-tcp -f

# Check EIP association status
systemctl status eip-associate
journalctl -u eip-associate --no-pager
```

### AWS CLI

```bash
# Verify AWS CLI is installed
which aws && aws --version

# Test instance role credentials
aws sts get-caller-identity

# Test Secrets Manager access
aws secretsmanager get-secret-value --secret-id openvpn-auth-aws/pki/ca-cert --query SecretString --output text | head -3
```

### ALB & Target Groups

```bash
# Check target group health (UDP daemon)
aws elbv2 describe-target-health \
  --target-group-arn <tg-arn> --output table

# Check daemon is listening and healthy
ss -tlnp | grep 8080
curl -s http://localhost:8080/healthz
```

### PKI / Certificates

```bash
# Verify server PKI on EC2
openssl x509 -in /etc/openvpn/server/ca.crt -noout -subject -issuer
openssl x509 -in /etc/openvpn/server/server.crt -noout -subject -issuer

# Verify client cert CN (from .ovpn file)
sed -n '/<cert>/,/<\/cert>/p' client.ovpn | grep -v '<' | openssl x509 -noout -subject

# Verify CA in Secrets Manager matches local PKI
aws secretsmanager get-secret-value \
  --secret-id openvpn-auth-aws/pki/ca-cert \
  --query SecretString --output text | openssl x509 -noout -subject
```

### Debugging Auth Flow

```bash
# Filter daemon logs for auth errors
journalctl -u openvpn-auth-udp --no-pager | grep -i "failed\|error\|mismatch\|denied"

# Check CN cross-check failures
journalctl -u openvpn-auth-udp --no-pager | grep -i "cross-check"

# Check JWT validation issues
journalctl -u openvpn-auth-udp --no-pager | grep -i "jwt"
```

### SSM Session Manager

```bash
# Connect from your local machine (instance ID from terraform output)
aws ssm start-session --target <instance-id> --region <region>
```

## Known Issues

### `aws: command not found`

Ubuntu 24.04 does not include `awscli` in the default apt repositories. The cloud-init config installs AWS CLI v2 from the official zip archive in `runcmd`. If this step fails (e.g. no internet access), all subsequent AWS API calls (`fetch-pki.sh`, `aws s3 cp`) will fail.

**Fix:** Ensure the instance has outbound internet access at boot. Set `ec2_associate_public_ip = true` (default) or configure VPC Endpoints.

### OpenVPN stuck in `activating (start)` with `management-hold`

OpenVPN is configured with `management-hold`, which pauses startup until the auth daemon connects to the management socket and sends a `hold release` command. This creates a startup ordering challenge:

1. OpenVPN starts and waits for hold release (`activating` state, never reaches `active`)
2. If the auth daemon has a hard systemd dependency (`Requires=openvpn-server@...`), systemd won't start the daemon until OpenVPN is `active`
3. Deadlock: OpenVPN waits for daemon, daemon waits for OpenVPN

**Solution:** The auth daemon services intentionally have **no systemd dependency** on OpenVPN. The daemon has built-in retry logic with exponential backoff (`mgmt.Dial()` in `internal/mgmt/client.go`) — it will keep trying to connect to the management socket until it becomes available. This allows both services to start independently:

- OpenVPN starts → listens on management socket → waits for hold release
- Auth daemon starts → connects to management socket (retrying if not ready yet) → sends hold release
- OpenVPN continues initialization → accepts VPN clients

A systemd drop-in override also changes the OpenVPN unit to `Type=simple` so systemd considers it "started" immediately (the default `Type=notify` would block because OpenVPN doesn't send `READY=1` until after hold release).

All services are started with `systemctl start --no-block` in cloud-init. Without `--no-block`, the `systemctl start` command would block cloud-init until OpenVPN reaches `active` state — which never happens because OpenVPN is waiting for the auth daemon to send `hold release`.

**Diagnose:**
```bash
# Check if OpenVPN is stuck waiting for hold release
journalctl -u openvpn-server@udp --no-pager | tail -20
# Expected: "Need hold release from management interface, waiting..."

# Check if daemon is running and connected
systemctl status openvpn-auth-udp
journalctl -u openvpn-auth-udp --no-pager | tail -20
```

### SSM Agent `unable to acquire credentials`

The EC2 instance launches without a public IP (the EIP is assigned after ALB health checks pass). Without outbound internet access, SSM Agent cannot register with the SSM service.

**Fix:** Set `ec2_associate_public_ip = true` (default). This assigns a temporary public IP at launch; the EIP replaces it once health checks pass. See `terraform/README.md` for alternative options (VPC Endpoints).

### Cloud-init does not pick up new user_data

EC2 instances only run cloud-init on first boot. Changing `user_data_base64` in Terraform requires replacing the instance (`user_data_replace_on_change = true` is set). If `terraform plan` shows an in-place update instead of replacement, the instance will not run the new cloud-init config.

**Fix:** Ensure `terraform plan` shows `# forces replacement`. If not, taint the instance:
```bash
terraform taint 'module.vpn_server[0].aws_instance.openvpn'
terraform apply
```

### Daemon crashes with `invalid value "300" for flag -hand-window: parse error`

The `--hand-window` flag expects a Go `time.Duration` string (e.g. `300s`, `5m`), not a plain integer. If the Terraform `hand_window` variable (integer seconds) is passed without a unit suffix, the daemon fails to parse it and exits immediately.

**Diagnose:**
```bash
journalctl -u openvpn-auth-udp --no-pager | grep "parse error"
```

**Fix:** The cloud-config template appends `s` to the value (`--hand-window=${hand_window}s`). If you see this error, the template is missing the suffix — check `cloud-config.yml.tftpl` for the daemon `ExecStart` lines. Note: OpenVPN's `hand-window` directive uses bare seconds and does NOT need the suffix.

### Callback returns 500 after Cognito login

After successful Cognito login, the browser gets a 500 error on `/oauth2/idpresponse`. Daemon logs show no incoming callback request.

The ALB `authenticate-cognito` action needs outbound HTTPS (port 443) to call Cognito's token endpoint and exchange the authorization code for tokens. If the ALB security group only allows egress to daemon ports (8080/8081), the token exchange fails and ALB returns 500.

**Diagnose:** Check ALB security group egress rules — there must be a rule allowing TCP 443 outbound (to `0.0.0.0/0` or Cognito IP ranges).

**Fix:** Add an egress rule to the ALB security group:
```hcl
resource "aws_vpc_security_group_egress_rule" "alb_to_cognito" {
  security_group_id = aws_security_group.alb.id
  description       = "ALB to Cognito token endpoint"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}
```

### Callback returns 403 `invalid jwt header` (base64 padding)

After Cognito login, the browser gets 403 and daemon logs show:
```
callback: failed to parse JWT header error="decode JWT header: illegal base64 data at input byte 423"
```

ALB-signed JWTs (`x-amzn-oidc-data`) use base64url **with padding** (`=`), unlike standard JWTs which omit padding. If the decoder uses `base64.RawURLEncoding` (no padding), it chokes on the `=` characters.

**Fix:** Strip padding before decoding: `base64.RawURLEncoding.DecodeString(strings.TrimRight(segment, "="))`. This is handled by the `decodeBase64URL` helper in `internal/callback/server.go`.

### debconf `Failed to open terminal` errors

Running `apt-get install` in cloud-init without `DEBIAN_FRONTEND=noninteractive` causes debconf/whiptail to fail because there is no interactive terminal. The cloud-init config sets this variable for all `apt-get install` commands in `runcmd`.

These errors are harmless warnings when `DEBIAN_FRONTEND=noninteractive` is set — packages still install correctly.

### Client hangs after invalid or tampered state

The VPN client appears stuck after opening the browser — no `AUTH_FAILED`, no tunnel, just silence until `--auth-timeout` expires (default 4m30s).

This happens when the `state` query parameter in the callback URL is invalid (tampered, corrupted, or expired). The daemon rejects the callback with HTTP 400, but because the state HMAC verification failed, it cannot extract the session ID. Without a session ID, it cannot look up the pending session or send `client-deny` to OpenVPN. The session remains in `PENDING` state until the auth timeout goroutine fires and denies it.

**This is expected behavior, not a bug.** The state blob is the only link between a callback request and a pending session. If the state is invalid, the daemon has no way to identify which client the callback belongs to.

**Diagnose:**
```bash
# Look for state validation failures in daemon logs
journalctl -u openvpn-auth-udp --no-pager | grep "invalid state"

# The corresponding timeout will appear ~auth-timeout later
journalctl -u openvpn-auth-udp --no-pager | grep "auth timeout"
```

**Mitigation:** This only affects error cases (tampered URLs, expired state). Legitimate users see auth success or failure within seconds. The `--auth-timeout` value controls the worst-case wait time.
