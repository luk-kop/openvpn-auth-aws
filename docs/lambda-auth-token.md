# Lambda Auth Token Implementation

## Security Enhancement

Lambda `/callback` must sign the request body with HMAC before POSTing to the daemon's `/callback` endpoint. The daemon verifies this signature before processing the callback.

## Implementation

### Lambda — Signing the request

```python
import hmac
import hashlib
import base64
import json
import requests

def sign_body(body_bytes, hmac_secret):
    """Generate HMAC-SHA256 signature of request body."""
    signature = hmac.new(
        key=hmac_secret.encode(),
        msg=body_bytes,
        digestmod=hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

# Build callback payload
payload = {
    "session_id": session_id,
    "code": authorization_code,
    "timestamp": int(time.time())
}
body = json.dumps(payload).encode()

# Sign and send
token = sign_body(body, hmac_secret)
requests.post(
    f"http://{daemon_ip}:{daemon_port}/callback",
    data=body,
    headers={
        "Content-Type": "application/json",
        "X-Internal-Token": token
    }
)
```

### Daemon verification

The daemon (`internal/callback/server.go`) verifies the callback:

1. Reads the request body
2. Checks `X-Internal-Token` header contains valid HMAC of the body
3. Parses JSON payload and checks timestamp (±30s to prevent replay)
4. Looks up session, exchanges auth code for tokens (PKCE), validates JWT claims

### HMAC Secret

Use the same HMAC secret that Lambda `/auth` uses for state blob verification:

```python
# Fetch from Secrets Manager (with caching)
secrets = get_hmac_secrets()  # Returns [AWSCURRENT, AWSPREVIOUS] during rotation
hmac_secret = secrets[0]  # Use AWSCURRENT for signing
```

## Security Properties

1. **Prevents forged callbacks**: Attacker who can reach the daemon's callback port cannot forge valid requests without the HMAC secret
2. **Replay protection**: Timestamp check (±30s) prevents replaying captured requests
3. **Rotation-safe**: Daemon and Lambda share the same secret (via Secrets Manager)
4. **Minimal overhead**: Single HMAC operation per callback

## Error Handling

**Daemon behavior when `X-Internal-Token` is missing or invalid**:

- HTTP 403 Forbidden response
- Callback is silently rejected (no session state change)

**Lambda should always include `X-Internal-Token`** when POSTing to the daemon. If Lambda fails to sign (e.g., missing HMAC secret), the daemon will reject the callback.
