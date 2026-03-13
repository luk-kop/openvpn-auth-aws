# Security Issues - openvpn-auth-aws

## Status Summary

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| #1 | 🔴 High | Password bypass in handleConnect | ✅ FIXED |
| #2 | 🔴 High | Missing HMAC verification for callback | ✅ FIXED |
| #3 | 🟡 Medium | No rate limiting on CLIENT:CONNECT | ⚠️ OPEN |

---

## 🔴 High Severity (FIXED)

### #1: Password bypass in handleConnect ✅

**Status:** FIXED (2026-03-09)

**Problem:** Code in `handler.go` accepted any non-empty password and bypassed WebAuth flow:

```go
// REMOVED CODE:
if pw := event.Env["password"]; pw != "" {
    h.metrics.AuthSuccess()
    sink.Send(Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
    return
}
```

**Impact:** Client with valid TLS certificate could bypass OIDC authentication by providing any password.

**Fix:** Removed password bypass logic. All CLIENT:CONNECT events now require WebAuth flow.

**Test:** Added `TestHandleConnectIgnoresPassword` to verify password field is ignored.

---

### #2: Missing HMAC verification for callback ✅

**Status:** FIXED (2026-03-09)

**Problem:** Callback endpoint lacked request verification. An attacker who could reach the daemon's `/callback` port could forge auth success responses.

**Impact:** Unauthorized VPN access if attacker can reach the callback endpoint.

**Fix:**
- Lambda `/callback` signs the request body with HMAC and sends it in `X-Internal-Token` header
- Daemon verifies HMAC before processing the callback
- Timestamp check (±30s) prevents replay attacks
- See [lambda-auth-token.md](lambda-auth-token.md) for implementation details

---

## 🟡 Medium Severity (OPEN)

### #3: No rate limiting on CLIENT:CONNECT

**Location:** `handler.go` (`handleConnect`)

**Problem:** Client can spam CLIENT:CONNECT events, creating multiple pending sessions:
- Each call creates an in-memory session
- Each starts a timeout goroutine
- Sessions remain for AuthTimeout duration (default 5 minutes) even after disconnect

**Mitigating factors:**
- `--single-session-per-user=true` (default, configurable) evicts existing sessions on new connect, limiting to one active session per CN
- OpenVPN's TLS handshake requirement limits pre-connection spam

**Remaining attack vectors:**

1. **Rapid reconnect:** User repeatedly connects/disconnects. Old session is evicted but there's a brief window where goroutines accumulate.

2. **Multiple certificates:** Attacker with multiple valid certificates (different CNs) can create one session per CN.

**Proposed fix:**

Track concurrent pending sessions per CN and limit to a small number (e.g. 3):

```go
// In handleConnect, before creating session:
h.mu.Lock()
count := h.cnCount[event.CommonName()]
h.mu.Unlock()

if count >= 3 {
    h.metrics.AuthDenied("too_many_pending")
    sink.Send(Decision{
        Type: DecisionDeny,
        CID: event.CID,
        KID: event.KID,
        Reason: "too many pending auth sessions",
    })
    return
}
```

---

## Rejected / False Positives

The following issues were initially identified but determined to be incorrect or not security-relevant:

### ❌ Race condition in inFlight map

**Why rejected:** Both `handleDisconnect()` and `clearInFlight()` use the same mutex (`h.mu`). Go's `delete()` does not panic on missing keys. No race condition exists.

### ❌ Timer not cancelable in authTimeout

**Why rejected:** `timer.C` is in the select statement alongside `ctx.Done()`, and `defer timer.Stop()` properly cleans up. No leak exists.

### ❌ No limit on Decision.Reason length

**Why rejected:** All `Reason` values in the codebase are short, constant strings (e.g., "auth timeout", "client does not support WebAuth"). No dynamic error messages are used.

### ❌ randomToken uses only 16 bytes

**Why rejected:** 128 bits of entropy is cryptographically sufficient for state/nonce tokens. This is a preference, not a vulnerability.

### ❌ No validation on ExpiresAt max TTL

**Why rejected:** This is a configuration robustness issue, not a security vulnerability. TTL is bounded by `HandWindow` configuration.

### ❌ Management password in plaintext memory

**Why rejected:** This is theoretical defense-in-depth with no practical mitigation in Go. Not a realistic security issue for this project.

---

## Recommendations

**Priority order for fixes:**

1. **#3 (Rate limiting)** - Prevents DoS, medium severity

**Testing:**
- Add integration tests for rate limiting
- Add stress tests for concurrent CLIENT:CONNECT
