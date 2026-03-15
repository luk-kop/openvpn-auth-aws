# Security Issues - openvpn-auth-aws

## Status Summary

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| #1 | 🔴 High | Password bypass in handleConnect | ✅ FIXED |
| #2 | 🔴 High | Missing HMAC verification for callback | ✅ FIXED |
| #3 | 🟡 Medium | No rate limiting on CLIENT:CONNECT | ⚠️ OPEN |
| #4 | 🔴 High | PKCE effectively disabled in WebAuth flow | ✅ FIXED (superseded in v2 — ALB handles PKCE) |
| #5 | 🟡 Medium | JWKS cache never evicts rotated keys | ✅ FIXED (superseded in v2 — no JWKS cache, ALB keys fetched per-kid) |
| #6 | 🟡 Medium | Unsafe stream read for mgmt socket auth | ✅ FIXED |
| #7 | 🟡 Medium | Callback server missing timeouts and body limit | ✅ FIXED |

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

**Fix (v1):** Lambda `/callback` signed the request body with HMAC (`X-Internal-Token` header). Daemon verified HMAC before processing.

**v2 status:** This issue is architecturally resolved. ALB `authenticate-cognito` action handles authentication. The daemon callback port is only reachable from the ALB security group (network isolation). ALB JWT `signer` field validation provides defense-in-depth against header spoofing.

---

### #4: PKCE effectively disabled in WebAuth flow ✅

**Status:** FIXED (2026-03-14)

**Problem:** The daemon computed `code_challenge` from `code_verifier` but discarded it (`_ = codeChallenge`). The auth URL sent to the client contained only `state`, so the Cognito authorization server was never given the challenge. When the daemon later exchanged the auth code with `code_verifier`, Cognito had nothing to verify it against.

**Impact:** PKCE did not protect against authorization code interception. If an auth code leaked between browser, API Gateway, Lambda, and the callback handler, it could be replayed without the original `code_verifier`.

**Why not in the URL:** OpenVPN CE clients have a 229-byte `INFOMSG` buffer limit (`alloc_buf_gc(256)` in `src/openvpn/push.c`, minus `>INFOMSG:` prefix). The WEB_AUTH URL with state blob already uses ~198 bytes. Adding `&code_challenge=<43 chars>&code_challenge_method=S256` (+73 bytes) would exceed the limit, causing the client to silently drop the URL.

**Fix:** Daemon computes `code_challenge` at session creation and stores it in the `PendingSession`. A new `GET /challenge?sid=<session_id>` endpoint on the daemon's HTTP server allows Lambda `/auth` to fetch the challenge before redirecting to Cognito. The endpoint:

- Requires `X-Internal-Token: HMAC(sid)` header (same auth model as `/callback`)
- Only returns challenges for sessions in `PENDING` state
- Returns `404` for unknown sessions, `409` for non-pending sessions

Lambda `/auth` flow: verify HMAC on state → extract daemon IP → `GET /challenge` → build Cognito authorize URL with `code_challenge` and `code_challenge_method=S256` → 302 redirect.

**v2 status:** This issue is architecturally resolved. ALB handles the full OIDC/PKCE flow internally — the daemon no longer performs token exchange or manages PKCE challenges.

**Files changed (v1 fix):** `internal/auth/handler.go`, `internal/auth/types.go`, `internal/auth/sessions.go`, `internal/callback/server.go`

---

### #5: JWKS cache never evicts rotated keys ✅

**Status:** FIXED (2026-03-14)

**Problem:** `JWKSCache.refresh()` only added new keys to the map — it never removed keys absent from the JWKS response. If Cognito rotated signing keys (e.g., due to compromise), the old key remained trusted until process restart.

**Impact:** Tokens signed by a revoked key would continue to validate as long as they were otherwise valid (correct issuer, audience, not expired).

**Fix:** `refresh()` now builds a fresh key map from the JWKS response and atomically replaces the old map. Keys removed from Cognito's JWKS endpoint are immediately untrusted.

**File changed:** `internal/cognito/jwks.go`

---

### #6: Unsafe stream read for mgmt socket auth ✅

**Status:** FIXED (2026-03-14)

**Problem:** Management socket authentication used `c.conn.Read(buf)` to read the 15-byte password prompt (`ENTER PASSWORD:`). On Unix sockets, `Read` may return fewer bytes than requested (short read). The returned byte count was discarded (`_`), so a short read would cause `string(buf) != "ENTER PASSWORD:"` to fail even when the socket was sending the correct prompt.

**Impact:** Flaky daemon startup failures depending on how the kernel packetized the socket data.

**Fix:** Replaced `c.conn.Read(buf)` with `io.ReadFull(c.conn, buf)`, which loops until all 15 bytes are received or an error occurs.

**File changed:** `internal/mgmt/client.go`

---

### #7: Callback server missing timeouts and body limit ✅

**Status:** FIXED (2026-03-14)

**Problem:** The callback HTTP server had two robustness issues:

1. `io.ReadAll(r.Body)` read the full request body with no size limit. A malicious or buggy client could send an arbitrarily large body, exhausting memory.
2. `http.Server` was created without `ReadHeaderTimeout`, `ReadTimeout`, or `WriteTimeout`. Slow clients could hold connections indefinitely.

**Impact:** DoS risk — resource exhaustion via large request bodies or slow connections.

**Fix:**
- Request body wrapped with `http.MaxBytesReader(w, r.Body, 64*1024)` (64 KB limit)
- HTTP server configured with `ReadHeaderTimeout: 5s`, `ReadTimeout: 10s`, `WriteTimeout: 10s`

**File changed:** `internal/callback/server.go`

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
