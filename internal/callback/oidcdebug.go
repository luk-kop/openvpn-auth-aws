package callback

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// OIDC debug logging implements the claim diagnostics described in
// docs/group-claims-debug-plan.md. It decodes ALB-forwarded headers
// (x-amzn-oidc-data, x-amzn-oidc-accesstoken, x-amzn-oidc-identity) and emits
// structured slog events for each. It never logs the raw JWT strings.
//
// Safe mode (--oidc-debug-claims):
//   - Logs header presence and lengths.
//   - For x-amzn-oidc-data: JWT header fields; per-claim name, JSON type, value
//     length. Full value (capped at 2048 original bytes, with an appended
//     truncation suffix) only for the hardcoded allowlist and the configured
//     --groups-claim.
//   - For x-amzn-oidc-accesstoken: per-claim name and JSON type when the value
//     looks like a JWT. No claim values, including group-like values.
//   - For x-amzn-oidc-identity: a salted SHA-256 prefix (first 16 hex chars).
//
// Unsafe mode (--oidc-debug-claims-unsafe, implies --oidc-debug-claims):
//   - Logs full decoded claim values for every claim in x-amzn-oidc-data and
//     x-amzn-oidc-accesstoken (still capped at 2048 original bytes).
//   - Still never logs the raw JWT strings or the raw x-amzn-oidc-identity.

const (
	oidcDebugValueCap      = 2048
	oidcIdentityHashHexLen = 16
)

// Hardcoded allowlist of group-like claim names whose full (capped) value is
// emitted in safe mode, in addition to the operator's configured
// --groups-claim. Union semantics: both sets flow through the same capped
// logger.
var oidcDebugGroupClaimAllowlist = []string{
	"cognito:groups",
	"groups",
	"roles",
}

// oidcDebugLogger decodes and logs ALB-forwarded OIDC headers at DEBUG level.
// A nil *oidcDebugLogger is a no-op, so callers can call l.Log(r) without a
// guard when the feature is disabled.
type oidcDebugLogger struct {
	unsafeMode            bool
	configuredGroupsClaim string
	// salt is generated once per daemon startup via crypto/rand. Keeping it
	// in-memory only makes identity hashes correlatable within this process
	// but not across restarts or other instances.
	salt []byte
}

// newOIDCDebugLogger constructs a debug logger when enabled is true, otherwise
// returns nil. The caller should pass nil straight through to the Server.
// Unsafe mode implies enabled: if unsafeMode is true, the logger is always
// constructed even when enabled is false. This makes the constructor robust
// against callers that build Config directly without going through
// config.Parse() (which normalizes the two flags).
func newOIDCDebugLogger(enabled, unsafeMode bool, configuredGroupsClaim string) (*oidcDebugLogger, error) {
	if !enabled && !unsafeMode {
		return nil, nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("oidc debug: generate salt: %w", err)
	}
	return &oidcDebugLogger{
		unsafeMode:            unsafeMode,
		configuredGroupsClaim: configuredGroupsClaim,
		salt:                  salt,
	}, nil
}

// Log emits all configured debug events for an incoming callback request.
// Safe to call on a nil receiver.
func (l *oidcDebugLogger) Log(r *http.Request, sessionID string) {
	if l == nil {
		return
	}

	oidcData := r.Header.Get("x-amzn-oidc-data")
	accessToken := r.Header.Get("x-amzn-oidc-accesstoken")
	identity := r.Header.Get("x-amzn-oidc-identity")

	slog.Debug("oidc_debug_headers",
		"sid", sessionID,
		"oidc_data_present", oidcData != "",
		"oidc_data_len", len(oidcData),
		"accesstoken_present", accessToken != "",
		"accesstoken_len", len(accessToken),
		"identity_present", identity != "",
		"identity_len", len(identity),
		"identity_hash", l.hashIdentity(identity),
	)

	if oidcData != "" {
		l.logJWT("oidc_debug_data", oidcData, sessionID, l.isGroupValueClaim)
	}
	if accessToken != "" {
		// Access-token claim values are never logged in safe mode, even for
		// group-like names. Unsafe mode logs values for all claims.
		l.logJWT("oidc_debug_accesstoken", accessToken, sessionID, func(string) bool { return false })
	}
}

// hashIdentity returns a salted SHA-256 prefix (first 16 hex characters) of
// the x-amzn-oidc-identity header value. Returns "" when the identity is empty.
func (l *oidcDebugLogger) hashIdentity(identity string) string {
	if identity == "" {
		return ""
	}
	h := sha256.New()
	h.Write(l.salt)
	h.Write([]byte(identity))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:oidcIdentityHashHexLen]
}

// isGroupValueClaim reports whether the x-amzn-oidc-data claim name should
// have its full (capped) value logged in safe mode. In unsafe mode, all claim
// values are logged regardless.
func (l *oidcDebugLogger) isGroupValueClaim(name string) bool {
	if l.configuredGroupsClaim != "" && name == l.configuredGroupsClaim {
		return true
	}
	for _, allowed := range oidcDebugGroupClaimAllowlist {
		if name == allowed {
			return true
		}
	}
	return false
}

// logJWT decodes the header and payload of a JWT-looking string and emits
// structured events. The raw token string is never logged.
// valueAllowed is consulted in safe mode to decide whether to log a claim's
// full (capped) value. In unsafe mode, every claim's value is logged.
func (l *oidcDebugLogger) logJWT(eventPrefix, token, sessionID string, valueAllowed func(string) bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		slog.Debug(eventPrefix+"_malformed",
			"sid", sessionID,
			"reason", "not three dot-separated segments",
			"segments", len(parts),
		)
		return
	}

	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		slog.Debug(eventPrefix+"_header_decode_failed",
			"sid", sessionID,
			"error", err.Error(),
		)
	} else {
		l.logJWTHeader(eventPrefix, headerBytes, sessionID)
	}

	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		slog.Debug(eventPrefix+"_payload_decode_failed",
			"sid", sessionID,
			"error", err.Error(),
		)
		return
	}
	l.logJWTPayload(eventPrefix, payloadBytes, sessionID, valueAllowed)
}

// logJWTHeader emits one event with the standard ALB JWT header fields.
// Unknown fields are ignored; the plan only requires kid, alg, signer, and typ.
func (l *oidcDebugLogger) logJWTHeader(eventPrefix string, headerBytes []byte, sessionID string) {
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		slog.Debug(eventPrefix+"_header_parse_failed",
			"sid", sessionID,
			"error", err.Error(),
		)
		return
	}
	attrs := []any{"sid", sessionID}
	for _, k := range []string{"kid", "alg", "signer", "typ"} {
		if v, ok := header[k]; ok {
			attrs = append(attrs, k, jsonScalarString(v))
		}
	}
	slog.Debug(eventPrefix+"_header", attrs...)
}

// logJWTPayload emits one event per claim in the JWT payload.
// In safe mode, valueAllowed gates which claims include their value.
// In unsafe mode, every claim's value is logged (still capped at 2048 bytes).
// Claim values are never sent through any code path that logs raw JWT strings.
func (l *oidcDebugLogger) logJWTPayload(eventPrefix string, payloadBytes []byte, sessionID string, valueAllowed func(string) bool) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		slog.Debug(eventPrefix+"_payload_parse_failed",
			"sid", sessionID,
			"error", err.Error(),
		)
		return
	}

	for name, raw := range payload {
		jsonType, valueLen := describeJSONValue(raw)
		attrs := []any{
			"sid", sessionID,
			"name", name,
			"type", jsonType,
			"len", valueLen,
		}

		if l.unsafeMode || valueAllowed(name) {
			emitted, truncated, totalBytes := capPayload(raw, oidcDebugValueCap)
			value := string(emitted)
			if truncated {
				// Per plan: suffix is appended to the truncated value inline,
				// so the emitted log string can exceed the cap by the suffix
				// length. Keep this in one field so log consumers see the
				// complete representation of the claim value.
				value += truncationSuffix(totalBytes)
			}
			attrs = append(attrs, "value", value)
		}

		slog.Debug(eventPrefix+"_claim", attrs...)
	}
}

// jsonScalarString renders a header field as a short string. Non-string values
// are rendered via fmt.Sprint so an unexpected alg:null or kid:number is still
// diagnosable rather than silently dropped.
func jsonScalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

// describeJSONValue returns the JSON type name and the length of the raw
// encoded value. Length is the number of bytes in the raw JSON token, which is
// a stable lower bound on the decoded string length.
func describeJSONValue(raw json.RawMessage) (string, int) {
	trimmed := trimJSONWhitespace(raw)
	if len(trimmed) == 0 {
		return "empty", 0
	}
	switch trimmed[0] {
	case '"':
		return "string", len(trimmed)
	case '{':
		return "object", len(trimmed)
	case '[':
		return "array", len(trimmed)
	case 't', 'f':
		return "bool", len(trimmed)
	case 'n':
		return "null", len(trimmed)
	}
	if (trimmed[0] >= '0' && trimmed[0] <= '9') || trimmed[0] == '-' {
		return "number", len(trimmed)
	}
	return "unknown", len(trimmed)
}

// trimJSONWhitespace removes JSON whitespace bytes (space, tab, CR, LF) from
// both ends of a raw JSON value. Encoders typically do not emit trailing
// whitespace, but the JSON grammar allows it around values so this makes
// describeJSONValue robust.
func trimJSONWhitespace(raw json.RawMessage) json.RawMessage {
	start := 0
	for start < len(raw) && isJSONWhitespace(raw[start]) {
		start++
	}
	end := len(raw)
	for end > start && isJSONWhitespace(raw[end-1]) {
		end--
	}
	return raw[start:end]
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// capPayload applies the 2048-byte cap per the plan. The cap is measured
// against the original payload bytes; the suffix is appended after truncation,
// so the emitted log string can exceed 2048 bytes by the suffix length.
func capPayload(raw json.RawMessage, maxBytes int) (emitted []byte, truncated bool, totalBytes int) {
	if len(raw) <= maxBytes {
		return raw, false, len(raw)
	}
	return raw[:maxBytes], true, len(raw)
}

// truncationSuffix renders the "<truncated,total_bytes=X>" marker used in debug
// logs when a value is capped. Defined here so tests can assert the exact form.
func truncationSuffix(totalBytes int) string {
	return fmt.Sprintf("<truncated,total_bytes=%d>", totalBytes)
}
