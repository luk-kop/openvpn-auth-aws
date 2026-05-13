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
// docs/group-authorization.md. It decodes ALB-forwarded headers
// (x-amzn-oidc-data, x-amzn-oidc-accesstoken, x-amzn-oidc-identity) and emits
// structured slog events for each. It never logs the raw JWT strings. Normal
// requests emit at most three records: oidc_debug_headers, oidc_debug_data, and
// oidc_debug_accesstoken.
//
// When --oidc-debug-claims is enabled:
//   - Logs header presence and lengths.
//   - For x-amzn-oidc-data and x-amzn-oidc-accesstoken: one aggregated record
//     per token with JWT header fields and a claims map containing JSON type,
//     value length, and full value capped at 2048 original bytes with an
//     appended truncation suffix.
//   - For x-amzn-oidc-identity: a salted SHA-256 prefix (first 16 hex chars).
//   - Never logs the raw JWT strings or the raw x-amzn-oidc-identity.

const (
	oidcDebugValueCap      = 2048
	oidcIdentityHashHexLen = 16
)

// oidcDebugLogger decodes and logs ALB-forwarded OIDC headers at DEBUG level.
// A nil *oidcDebugLogger is a no-op, so callers can call l.Log(r) without a
// guard when the feature is disabled.
type oidcDebugLogger struct {
	// salt is generated once per daemon startup via crypto/rand. Keeping it
	// in-memory only makes identity hashes correlatable within this process
	// but not across restarts or other instances.
	salt []byte
}

// newOIDCDebugLogger constructs a debug logger when enabled is true, otherwise
// returns nil. The caller should pass nil straight through to the Server.
func newOIDCDebugLogger(enabled bool) (*oidcDebugLogger, error) {
	if !enabled {
		return nil, nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("oidc debug: generate salt: %w", err)
	}
	return &oidcDebugLogger{salt: salt}, nil
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
		l.logJWT("oidc_debug_data", oidcData, sessionID)
	}
	if accessToken != "" {
		l.logJWT("oidc_debug_accesstoken", accessToken, sessionID)
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

// logJWT decodes the header and payload of a JWT-looking string and emits one
// structured event for that token. The raw token string is never logged.
func (l *oidcDebugLogger) logJWT(eventPrefix, token, sessionID string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		slog.Debug(eventPrefix,
			"sid", sessionID,
			"token_error", "not three dot-separated segments",
			"segments", len(parts),
		)
		return
	}

	attrs := []any{"sid", sessionID}
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		attrs = append(attrs, "header_error", err.Error())
	} else {
		header, err := parseOIDCDebugJWTHeader(headerBytes)
		if err != nil {
			attrs = append(attrs, "header_error", err.Error())
		} else {
			attrs = append(attrs, "header", header)
		}
	}

	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		attrs = append(attrs, "payload_error", err.Error())
		slog.Debug(eventPrefix, attrs...)
		return
	}
	claims, err := buildClaimInfoMap(payloadBytes)
	if err != nil {
		attrs = append(attrs, "payload_error", err.Error())
		slog.Debug(eventPrefix, attrs...)
		return
	}
	attrs = append(attrs, "claims", claims)
	slog.Debug(eventPrefix, attrs...)
}

// parseOIDCDebugJWTHeader returns the standard ALB JWT header fields. Unknown fields are
// ignored; operators only need kid, alg, signer, and typ for diagnostics.
func parseOIDCDebugJWTHeader(headerBytes []byte) (map[string]any, error) {
	var raw map[string]any
	if err := json.Unmarshal(headerBytes, &raw); err != nil {
		return nil, err
	}
	header := map[string]any{}
	for _, k := range []string{"kid", "alg", "signer", "typ"} {
		if v, ok := raw[k]; ok {
			header[k] = jsonScalarString(v)
		}
	}
	return header, nil
}

// buildClaimInfoMap returns a map keyed by claim name. Every claim includes
// its capped value. Claim values are never sent through any code path that logs
// raw JWT strings.
func buildClaimInfoMap(payloadBytes []byte) (map[string]any, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}

	claims := make(map[string]any, len(payload))
	for name, raw := range payload {
		jsonType, valueLen := describeJSONValue(raw)
		claim := map[string]any{
			"type": jsonType,
			"len":  valueLen,
		}

		emitted, truncated, totalBytes := capPayload(raw, oidcDebugValueCap)
		value := string(emitted)
		if truncated {
			// The suffix is appended to the truncated value inline, so the
			// emitted log string can exceed the cap by the suffix length.
			// Keep this in one field so log consumers see the complete
			// representation of the claim value.
			value += truncationSuffix(totalBytes)
		}
		claim["value"] = value

		claims[name] = claim
	}
	return claims, nil
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
