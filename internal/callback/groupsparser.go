package callback

import (
	"encoding/json"
	"strings"
)

// parseGroupsClaim extracts a list of group names from a JWT claim value.
//
// The parser implements the rules from docs/group-authorization.md:
//
//  1. JSON array: apply array rules (strings only, trimmed, empty dropped).
//  2. String that parses as a valid JSON array: parse and apply array rules.
//  3. String matching `^\[.*\]$` (after trim) that is NOT a valid JSON array:
//     parse as a bracketed CSV compatibility format only when the inner
//     content contains a comma. Split on ",", trim each element, and drop
//     empty elements. Bracketed non-JSON strings without commas yield no
//     groups.
//  4. String containing commas: split on "," and trim each element. If all
//     elements are empty after trimming, return no groups (do not fall to 5).
//  5. Non-empty string: treat as one group.
//  6. Anything else (nil, bool, number, object, empty / whitespace-only
//     string): no groups.
//
// For string claim values, whitespace is trimmed once upfront before evaluating
// rules 2-5. Rules 1 and 6 are unaffected. Group comparison stays exact and
// case-sensitive per the plan.
func parseGroupsClaim(value any) []string {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case []any:
		return groupsFromArray(v)
	case string:
		return parseStringGroupsClaim(v)
	default:
		// Rule 6: non-string scalars (bool, float64, json.Number,
		// map[string]any, or any other type) yield no groups.
		return nil
	}
}

// groupsFromArray applies array rules to a []any: keep only string elements,
// trim each, drop empty results. Non-string elements are ignored.
func groupsFromArray(items []any) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseStringGroupsClaim applies rules 2-5 to a string claim value. The value
// is trimmed once upfront; rules 2-5 see only the trimmed form.
func parseStringGroupsClaim(raw string) []string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}

	// Rule 2 + 3: bracketed values. Any string that looks like a JSON array
	// (starts with '[' and ends with ']') is first parsed as JSON array. If
	// that fails, treat comma-containing inner content as the bracketed CSV
	// compatibility format observed in Cognito/Entra mappings.
	if looksLikeJSONArray(s) {
		var arr []any
		if err := json.Unmarshal([]byte(s), &arr); err == nil {
			return groupsFromArray(arr)
		}
		return groupsFromBracketedCSV(s)
	}

	// Rule 4: CSV form.
	if strings.Contains(s, ",") {
		return groupsFromCSV(s)
	}

	// Rule 5: single non-empty string becomes one group.
	return []string{s}
}

// looksLikeJSONArray reports whether s starts with '[' and ends with ']'.
// Whitespace is already trimmed by the caller.
func looksLikeJSONArray(s string) bool {
	return len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']'
}

// groupsFromCSV splits a comma-separated string, trims each element, and
// drops empty ones. Returns nil when no non-empty elements remain, so the
// caller does not fall through to rule 5.
func groupsFromCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// groupsFromBracketedCSV parses the compatibility shape "[a, b]" by removing
// the outer brackets and applying the normal CSV rules to the inner content.
// A comma is required: observed Cognito/Entra mappings emit a single group as
// "a", not "[a]", so bracketed non-JSON strings without commas are treated as
// malformed.
func groupsFromBracketedCSV(s string) []string {
	if !looksLikeJSONArray(s) {
		return nil
	}
	inner := s[1 : len(s)-1]
	if !strings.Contains(inner, ",") {
		return nil
	}
	return groupsFromCSV(inner)
}
