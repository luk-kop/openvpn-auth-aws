package callback

import (
	"encoding/json"
	"reflect"
	"testing"
)

// mustUnmarshal decodes a JSON snippet into the Go value the claim would have
// after json.Unmarshal into map[string]any. Tests call this to get realistic
// inputs (json.Number behavior, []any, map[string]any, etc.).
func mustUnmarshal(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("invalid JSON fixture %q: %v", s, err)
	}
	return v
}

// TestParseGroupsClaim_AllRules is the primary coverage grid for the parser.
// Each row captures a claim value as it would appear after JSON decoding and
// the expected parse result. Rule numbers refer to docs/group-claims-debug-plan.md.
func TestParseGroupsClaim_AllRules(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  []string
	}{
		// Rule 1: JSON array (native []any).
		{
			name:  "rule1/array_of_strings",
			value: mustUnmarshal(t, `["xxx","yyy"]`),
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule1/array_with_leading_trailing_whitespace_trimmed",
			value: mustUnmarshal(t, `["  xxx  ","yyy"]`),
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule1/array_non_string_elements_ignored",
			value: mustUnmarshal(t, `["xxx",42,true,null,"yyy"]`),
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule1/array_empty_elements_dropped",
			value: mustUnmarshal(t, `["","xxx","   ","yyy",""]`),
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule1/array_empty_returns_nil",
			value: mustUnmarshal(t, `[]`),
			want:  nil,
		},
		{
			name:  "rule1/array_only_whitespace_returns_nil",
			value: mustUnmarshal(t, `["   ","\t"]`),
			want:  nil,
		},

		// Rule 2: string that parses as JSON array.
		{
			name:  "rule2/json_array_as_string",
			value: `["xxx","yyy"]`,
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule2/json_array_as_string_with_surrounding_whitespace",
			value: `  ["xxx","yyy"]  `,
			want:  []string{"xxx", "yyy"},
		},

		// Rule 3: bracketed but not valid JSON array → no groups.
		{
			name:  "rule3/bracketed_non_json_no_commas",
			value: `[xxx yyy]`,
			want:  nil,
		},
		{
			name:  "rule3/bracketed_non_json_with_commas",
			value: `[a,b]`,
			want:  nil,
		},
		{
			name:  "rule3/bracketed_non_json_with_commas_and_spaces",
			value: `[a, b]`,
			want:  nil,
		},
		{
			name:  "rule3/bracketed_non_json_with_surrounding_whitespace",
			value: `  [a,b]  `,
			want:  nil,
		},
		{
			name:  "rule3/bracketed_empty_is_empty_array",
			value: `[]`,
			want:  nil,
		},

		// Rule 4: comma-separated string.
		{
			name:  "rule4/csv_two_groups",
			value: "xxx, yyy",
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule4/csv_surrounding_whitespace_trimmed",
			value: "  xxx , yyy  ",
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule4/csv_empty_elements_dropped",
			value: "xxx,, yyy, ,",
			want:  []string{"xxx", "yyy"},
		},
		{
			name:  "rule4/csv_all_empty_returns_nil_no_fallthrough",
			value: ", , ,",
			want:  nil,
		},
		{
			name:  "rule4/csv_single_trailing_comma",
			value: "only,",
			want:  []string{"only"},
		},

		// Rule 5: non-empty string with no commas, not bracketed.
		{
			name:  "rule5/single_string",
			value: "xxx",
			want:  []string{"xxx"},
		},
		{
			name:  "rule5/single_string_with_whitespace_trimmed",
			value: "  xxx  ",
			want:  []string{"xxx"},
		},

		// Documented scalar-JSON-as-string cases from the plan: these continue
		// through the string rules and land on rule 5 as literal single groups.
		// Operators should avoid them but the parser accepts them for
		// predictability; OIDC debug logging is the safety net.
		{
			name:  "rule5/scalar_true_as_single_group",
			value: "true",
			want:  []string{"true"},
		},
		{
			name:  "rule5/scalar_false_as_single_group",
			value: "false",
			want:  []string{"false"},
		},
		{
			name:  "rule5/scalar_42_as_single_group",
			value: "42",
			want:  []string{"42"},
		},
		{
			name:  "rule5/scalar_null_as_single_group",
			value: "null",
			want:  []string{"null"},
		},
		{
			name:  "rule5/scalar_empty_object_as_single_group",
			value: "{}",
			want:  []string{"{}"},
		},

		// Rule 6: anything else.
		{
			name:  "rule6/nil",
			value: nil,
			want:  nil,
		},
		{
			name:  "rule6/empty_string",
			value: "",
			want:  nil,
		},
		{
			name:  "rule6/whitespace_only_string",
			value: "   \t\n",
			want:  nil,
		},
		{
			name:  "rule6/bool_true",
			value: true,
			want:  nil,
		},
		{
			name:  "rule6/bool_false",
			value: false,
			want:  nil,
		},
		{
			name:  "rule6/number_float64",
			value: 42.0,
			want:  nil,
		},
		{
			name:  "rule6/json_number",
			value: json.Number("42"),
			want:  nil,
		},
		{
			name:  "rule6/map_object",
			value: map[string]any{"k": "v"},
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseGroupsClaim(tc.value)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseGroupsClaim(%#v) = %#v, want %#v", tc.value, got, tc.want)
			}
		})
	}
}

// TestExtractGroupsFromRaw_UsesParser confirms the server's extraction helper
// routes group-claim decoding through parseGroupsClaim (not a bespoke JSON
// array path). A claim value that's a single string must now yield a single
// group instead of being silently dropped as "not an array".
func TestExtractGroupsFromRaw_UsesParser(t *testing.T) {
	raw := map[string]any{
		"email":         "u@example.com",
		"custom:groups": "vpn-users",
	}
	got, present := extractGroupsFromRaw(raw, "custom:groups")
	if !present {
		t.Fatal("expected custom:groups claim to be present")
	}
	want := []string{"vpn-users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extractGroupsFromRaw string claim = %#v, want %#v", got, want)
	}
}

// TestExtractGroupsFromRaw_MissingClaim returns nil when the claim name is
// absent. This guards the callback's "deny when configured claim is absent"
// contract — the caller uses nil as the signal for absent/unusable claims.
func TestExtractGroupsFromRaw_MissingClaim(t *testing.T) {
	raw := map[string]any{"email": "u@example.com"}
	got, present := extractGroupsFromRaw(raw, "custom:groups")
	if present {
		t.Fatal("expected missing claim to report present=false")
	}
	if got != nil {
		t.Fatalf("expected nil for missing claim, got %#v", got)
	}
}

// TestExtractGroupsFromRaw_EmptyClaimName returns nil. cognito-api mode passes
// an empty claim name and must not surface any groups.
func TestExtractGroupsFromRaw_EmptyClaimName(t *testing.T) {
	raw := map[string]any{"cognito:groups": []any{"vpn-users"}}
	got, present := extractGroupsFromRaw(raw, "")
	if present {
		t.Fatal("expected empty claim name to report present=false")
	}
	if got != nil {
		t.Fatalf("expected nil when claim name is empty, got %#v", got)
	}
}

// TestExtractGroupsFromRaw_CSVClaim proves the parser handles CSV values,
// which the legacy extractor silently dropped.
func TestExtractGroupsFromRaw_CSVClaim(t *testing.T) {
	raw := map[string]any{"custom:groups": "a, b , c"}
	got, present := extractGroupsFromRaw(raw, "custom:groups")
	if !present {
		t.Fatal("expected custom:groups claim to be present")
	}
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extractGroupsFromRaw CSV claim = %#v, want %#v", got, want)
	}
}

// TestExtractGroupsFromRaw_JSONArrayAsString ensures the parser handles a
// JSON-encoded array wrapped in a string value, as some IdP mappings emit.
func TestExtractGroupsFromRaw_JSONArrayAsString(t *testing.T) {
	raw := map[string]any{"custom:groups": `["a","b"]`}
	got, present := extractGroupsFromRaw(raw, "custom:groups")
	if !present {
		t.Fatal("expected custom:groups claim to be present")
	}
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extractGroupsFromRaw JSON-as-string = %#v, want %#v", got, want)
	}
}

// TestExtractGroupsFromRaw_BracketedNonJSONRejected documents that the
// non-standard [a,b] shape is rejected per the plan. Operators see this via
// OIDC debug logging and must fix the IdP/Cognito mapping upstream.
func TestExtractGroupsFromRaw_BracketedNonJSONRejected(t *testing.T) {
	raw := map[string]any{"custom:groups": "[a,b]"}
	got, present := extractGroupsFromRaw(raw, "custom:groups")
	if !present {
		t.Fatal("expected custom:groups claim to be present")
	}
	if got != nil {
		t.Fatalf("expected nil for [a,b] bracketed non-JSON string, got %#v", got)
	}
}
