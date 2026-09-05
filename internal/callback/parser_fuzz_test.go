package callback

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func FuzzParseJWTHeader(f *testing.F) {
	validHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"key-1","signer":"arn:aws:elasticloadbalancing:region:account:loadbalancer/app/example/id"}`))
	f.Add(validHeader + ".e30.signature")
	f.Add(validHeader + "==.e30=.signature")
	f.Add("not-a-jwt")
	f.Add("..")
	f.Add("!!!!.e30.signature")

	f.Fuzz(func(t *testing.T, token string) {
		_, err := parseJWTHeader(token)
		if err != nil {
			return
		}

		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("parseJWTHeader accepted token with %d parts", len(parts))
		}
		header, err := decodeBase64URL(parts[0])
		if err != nil {
			t.Fatalf("parseJWTHeader accepted invalid base64url: %v", err)
		}
		var decoded albJWTHeader
		if err := json.Unmarshal(header, &decoded); err != nil {
			t.Fatalf("parseJWTHeader accepted invalid JSON: %v", err)
		}
	})
}

func FuzzParseGroupsClaim(f *testing.F) {
	f.Add([]byte(`["vpn-users","admins"]`))
	f.Add([]byte(`"[vpn-users, admins]"`))
	f.Add([]byte(`"vpn-users, admins"`))
	f.Add([]byte(`null`))
	f.Add([]byte{0xff, ',', ' ', 'x'})

	f.Fuzz(func(t *testing.T, input []byte) {
		assertNormalizedGroups(t, parseGroupsClaim(string(input)))

		var decoded any
		if err := json.Unmarshal(input, &decoded); err == nil {
			assertNormalizedGroups(t, parseGroupsClaim(decoded))
		}
	})
}

func assertNormalizedGroups(t *testing.T, groups []string) {
	t.Helper()
	for _, group := range groups {
		if group == "" {
			t.Fatal("parseGroupsClaim returned an empty group")
		}
		if group != strings.TrimSpace(group) {
			t.Fatalf("parseGroupsClaim returned an untrimmed group %q", group)
		}
	}
}
