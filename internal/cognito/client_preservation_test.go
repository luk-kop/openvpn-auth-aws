package cognito

// Preservation tests for CheckUser — Property 2: Non-Buggy Input Behavior
//
// These tests MUST PASS on unfixed code. They document correct baseline behavior
// that must not regress after fixes are applied.
//
// Observed on unfixed code:
//   - CheckUser with {Enabled: true, UserStatus: "CONFIRMED"} sets result.Enabled = true
//
// Property: for all AdminGetUser responses where resp.Enabled=true and
// resp.UserStatus="CONFIRMED", CheckUser sets result.Enabled=true.
//
// Validates: Requirements 3.1, 3.2

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// newPreservationChecker builds a Checker backed by a mock HTTP transport.
func newPreservationChecker(transport http.RoundTripper) *Checker {
	cfg := aws.Config{
		Region:      "eu-west-1",
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:  &http.Client{Transport: transport},
	}
	client := cognitoidentityprovider.NewFromConfig(cfg, func(o *cognitoidentityprovider.Options) {
		o.BaseEndpoint = aws.String("https://cognito-idp.eu-west-1.amazonaws.com")
	})
	return &Checker{
		client:     client,
		userPoolID: "eu-west-1_TestPool",
	}
}

// confirmedUserTransport returns a mock that responds with a CONFIRMED, enabled user
// and the specified group membership.
func confirmedUserTransport(t *testing.T, inGroup bool) http.RoundTripper {
	t.Helper()
	groupsBody := `{"Groups": []}`
	if inGroup {
		groupsBody = `{"Groups": [{"GroupName": "vpn-users"}]}`
	}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Header.Get("X-Amz-Target") {
		case "AWSCognitoIdentityProviderService.AdminGetUser":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
				Body: io.NopCloser(bytes.NewBufferString(`{
					"Enabled": true,
					"UserStatus": "CONFIRMED",
					"Username": "native-user"
				}`)),
			}, nil
		case "AWSCognitoIdentityProviderService.AdminListGroupsForUser":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
				Body:       io.NopCloser(bytes.NewBufferString(groupsBody)),
			}, nil
		default:
			t.Fatalf("unexpected X-Amz-Target: %s", req.Header.Get("X-Amz-Target"))
			return nil, nil
		}
	})
}

// TestPreservation_CheckUser_ConfirmedNativeUser_Enabled verifies that CheckUser
// sets result.Enabled=true for a confirmed native Cognito user (UserStatus=CONFIRMED,
// Enabled=true).
//
// Property: for all AdminGetUser responses where resp.Enabled=true and
// resp.UserStatus="CONFIRMED", CheckUser sets result.Enabled=true.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.1
func TestPreservation_CheckUser_ConfirmedNativeUser_Enabled(t *testing.T) {
	cases := []struct {
		name    string
		inGroup bool
	}{
		{"in_group", true},
		{"not_in_group", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			checker := newPreservationChecker(confirmedUserTransport(t, tc.inGroup))

			result, err := checker.CheckUser(context.Background(), "native-user", "vpn-users", true)
			if err != nil {
				t.Fatalf("CheckUser returned unexpected error: %v", err)
			}

			// Preservation: confirmed native users must continue to get result.Enabled=true.
			if !result.Enabled {
				t.Errorf("Preservation FAILED: CheckUser returned Enabled=false for confirmed native user (UserStatus=CONFIRMED, Enabled=true); expected Enabled=true")
			}
			if !result.Exists {
				t.Errorf("Preservation FAILED: CheckUser returned Exists=false for confirmed native user; expected Exists=true")
			}
			if result.InGroup != tc.inGroup {
				t.Errorf("Preservation FAILED: CheckUser returned InGroup=%v; expected %v", result.InGroup, tc.inGroup)
			}
		})
	}
}

// TestPreservation_CheckUser_ConfirmedNativeUser_MultipleUsers verifies the
// property holds across a range of confirmed native users.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.1
func TestPreservation_CheckUser_ConfirmedNativeUser_MultipleUsers(t *testing.T) {
	usernames := []string{
		"alice@example.com",
		"bob@example.com",
		"carol@example.com",
		"dave@example.com",
		"eve@example.com",
	}

	for _, username := range usernames {
		username := username
		t.Run(username, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.Header.Get("X-Amz-Target") {
				case "AWSCognitoIdentityProviderService.AdminGetUser":
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
						Body: io.NopCloser(bytes.NewBufferString(`{
							"Enabled": true,
							"UserStatus": "CONFIRMED",
							"Username": "` + username + `"
						}`)),
					}, nil
				case "AWSCognitoIdentityProviderService.AdminListGroupsForUser":
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
						Body:       io.NopCloser(bytes.NewBufferString(`{"Groups": [{"GroupName": "vpn-users"}]}`)),
					}, nil
				default:
					t.Fatalf("unexpected X-Amz-Target: %s", req.Header.Get("X-Amz-Target"))
					return nil, nil
				}
			})

			checker := newPreservationChecker(transport)
			result, err := checker.CheckUser(context.Background(), username, "vpn-users", true)
			if err != nil {
				t.Fatalf("CheckUser(%q) returned unexpected error: %v", username, err)
			}

			// Preservation: confirmed native users must continue to get result.Enabled=true.
			if !result.Enabled {
				t.Errorf("Preservation FAILED: CheckUser(%q) returned Enabled=false for confirmed native user; expected Enabled=true", username)
			}
		})
	}
}
