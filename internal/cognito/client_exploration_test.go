package cognito

// BugConditionExploration: M10-cognito
//
// This file contains a bug condition exploration test that is EXPECTED TO FAIL
// on unfixed code. The failure confirms the bug exists.
//
// Bug: CheckUser sets result.Enabled = resp.Enabled && resp.UserStatus == types.UserStatusTypeConfirmed
// Federated IdP users have UserStatus = "EXTERNAL_PROVIDER", so result.Enabled is always false
// even when the account is active (resp.Enabled == true).
//
// Counterexample found on unfixed code (actual test output):
//   BUG M10-cognito CONFIRMED: CheckUser returned Enabled=false for an active
//   federated user (resp.Enabled=true, UserStatus=EXTERNAL_PROVIDER); expected Enabled=true
//
// Root cause: The Enabled check uses only UserStatusTypeConfirmed, not accounting
// for UserStatusTypeExternalProvider (federated SAML/OIDC/Google/Azure AD users).

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

// TestBugCondition_M10_cognito demonstrates that CheckUser incorrectly sets
// result.Enabled=false for an active federated IdP user (UserStatus=EXTERNAL_PROVIDER).
//
// On UNFIXED code: result.Enabled=false — test FAILS (expected outcome).
// On FIXED code:   result.Enabled=true  — test PASSES.
//
// Validates: Requirements 1.2, 2.1
func TestBugCondition_M10_cognito(t *testing.T) {
	// Mock AdminGetUser returning an active federated user.
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			target := req.Header.Get("X-Amz-Target")
			switch target {
			case "AWSCognitoIdentityProviderService.AdminGetUser":
				// Active federated user: Enabled=true, UserStatus=EXTERNAL_PROVIDER
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
					Body: io.NopCloser(bytes.NewBufferString(`{
						"Enabled": true,
						"UserStatus": "EXTERNAL_PROVIDER",
						"Username": "google_12345"
					}`)),
				}, nil
			case "AWSCognitoIdentityProviderService.AdminListGroupsForUser":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
					Body: io.NopCloser(bytes.NewBufferString(`{
						"Groups": [{"GroupName": "vpn-users"}]
					}`)),
				}, nil
			default:
				t.Fatalf("unexpected X-Amz-Target: %s", target)
				return nil, nil
			}
		}),
	}

	cfg := aws.Config{
		Region:      "eu-west-1",
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:  httpClient,
	}

	client := cognitoidentityprovider.NewFromConfig(cfg, func(o *cognitoidentityprovider.Options) {
		o.BaseEndpoint = aws.String("https://cognito-idp.eu-west-1.amazonaws.com")
	})

	checker := &Checker{
		client:     client,
		userPoolID: "eu-west-1_TestPool",
	}

	result, err := checker.CheckUser(context.Background(), "google_12345", "vpn-users", true)
	if err != nil {
		t.Fatalf("CheckUser returned unexpected error: %v", err)
	}

	// On unfixed code: result.Enabled=false — this assertion FAILS (expected).
	// On fixed code:   result.Enabled=true  — this assertion PASSES.
	if !result.Enabled {
		t.Errorf("BUG M10-cognito CONFIRMED: CheckUser returned Enabled=false for an active federated user (resp.Enabled=true, UserStatus=EXTERNAL_PROVIDER); expected Enabled=true")
	}
}
