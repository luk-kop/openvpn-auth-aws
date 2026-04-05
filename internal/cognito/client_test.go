package cognito

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCheckerCheckUser_FindsRequiredGroupOnSecondPage(t *testing.T) {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			target := req.Header.Get("X-Amz-Target")
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}

			switch target {
			case "AWSCognitoIdentityProviderService.AdminGetUser":
				return jsonResponse(`{
					"Enabled": true,
					"UserStatus": "CONFIRMED",
					"Username": "alice@example.com"
				}`), nil
			case "AWSCognitoIdentityProviderService.AdminListGroupsForUser":
				if strings.Contains(string(body), `"NextToken":"page-2"`) {
					return jsonResponse(`{
						"Groups": [{"GroupName": "required-group"}]
					}`), nil
				}
				return jsonResponse(`{
					"Groups": [{"GroupName": "first-page-group"}],
					"NextToken": "page-2"
				}`), nil
			default:
				t.Fatalf("unexpected X-Amz-Target: %s", target)
				return nil, nil
			}
		}),
	}

	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:  httpClient,
	}

	client := cognitoidentityprovider.NewFromConfig(cfg, func(o *cognitoidentityprovider.Options) {
		o.BaseEndpoint = aws.String("https://cognito-idp.us-east-1.amazonaws.com")
	})

	checker := &Checker{
		client:     client,
		userPoolID: "pool-id",
	}

	result, err := checker.CheckUser(context.Background(), "alice@example.com", "required-group", true)
	if err != nil {
		t.Fatalf("CheckUser returned error: %v", err)
	}
	if !result.Exists {
		t.Fatal("expected user to exist")
	}
	if !result.Enabled {
		t.Fatal("expected user to be enabled")
	}
	if !result.InGroup {
		t.Fatal("expected required group to be found on second page")
	}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}
