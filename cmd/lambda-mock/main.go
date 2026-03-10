// lambda-mock simulates the Lambda /auth endpoint for local development.
// It verifies the HMAC signature, writes SUCCESS to DynamoDB (LocalStack),
// and returns an HTML confirmation page — exactly what the real Lambda /callback
// would do after a successful Cognito login.
//
// Usage (via docker compose):
//
//	VPN_AUTH_HMAC_SECRET=test-secret
//	DYNAMODB_ENDPOINT=http://localstack:4566
//	DYNAMODB_TABLE=vpn-sessions
//	AWS_REGION=eu-west-1
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func main() {
	hmacSecret := mustEnv("VPN_AUTH_HMAC_SECRET")
	tableName := getenv("DYNAMODB_TABLE", "vpn-sessions")
	region := getenv("AWS_REGION", "eu-west-1")
	addr := getenv("LISTEN_ADDR", ":8080")

	ctx := context.Background()

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Fatalf("aws config: %v", err)
	}

	db := dynamodb.NewFromConfig(awsCfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		state := strings.Trim(r.URL.Query().Get("state"), "'")
		sig := strings.Trim(r.URL.Query().Get("sig"), "'")
		if state == "" || sig == "" {
			http.Error(w, "missing state or sig", http.StatusBadRequest)
			return
		}

		// Verify HMAC signature (same as daemon StaticSigner.Sign)
		expected := sign(hmacSecret, state)
		if sig != expected {
			log.Printf("/auth: invalid sig for state=%s", state)
			http.Error(w, "invalid signature", http.StatusForbidden)
			return
		}

		// Generate auth_token = HMAC(state|SUCCESS) — matches poller.verifyAuthToken
		authToken := sign(hmacSecret, state+"|SUCCESS")

		_, err := db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(tableName),
			Key: map[string]types.AttributeValue{
				"state": &types.AttributeValueMemberS{Value: state},
			},
			UpdateExpression: aws.String("SET #s = :s, auth_token = :t, #ttl = :ttl"),
			ExpressionAttributeNames: map[string]string{
				"#s":   "status",
				"#ttl": "ttl",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":s":   &types.AttributeValueMemberS{Value: "SUCCESS"},
				":t":   &types.AttributeValueMemberS{Value: authToken},
				":ttl": &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)},
			},
		})
		if err != nil {
			log.Printf("/auth: dynamodb update error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		log.Printf("/auth: approved state=%s", state)
		w.Header().Set("Content-Type", "text/html")
		if _, err := fmt.Fprintf(w, `<!DOCTYPE html>
<html><body>
<h1>Authentication successful</h1>
<p>You can close this window and return to your VPN client.</p>
</body></html>`); err != nil {
			log.Printf("/auth: write response: %v", err)
		}
	})

	log.Printf("Lambda mock listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func sign(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
