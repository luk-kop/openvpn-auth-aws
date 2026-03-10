//go:build integration

package dynamo

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"openvpn-auth-aws/internal/auth"
)

func setupLocalStack(t *testing.T) (*Store, context.Context) {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: "http://localhost:4566"}, nil
				},
			),
		),
	)
	if err != nil {
		t.Fatalf("aws config: %v", err)
	}

	client := dynamodb.NewFromConfig(cfg)
	tableName := "vpn-sessions-test"

	// Create table
	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("state"), KeyType: types.KeyTypeHash},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("state"), AttributeType: types.ScalarAttributeTypeS},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	t.Cleanup(func() {
		_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{
			TableName: aws.String(tableName),
		})
	})

	return NewStore(cfg, tableName), ctx
}

func TestDynamoDBIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	store, ctx := setupLocalStack(t)

	session := auth.PendingSession{
		State:         "test-state-123",
		Nonce:         "test-nonce-456",
		CommonName:    "john@example.com",
		CID:           "1",
		KID:           "1",
		Username:      "john",
		CNCrossCheck:  true,
		RequiredGroup: "vpn-users",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(10 * time.Minute),
	}

	// Test PutPending
	err := store.PutPending(ctx, session)
	if err != nil {
		t.Fatalf("PutPending: %v", err)
	}

	// Test GetStatus
	status, err := store.GetStatus(ctx, "test-state-123")
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != auth.StatusPending {
		t.Fatalf("expected PENDING, got %s", status)
	}

	// Test non-existent state
	status, err = store.GetStatus(ctx, "non-existent")
	if err != nil {
		t.Fatalf("GetStatus non-existent: %v", err)
	}
	if status != auth.StatusPending {
		t.Fatalf("expected PENDING for non-existent, got %s", status)
	}
}
