package dynamo

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"openvpn-auth-aws/internal/auth"
)

type Store struct {
	client    *dynamodb.Client
	tableName string
}

func NewStore(cfg aws.Config, tableName string) *Store {
	return &Store{
		client:    dynamodb.NewFromConfig(cfg),
		tableName: tableName,
	}
}

func (s *Store) PutPending(ctx context.Context, session auth.PendingSession) error {
	item := map[string]types.AttributeValue{
		"state":          &types.AttributeValueMemberS{Value: session.State},
		"status":         &types.AttributeValueMemberS{Value: string(auth.StatusPending)},
		"nonce":          &types.AttributeValueMemberS{Value: session.Nonce},
		"common_name":    &types.AttributeValueMemberS{Value: session.CommonName},
		"cid":            &types.AttributeValueMemberS{Value: session.CID},
		"kid":            &types.AttributeValueMemberS{Value: session.KID},
		"cn_cross_check": &types.AttributeValueMemberBOOL{Value: session.CNCrossCheck},
		"created_at":     &types.AttributeValueMemberS{Value: session.CreatedAt.Format("2006-01-02T15:04:05Z07:00")},
		"ttl":            &types.AttributeValueMemberN{Value: strconv.FormatInt(session.ExpiresAt.Unix(), 10)},
	}
	if session.Username != "" {
		item["username"] = &types.AttributeValueMemberS{Value: session.Username}
	}
	if session.RequiredGroup != "" {
		item["required_group"] = &types.AttributeValueMemberS{Value: session.RequiredGroup}
	}

	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
	})
	return err
}

func (s *Store) GetStatus(ctx context.Context, state string) (auth.StatusResult, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"state": &types.AttributeValueMemberS{Value: state},
		},
		ProjectionExpression: aws.String("#status, auth_token"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status",
		},
	})
	if err != nil {
		return auth.StatusResult{}, fmt.Errorf("dynamodb get: %w", err)
	}
	if result.Item == nil {
		return auth.StatusResult{Status: auth.StatusPending}, nil
	}

	var record struct {
		Status    string `dynamodbav:"status"`
		AuthToken string `dynamodbav:"auth_token"`
	}
	if err := attributevalue.UnmarshalMap(result.Item, &record); err != nil {
		return auth.StatusResult{}, fmt.Errorf("unmarshal: %w", err)
	}
	return auth.StatusResult{
		Status:    auth.Status(record.Status),
		AuthToken: record.AuthToken,
	}, nil
}

// MemoryStore for testing
type MemoryStore struct {
	mu         sync.RWMutex
	sessions   map[string]auth.PendingSession
	statuses   map[string]auth.Status
	authTokens map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions:   make(map[string]auth.PendingSession),
		statuses:   make(map[string]auth.Status),
		authTokens: make(map[string]string),
	}
}

func (s *MemoryStore) PutPending(_ context.Context, session auth.PendingSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.State] = session
	s.statuses[session.State] = auth.StatusPending
	return nil
}

func (s *MemoryStore) GetStatus(_ context.Context, state string) (auth.StatusResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if status, ok := s.statuses[state]; ok {
		return auth.StatusResult{Status: status, AuthToken: s.authTokens[state]}, nil
	}
	return auth.StatusResult{Status: auth.StatusPending}, nil
}

func (s *MemoryStore) SetStatus(state string, status auth.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses[state] = status
}

func (s *MemoryStore) SetStatusWithToken(state string, status auth.Status, authToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses[state] = status
	s.authTokens[state] = authToken
}
