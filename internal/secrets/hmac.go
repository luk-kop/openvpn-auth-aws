package secrets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type Signer struct {
	client    *secretsmanager.Client
	secretARN string
	secret    []byte
}

func NewSigner(cfg aws.Config, secretARN string) (*Signer, error) {
	client := secretsmanager.NewFromConfig(cfg)

	resp, err := client.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	})
	if err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}

	return &Signer{
		client:    client,
		secretARN: secretARN,
		secret:    []byte(*resp.SecretString),
	}, nil
}

func (s *Signer) Sign(state string) string {
	sum := hmac.New(sha256.New, s.secret)
	sum.Write([]byte(state))
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))
}

// StaticSigner for testing
type StaticSigner struct {
	secret []byte
}

func NewStaticSigner(secret string) *StaticSigner {
	return &StaticSigner{secret: []byte(secret)}
}

func (s *StaticSigner) Sign(state string) string {
	sum := hmac.New(sha256.New, s.secret)
	sum.Write([]byte(state))
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))
}
