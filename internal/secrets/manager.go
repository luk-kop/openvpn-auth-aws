package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type HMACSecretGetter interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func FetchHMACSecret(ctx context.Context, client HMACSecretGetter, secretID string) (string, error) {
	if secretID == "" {
		return "", fmt.Errorf("hmac secret secret id is required")
	}

	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretID,
	})
	if err != nil {
		return "", fmt.Errorf("get hmac secret %q: %w", secretID, err)
	}
	if out == nil {
		return "", fmt.Errorf("hmac secret %q returned no response", secretID)
	}
	if out.SecretString != nil {
		return *out.SecretString, nil
	}
	if len(out.SecretBinary) > 0 {
		return string(out.SecretBinary), nil
	}
	return "", fmt.Errorf("hmac secret %q has no SecretString or SecretBinary value", secretID)
}
