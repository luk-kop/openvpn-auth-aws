package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeHMACSecretGetter struct {
	output *secretsmanager.GetSecretValueOutput
	err    error
	input  *secretsmanager.GetSecretValueInput
}

func (f *fakeHMACSecretGetter) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.input = in
	return f.output, f.err
}

func TestFetchHMACSecret_SecretString(t *testing.T) {
	secret := "test-secret-key!!"
	client := &fakeHMACSecretGetter{
		output: &secretsmanager.GetSecretValueOutput{SecretString: &secret},
	}

	got, err := FetchHMACSecret(context.Background(), client, "vpn/hmac")
	if err != nil {
		t.Fatalf("FetchHMACSecret returned error: %v", err)
	}
	if got != secret {
		t.Fatalf("FetchHMACSecret = %q, want %q", got, secret)
	}
	if client.input == nil || client.input.SecretId == nil || *client.input.SecretId != "vpn/hmac" {
		t.Fatalf("GetSecretValue input SecretId = %#v, want vpn/hmac", client.input)
	}
}

func TestFetchHMACSecret_SecretBinary(t *testing.T) {
	client := &fakeHMACSecretGetter{
		output: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte("test-secret-key!!")},
	}

	got, err := FetchHMACSecret(context.Background(), client, "vpn/hmac")
	if err != nil {
		t.Fatalf("FetchHMACSecret returned error: %v", err)
	}
	if got != "test-secret-key!!" {
		t.Fatalf("FetchHMACSecret = %q, want test-secret-key!!", got)
	}
}

func TestFetchHMACSecret_GetError(t *testing.T) {
	client := &fakeHMACSecretGetter{err: errors.New("boom")}

	_, err := FetchHMACSecret(context.Background(), client, "vpn/hmac")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "vpn/hmac") {
		t.Fatalf("error %q does not include secret ID", err)
	}
}

func TestFetchHMACSecret_EmptySecretID(t *testing.T) {
	client := &fakeHMACSecretGetter{}

	_, err := FetchHMACSecret(context.Background(), client, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFetchHMACSecret_NoValue(t *testing.T) {
	client := &fakeHMACSecretGetter{
		output: &secretsmanager.GetSecretValueOutput{},
	}

	_, err := FetchHMACSecret(context.Background(), client, "vpn/hmac")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestFetchHMACSecret_NilResponse(t *testing.T) {
	client := &fakeHMACSecretGetter{}

	_, err := FetchHMACSecret(context.Background(), client, "vpn/hmac")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
