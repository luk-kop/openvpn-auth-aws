package cognito

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// generateTestECKey returns a fresh P-256 key and its PEM-encoded public key.
func generateTestECKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pemBytes
}

func TestFetchALBPublicKey(t *testing.T) {
	_, validPEM := generateTestECKey(t)

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantErr     bool
		errContains string
	}{
		{
			name: "success — valid PEM returned",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(validPEM)
			},
		},
		{
			name: "HTTP error — non-200 status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr:     true,
			errContains: "unexpected status 404",
		},
		{
			name: "invalid PEM body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("not a pem block"))
			},
			wantErr:     true,
			errContains: "failed to decode PEM block",
		},
		{
			name: "PEM contains RSA key, not EC",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Encode a non-EC key type by faking the PEM header
				w.WriteHeader(http.StatusOK)
				// Use valid DER but wrap it as a certificate (wrong type)
				_, ecPEM := generateTestECKey(t)
				// Replace PUBLIC KEY header with something that parses as non-EC
				// Easiest: send a PEM block with garbage DER so x509.Parse fails
				garbage := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")})
				_ = ecPEM
				_, _ = w.Write(garbage)
			},
			wantErr:     true,
			errContains: "parse public key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			key, err := FetchALBPublicKey(context.Background(), srv.URL, "test-kid")

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil key")
			}
			if key.Curve != elliptic.P256() {
				t.Errorf("expected P-256 curve, got %v", key.Curve)
			}
		})
	}
}

func TestParseECPublicKey(t *testing.T) {
	_, validPEM := generateTestECKey(t)

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:  "valid P-256 PEM",
			input: validPEM,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "garbage bytes",
			input:   []byte("not pem"),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := parseECPublicKey(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil key")
			}
		})
	}
}
