package cognito

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
)

// FetchALBPublicKey fetches the ECDSA public key for the given kid from the
// ALB public key endpoint and returns it parsed as *ecdsa.PublicKey.
//
// The key is fetched from:
//
//	https://public-keys.auth.elb.{region}.amazonaws.com/{kid}
func FetchALBPublicKey(ctx context.Context, region, kid string) (*ecdsa.PublicKey, error) {
	url := fmt.Sprintf("https://public-keys.auth.elb.%s.amazonaws.com/%s", region, kid)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("albkeys: build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("albkeys: fetch public key for kid %q: %w", kid, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("albkeys: unexpected status %d fetching public key for kid %q", resp.StatusCode, kid)
	}

	// PEM public keys are small; cap reads at 8 KB to prevent unexpected large responses.
	const maxKeySize = 8 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySize))
	if err != nil {
		return nil, fmt.Errorf("albkeys: read response body for kid %q: %w", kid, err)
	}

	return parseECPublicKey(body)
}

// parseECPublicKey parses a PEM-encoded ECDSA public key.
func parseECPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("albkeys: failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("albkeys: parse public key: %w", err)
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("albkeys: expected *ecdsa.PublicKey, got %T", pub)
	}

	return ecKey, nil
}
