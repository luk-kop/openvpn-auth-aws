package cognito

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"openvpn-auth-aws/internal/auth"
)

type Exchanger struct {
	httpClient    *http.Client
	tokenEndpoint string
	clientID      string
	jwks          *JWKSCache
	issuerURL     string
}

func NewExchanger(tokenEndpoint, clientID, issuerURL string) *Exchanger {
	return &Exchanger{
		httpClient:    http.DefaultClient,
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		jwks:          NewJWKSCache(issuerURL),
		issuerURL:     issuerURL,
	}
}

func (e *Exchanger) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*auth.IDTokenClaims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"client_id":     {e.clientID},
		"redirect_uri":  {redirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("unmarshal token response: %w", err)
	}
	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("no id_token in response")
	}

	claims, err := e.jwks.ValidateIDToken(tokenResp.IDToken, e.issuerURL, e.clientID)
	if err != nil {
		return nil, fmt.Errorf("validate id_token: %w", err)
	}

	return claims, nil
}

// StaticExchanger returns fixed claims for local dev.
type StaticExchanger struct {
	Email  string
	Groups []string
}

func NewStaticExchanger(email string, groups []string) *StaticExchanger {
	return &StaticExchanger{Email: email, Groups: groups}
}

func (e *StaticExchanger) Exchange(_ context.Context, _, _, _ string) (*auth.IDTokenClaims, error) {
	return &auth.IDTokenClaims{
		Email:  e.Email,
		Nonce:  "", // nonce check skipped for static exchanger
		Groups: e.Groups,
	}, nil
}
