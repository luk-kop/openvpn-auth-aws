# Testing Strategy

## Overview

This project uses a hybrid testing approach:

- **Interface-based mocking** for fast unit tests
- **LocalStack** for integration tests with real AWS API calls

## Architecture

All external dependencies are behind interfaces defined in `internal/auth/types.go`:

```go
type IdentityChecker interface {
    CheckUser(context.Context, string, string, bool) (IdentityResult, error)
}

type StateSigner interface {
    Sign(string) string
    Verify(string, string) bool
}

type TokenExchanger interface {
    Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (Claims, error)
}
```

Each package provides two implementations:

- **Real AWS client** (e.g., `cognito.Checker`, `cognito.Exchanger`, `secrets.Signer`)
- **Mock for testing** (e.g., `cognito.StaticChecker`, `cognito.StaticExchanger`, `secrets.StaticSigner`)

## Running Tests

### Unit Tests (Fast, No AWS)

```bash
make test
# or
go test -v -short ./...
```

Uses in-memory mocks. No external dependencies.

### Manual Testing

#### With mocks (three terminals):

```bash
# Terminal 1: OpenVPN management socket simulator
make run-mgmt-mock

# Terminal 2: daemon with local mocks
make run-daemon

# Terminal 3: OAuth2 simulator
make run-lambda-mock
```

#### Full Docker stack:

```bash
make stack-up
sudo openvpn --config lab/client.ovpn
```

#### With real AWS:

```bash
export AWS_REGION=eu-west-1
export VPN_AUTH_COGNITO_USER_POOL_ID=eu-west-1_AbCdEfGhI
export VPN_AUTH_HMAC_SECRET_ARN=arn:aws:secretsmanager:...

./openvpn-auth-daemon \
  --api-gateway-url "https://vpn-auth.example.com" \
  --management-socket "/run/openvpn/management.sock" \
  --management-password-file "/etc/openvpn/management-pw"
```

## Test Coverage

Current coverage:

- ✅ Management interface protocol parsing
- ✅ Command generation (client-auth, client-deny, client-pending-auth, etc.)
- ✅ Auth handler logic (WebAuth check, session eviction, reauth)
- ✅ Callback server (token exchange, claim validation)
- ✅ Session store (TTL reaper, atomic state transitions)
- ✅ State blob signing/verification
- ❌ Cognito integration (not yet implemented)
- ❌ Full auth flow end-to-end (requires Docker stack)

## Adding New Tests

### Unit test with mocks:

```go
func TestMyFeature(t *testing.T) {
    cfg := config.Config{
        APIGatewayURL: "https://vpn-auth.example.com",
        HMACSecret:    "secret",
        HandWindow:    5 * time.Second,
        AuthTimeout:   5 * time.Second,
        CallbackPort:  8080,
    }
    sessions := auth.NewSessionStore()
    identity := cognito.NewStaticChecker(false)
    signer := secrets.NewStaticSigner("test-secret")
    m := metrics.NewEmitter(&strings.Builder{}, "test")

    handler := auth.NewHandler(cfg, sessions, identity, signer, m)
    // test...
}
```

## CI/CD Recommendations

```yaml
# .github/workflows/test.yml
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - run: go test -v -short ./...
```
