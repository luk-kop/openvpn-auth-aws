# Testing Strategy

## Development & Testing Modes

There are two supported modes for running and testing the daemon. Each covers a different subset of the auth flow.

### Mode 1: Full Local (no AWS)

Everything runs locally — no AWS credentials, no real OIDC flow, no domain or certificate needed.

`alb-mock` simulates the ALB + Cognito authenticate action: it verifies the HMAC state blob, builds an unsigned JWT with hardcoded test identity, and forwards the request to the daemon with `x-amzn-oidc-*` headers. The daemon skips JWT signature validation (no `--alb-arn`).

**What is tested:**
- State blob HMAC signing and verification
- Session lifecycle (SessionPending → SessionProcessing → SessionDone/SessionFailed)
- Single-session-per-user eviction logic
- Management socket protocol (connect, reauth, disconnect, established)
- Callback server request handling
- JWT claims parsing and group membership checks (from claims)
- CN cross-check logic (if enabled)
- Health check endpoint (`/healthz`)

**What is NOT tested:**
- Real OIDC/OAuth2 browser redirect flow
- Cognito hosted UI login
- ALB JWT signing (ES256) and `signer` field validation
- Cognito API calls (`AdminGetUser`, `AdminListGroupsForUser`)
- ALB target group routing
- EIP association

**How to run:**

Three-terminal setup (no Docker, no OpenVPN):

```bash
# Terminal 1: OpenVPN management socket simulator
make run-mgmt-mock

# Terminal 2: daemon with local mocks
make run-daemon

# Terminal 3: ALB + Cognito simulator
make run-alb-mock
```

In mgmt-mock terminal, type `connect 1 user@example.com`, `reauth 1 user@example.com`, or `disconnect 1` to trigger events.

Full Docker stack (with real OpenVPN):

```bash
make stack-up              # auto-runs PKI setup if needed
sudo openvpn --config lab/client.ovpn
# Logs: docker compose -f lab/docker-compose.yml logs -f daemon
```

### Mode 2: Full AWS (Terraform)

All infrastructure deployed to AWS via Terraform. Tests the complete end-to-end flow including real OIDC authentication.

**Prerequisites:**
- AWS account with credentials configured
- Own domain with DNS pointing to ALB
- ACM certificate for that domain (same region as ALB)
- Cognito User Pool with a test user in the `vpn-users` group

**What is tested:**
- Everything from Mode 1, plus:
- Real browser-based OIDC flow (Cognito hosted UI)
- ALB Cognito authenticate action (redirect, token exchange, session cookie)
- ALB JWT signing (ES256) and daemon-side validation
- Cognito API calls (`AdminGetUser` on reauth, `AdminListGroupsForUser` for groups)
- ALB path-based routing to correct daemon target group
- EIP association gated on target group health
- Health check integration with ALB

**How to run:**

```bash
# 1. Generate and upload PKI (see docs/pki.md)
make pki-init
make pki-upload

# 2. Deploy infrastructure
cd terraform && terraform apply

# 3. Create DNS CNAME: vpn-auth.example.com → ALB DNS name (from terraform output)
# 4. Create test user in Cognito and add to vpn-users group

# 5. Generate client config
make pki-client CN=user@example.com
make pki-client-config CN=user@example.com REMOTE=<EIP from terraform output>

# 6. Connect
sudo openvpn --config pki/clients/user@example.com.ovpn
```

### Terraform Partial Deploys

Terraform variables `deploy_cognito` and `deploy_compute` allow deploying subsets of the infrastructure. Dependencies are enforced via validation (`deploy_compute` requires `deploy_cognito`):

| Scenario | Variables | Use case |
|---|---|---|
| Cognito only | `deploy_cognito=true, deploy_compute=false` | Create user pool for manual testing or external use |
| Full stack | both `true` (default) | Production or end-to-end testing |

## Unit Tests

```bash
make test
# or
go test -v -short ./...
```

Uses in-memory mocks via interfaces defined in `internal/auth/types.go`:

```go
type IdentityChecker interface {
    CheckUser(context.Context, string, string, bool) (IdentityResult, error)
}

type StateSigner interface {
    Sign(string) string
    Verify(string, string) bool
}
```

Each package provides a real AWS implementation and a mock for testing (e.g., `cognito.StaticChecker`, `secrets.StaticSigner`).

### Test Coverage

- Management interface protocol parsing
- Command generation (client-auth, client-deny, client-pending-auth, etc.)
- Auth handler logic (WebAuth check, session eviction, reauth)
- Callback server (claim validation, state HMAC verification)
- Session store (TTL reaper, atomic state transitions)
- State blob signing/verification

### Adding New Tests

```go
func TestMyFeature(t *testing.T) {
    cfg := config.Config{
        CallbackURL:  "http://localhost:8080/callback/01/udp",
        HMACSecret:   "secret",
        HandWindow:   5 * time.Second,
        AuthTimeout:  5 * time.Second,
        CallbackPort: 8080,
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
