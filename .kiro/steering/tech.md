# Tech Stack

## Language & Runtime

- Go 1.26.1
- Module: `openvpn-auth-aws`
- Lambda Router: separate module `lambda-router` (in `lambda-router/`)

## Key Dependencies

- `github.com/aws/aws-sdk-go-v2` — AWS SDK (Cognito, EC2 IMDS)
- `github.com/golang-jwt/jwt/v5` — JWT validation
- `github.com/aws/aws-lambda-go` — Lambda Router runtime (separate module)
- Standard library only for HTTP, logging (`log/slog`), crypto, and flag parsing

## Configuration

All config is via CLI flags with `VPN_AUTH_*` environment variable overrides. Parsed in `internal/config/config.go` using the standard `flag` package. No third-party config libraries.

## Logging

`log/slog` with text or JSON output (controlled by `--log-format`). Use structured key-value pairs: `slog.Info("event", "key", value)`.

## Testing

- Unit tests use `go test -v -short ./...` — the `-short` flag skips any tests guarded by `testing.Short()`
- Integration tests against real AWS APIs are not yet implemented
- Table-driven tests are the standard pattern
- Interfaces are defined in `internal/auth/types.go` to enable mocking without external libraries

## Common Commands

```bash
make build              # build all three binaries
make build-lambda       # build Lambda Router (outputs lambda-arm64.zip + lambda-amd64.zip)
make test               # unit tests (go test -v -short ./...)
make clean              # remove binaries and test cache

go test -v -short ./internal/auth/...   # test a single package
go vet ./...                            # static analysis
golangci-lint run                       # linter

make run-daemon         # start daemon (no --cognito-user-pool-id = local dev mode)
make run-alb-mock       # ALB + Cognito authenticate action simulator on :8080
make run-mgmt-mock      # OpenVPN management socket simulator

make setup              # run lab/setup.sh (PKI + configs, run once)
make stack-up           # full Docker stack (OpenVPN + daemon + alb-mock)
make stack-down         # stop Docker stack
make stack-rebuild      # rebuild images and restart

make pki-init           # initialize PKI (offline, for AWS deployments)
make pki-client CN=user@example.com          # generate client cert
make pki-upload                              # upload PKI to SSM Parameter Store
make pki-client-config CN=user@example.com REMOTE=host:port  # generate .ovpn file
```

## CI/CD

GitHub Actions workflows in `.github/workflows/`:
- `ci.yml` — runs tests and linting on PRs
- `release.yml` — builds and publishes release artifacts
- `labeler.yml` — auto-labels PRs based on changed paths

Dependabot configured in `.github/dependabot.yml` for Go module updates.

## Pre-commit Hooks

Configured in `.pre-commit-config.yaml`: `golangci-lint run`, `go vet ./...`, `go test ./...`, plus file hygiene (trailing whitespace, EOF newline, merge conflicts, AWS credential detection).

## Build Outputs

Three binaries built to the repo root: `openvpn-auth-daemon`, `mgmt-mock`, `alb-mock`.
Lambda Router zips built to `lambda-router/`: `lambda-arm64.zip`, `lambda-amd64.zip`.
