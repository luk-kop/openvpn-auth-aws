# Tech Stack

## Language & Runtime

- Go 1.26.3 (both modules)
- Main module: `openvpn-auth-aws`
- Lambda Router: separate module `lambda-router` (in `lambda-router/`)
- Target OS: Linux only. Docker base: `golang:1.26.3-alpine` builder → `alpine:3.23` runtime

## Key Dependencies

- `github.com/aws/aws-sdk-go-v2` + `config`, `credentials` — AWS SDK core
- `github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider` — `AdminGetUser`, `AdminListGroupsForUser`
- `github.com/aws/aws-sdk-go-v2/service/secretsmanager` — HMAC secret loading (`--hmac-secret-secret-id`)
- `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` — instance metadata (indirect)
- `github.com/golang-jwt/jwt/v5` — ALB JWT (ES256) validation
- `github.com/aws/aws-lambda-go` — Lambda Router runtime (separate module)
- Standard library only for HTTP, logging (`log/slog`), crypto, and flag parsing

## Configuration

All config is via CLI flags with `VPN_AUTH_*` environment variable overrides. Parsed in `internal/config/config.go` using the standard `flag` package. No third-party config libraries. The HMAC secret can be supplied inline (`--hmac-secret`) or loaded from AWS Secrets Manager (`--hmac-secret-secret-id`).

## Logging

`log/slog` with text or JSON output (controlled by `--log-format`). Use structured key-value pairs: `slog.Info("event", "key", value)`. Raw management-socket traffic can be logged for debugging with `VPN_AUTH_MANAGEMENT_RAW_LOG=true`.

## Testing

- Unit tests use `go test -v -short ./...` — the `-short` flag skips any tests guarded by `testing.Short()`
- Integration tests against real AWS APIs are not yet implemented
- Table-driven tests are the standard pattern
- Interfaces are defined in `internal/auth/types.go` to enable mocking without external libraries
- `lambda-router/main_test.go` exercises the Lambda Router in isolation via the separate module

## Common Commands

```bash
make build              # build daemon + mgmt-mock + alb-mock to repo root
make build-lambda       # build Lambda Router (outputs lambda-router/lambda-arm64.zip + lambda-amd64.zip)
make build-release      # release artifacts to bin/ (tarballs, lambda zips, checksums.txt)
make test               # unit tests (go test -v -short ./...)
make clean              # remove binaries, bin/, .cache/, and test cache

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

# OpenVPN 2.7 multi-socket lab (one OpenVPN process on UDP 1194 + TCP 1195)
make setup-multisocket
make stack-up-multisocket
make stack-rebuild-multisocket
make verify-multisocket          # runs lab/run-multisocket-verification.sh
make stack-down-multisocket

make pki-init                                                # initialize PKI (offline, for AWS deployments)
make pki-tls-crypt [FORCE=1]                                 # generate/rotate tls-crypt key
make pki-client CN=user@example.com                          # generate client cert
make pki-upload [PKI_REGION=eu-west-1] [PKI_PREFIX=...]      # upload PKI to SSM Parameter Store
make pki-client-config CN=user@example.com REMOTE=host:port  # generate .ovpn file
```

## CI/CD

GitHub Actions workflows in `.github/workflows/`:
- `ci.yml` — runs tests and linting on PRs
- `release.yml` — builds and publishes release artifacts (driven by `make build-release`)
- `labeler.yml` — auto-labels PRs based on changed paths

Dependabot configured in `.github/dependabot.yml` for Go module updates.

## Pre-commit Hooks

Configured in `.pre-commit-config.yaml`: `golangci-lint run`, `go vet ./...`, `go test ./...`, plus file hygiene (trailing whitespace, EOF newline, merge conflicts, AWS credential detection).

## Build Outputs

- Development binaries (repo root, via `make build`): `openvpn-auth-daemon`, `mgmt-mock`, `alb-mock`
- Lambda Router zips (via `make build-lambda`): `lambda-router/lambda-arm64.zip`, `lambda-router/lambda-amd64.zip`
- Release artifacts (via `make build-release`, written to `bin/`): per-arch tarballs for the daemon, per-arch Lambda zips, `checksums.txt`
- Container image: built from the repo root `Dockerfile` (non-root user `appuser`, uid 10001)
