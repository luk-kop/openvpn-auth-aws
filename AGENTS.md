# Repository Guidelines

## Project Structure & Module Organization

`openvpn-auth-aws` is a Go daemon that connects OpenVPN management events to an
AWS Cognito/ALB browser-authentication flow. Executables live under `cmd/`:
`openvpn-auth-daemon`, `mgmt-mock`, and `alb-mock`. Core packages live under
`internal/`: `app`, `auth`, `callback`, `cognito`, `config`, `metrics`, `mgmt`,
and `secrets`. The optional callback-routing Lambda is in `lambda-router/`.
Terraform and its modules are in `terraform/`, Docker/OpenVPN integration labs
are in `lab/`, PKI tooling is in `scripts/`, and maintained documentation is in
`docs/`. Go tests sit next to package code as `*_test.go`.

## Build, Test, and Development Commands

- `make test`: runs the fast root-module suite with `go test -v -short ./...`.
- `go test -race -short ./...`: runs the root-module race suite.
- `cd lambda-router && go test -v -short ./...`: tests the Lambda module.
- `make build`: builds the daemon and both local mock binaries.
- `make build-lambda`: cross-builds Lambda Router archives for amd64 and arm64.
- `make build-release`: builds release archives, Lambda artifacts, and checksums.
- `make tidy`: synchronizes the root `go.mod` and `go.sum`.
- `make run-mgmt-mock`, `make run-daemon`, and `make run-alb-mock`: run the
  three-process local development flow.
- `make stack-up` / `make stack-down`: start or stop the standard Docker lab.
- `make verify-local-new-wins`: run the OpenVPN 2.7.5 local replacement
  acceptance flow after its documented lab prerequisites are running.

Prefer Make targets where available so build metadata and repository workflows
stay consistent. Do not start Docker or AWS-backed integration flows unless the
task requires them.

## Coding Style & Naming Conventions

Use idiomatic Go and keep changed Go files `gofmt` formatted. Package names are
lowercase and concise. Keep implementation details unexported unless they form a
real package API, and document exported identifiers. Preserve the existing
ownership boundaries: `internal/app` owns daemon and management-connection
lifecycle, `internal/auth` owns session and identity decisions, and
`internal/mgmt` owns protocol parsing and command representation. Keep parsers
tolerant of additive OpenVPN fields, but keep command-response contracts strict.
Do not introduce listener or protocol hints as authorization or session keys.

## Testing Guidelines

Use Go's standard `testing` package. Name tests `Test<Behavior>` and keep focused
scenario tests close to the changed package. Prefer hand-written fakes, Unix
socket fixtures, and the existing mocks over live AWS calls. Add or update tests
for management parsing, reconnect behavior, session transitions, callback
validation, and configuration changes. Run `make test` before handoff; also run
the Lambda module tests when changing `lambda-router/`. Run race tests for
concurrency or lifecycle changes. OpenVPN/Docker acceptance is proportional to
the change and should follow `docs/testing.md`.

## Commit & Pull Request Guidelines

Recent history uses Conventional Commit-style subjects such as
`fix: preserve certificate CN in OpenVPN status handling`,
`feat: openvpn 2.7 support`, and `docs: improved docs`. Keep commits focused and
avoid mixing unrelated cleanup with the requested change. PRs should explain
the behavior change, call out configuration or Terraform impact, link relevant
issues, and include the tests or lab flows that were run.

## Security & Configuration Tips

Do not commit AWS credentials, client private keys, populated PKI material,
management passwords, HMAC secrets, JWTs, or generated release/lab artifacts.
Keep callback state and credential-like management environment values redacted
from logs. Do not weaken ALB JWT validation, signed-state validation, CN checks,
group authorization, or management-socket ownership to make a test pass. Keep
production defaults fail-closed while preserving explicitly documented local
mock modes. Treat changes to Terraform IAM, security groups, callback routing,
Secrets Manager access, and OpenVPN management commands as security-sensitive.

## Ignored Workspace Areas

Treat `notes/` as private scratch space outside the project scope. Do not list,
search, read, modify, summarize, or cite files under `notes/`. Access `notes/`
only when the user explicitly requests work in that directory or names a
specific file inside it. Never treat content from `notes/` as current project
documentation.
