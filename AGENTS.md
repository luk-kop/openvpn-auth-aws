# Repository Guidelines

## Project Structure & Module Organization

`cmd/` contains the daemon and local `mgmt-mock` and `alb-mock` executables.
Core packages are under `internal/`: `app` owns daemon lifecycle, `auth` owns
sessions and identity decisions, and `mgmt` owns protocol parsing and commands.
The callback-routing Lambda is a separate Go module in `lambda-router/`.
Terraform examples live in `terraform/`, integration labs in `lab/`, PKI tools
in `scripts/`, and documentation in `docs/`. Tests sit beside code
as `*_test.go`.

## Build, Test, and Development Commands

- `make help`: list targets.
- `make test`: run the root-module suite.
- `cd lambda-router && go test -v -short ./...`: test the Lambda module.
- `make lint`: run `golangci-lint` and `go vet` for both modules.
- `make race-test`: run race-enabled tests for both modules.
- `make vulncheck`: scan both modules with `govulncheck`.
- `make fuzz FUZZ_TIME=2m`: fuzz parsers for two minutes.
- `make build` / `make build-lambda`: build daemon tools or Lambda archives.
- `make run-mgmt-mock`, `make run-daemon`, and `make run-alb-mock`: run the
  three-process local flow.

Prefer Make targets where available. Do not start Docker or AWS-backed flows
unless the task requires them.

## Coding Style & Naming Conventions

Run `gofmt` on changed Go files. Use lowercase package names, document
exported identifiers, and keep implementation details private unless they form
an API. Parsers should tolerate additive OpenVPN fields, while command
contracts remain strict. Never authorize using listener or protocol hints.

## Testing Guidelines

Use Go's `testing` package and name tests `Test<Behavior>` or `Fuzz<Target>`.
Prefer hand-written fakes, socket fixtures, and mocks over live AWS
calls. Add tests for changed behavior. Run `make test` and `make lint` before
handoff, Lambda tests for `lambda-router/` changes, and `make race-test` for
concurrency changes. Follow `docs/testing.md` for Docker acceptance flows.

## Commit & Pull Request Guidelines

Use focused Conventional Commit-style subjects such as `fix: ...`, `feat: ...`,
`ci: ...`, or `docs: ...`. PRs should explain behavior changes, identify
configuration or Terraform impact, link relevant issues, and list validation
performed. Avoid unrelated cleanup.

## Security & Workspace Boundaries

Never commit credentials, private keys, populated PKI, passwords, HMAC secrets,
JWTs, or generated artifacts. Keep secrets and callback state out of logs. Do
not weaken ALB JWT, signed-state, CN, group, or management-socket validation.
Treat infrastructure and management-command changes as security-sensitive.

Treat `notes/` as private scratch space: do not list, search, read, modify,
summarize, or cite it unless the user explicitly names that directory or a
file within it.
