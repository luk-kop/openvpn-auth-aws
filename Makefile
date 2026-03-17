.PHONY: test setup build clean \
	stack-up stack-down stack-rebuild \
	run-daemon run-alb-mock run-mgmt-mock \
	pki-init pki-client pki-upload pki-client-config

# Unit tests (fast, no AWS)
test:
	go test -v -short ./...

# Local dev test: mgmt-mock + daemon + alb-mock (no Docker, no OpenVPN)
# Terminal 1: make run-daemon
# Terminal 2: make run-alb-mock
# Terminal 3: make run-mgmt-mock → type "connect 1 user@example.com"
run-daemon:
	go run ./cmd/openvpn-auth-daemon \
		--cn-cross-check=false \
		--hmac-secret=test-secret \
		--callback-url=http://localhost:8080/callback \
		--cognito-skip-reauth \
		--cognito-groups-from-claims \
		--management-socket=/tmp/openvpn-mgmt.sock \
		--management-password-file=/tmp/mgmt-pw \
		--callback-port=8081 \
		--auth-timeout=120s \
		--hand-window=120s

run-alb-mock:
	DAEMON_ADDR=localhost:8081 go run ./cmd/alb-mock

run-mgmt-mock:
	go run ./cmd/mgmt-mock

# Setup lab environment (run once, or to regenerate certs)
setup:
	cd lab && ./setup.sh

# Start full stack (Docker)
stack-up:
	@if [ ! -f lab/openvpn-data/openvpn.conf ] || [ ! -f lab/client.ovpn ]; then \
		echo "==> PKI not found, running setup..."; \
		cd lab && ./setup.sh; \
	fi
	docker compose -f lab/docker-compose.yml up -d
	@echo ""
	@echo "==> Stack ready!"
	@echo "    OpenVPN:     udp://localhost:1194"
	@echo "    alb-mock:    http://localhost:8080"
	@echo "    daemon cb:   http://localhost:8081"
	@echo ""
	@echo "Connect: sudo openvpn --config lab/client.ovpn"
	@echo "Logs:    docker compose -f lab/docker-compose.yml logs -f daemon"

# Stop full stack
stack-down:
	docker compose -f lab/docker-compose.yml down

# Rebuild images and restart stack (use after code changes)
stack-rebuild:
	docker compose -f lab/docker-compose.yml build --no-cache
	docker compose -f lab/docker-compose.yml up -d
	@echo ""
	@echo "==> Stack ready!"
	@echo "    OpenVPN:     udp://localhost:1194"
	@echo "    alb-mock:    http://localhost:8080"
	@echo "    daemon cb:   http://localhost:8081"
	@echo ""
	@echo "Connect: sudo openvpn --config lab/client.ovpn"
	@echo "Logs:    docker compose -f lab/docker-compose.yml logs -f daemon"

# Build all binaries
build:
	go build -o openvpn-auth-daemon ./cmd/openvpn-auth-daemon
	go build -o mgmt-mock ./cmd/mgmt-mock
	go build -o alb-mock ./cmd/alb-mock

clean:
	rm -f openvpn-auth-daemon mgmt-mock alb-mock
	go clean -testcache

# --- PKI Management (offline, for AWS deployments) ---
PKI_REGION ?= eu-west-1
PKI_PREFIX ?= openvpn-auth-aws

pki-init:
	./scripts/pki.sh init

pki-client:
	@test -n "$(CN)" || (echo "Usage: make pki-client CN=user@example.com" && exit 1)
	./scripts/pki.sh client "$(CN)"

pki-upload:
	./scripts/pki.sh upload --region "$(PKI_REGION)" --prefix "$(PKI_PREFIX)"

pki-client-config:
	@test -n "$(CN)" || (echo "Usage: make pki-client-config CN=user@example.com REMOTE=<host|ip>[:port]" && exit 1)
	@test -n "$(REMOTE)" || (echo "Usage: make pki-client-config CN=user@example.com REMOTE=<host|ip>[:port]" && exit 1)
	./scripts/pki.sh client-config "$(CN)" --remote "$(REMOTE)"
