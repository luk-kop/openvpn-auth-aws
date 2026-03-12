.PHONY: test test-local setup stack-up stack-down stack-rebuild build clean

# Unit tests (fast, no AWS)
test:
	go test -v -short ./...

# Local dev test: mgmt-mock + daemon + lambda-mock (no Docker, no OpenVPN)
# Terminal 1: make run-daemon
# Terminal 2: make run-lambda-mock
# Terminal 3: make run-mgmt-mock → type "connect 1 user@example.com"
run-daemon:
	go run ./cmd/openvpn-auth-daemon \
		--use-local-mocks \
		--cn-cross-check=false \
		--hmac-secret=test-secret \
		--api-gateway-url=http://localhost:8080 \
		--management-socket=/tmp/openvpn-mgmt.sock \
		--management-password-file=/tmp/mgmt-pw \
		--callback-port=8081 \
		--instance-ip=127.0.0.1 \
		--auth-timeout=120s \
		--hand-window=120s

run-lambda-mock:
	VPN_AUTH_HMAC_SECRET=test-secret go run ./cmd/lambda-mock

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
	@echo "    lambda-mock: http://localhost:8080"
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

# Build all binaries
build:
	go build -o openvpn-auth-daemon ./cmd/openvpn-auth-daemon
	go build -o mgmt-mock ./cmd/mgmt-mock
	go build -o lambda-mock ./cmd/lambda-mock

clean:
	rm -f openvpn-auth-daemon mgmt-mock lambda-mock
	go clean -testcache
