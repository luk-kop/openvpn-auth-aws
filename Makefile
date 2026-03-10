.PHONY: test test-integration localstack-up localstack-down setup stack-up stack-down build clean

# Unit tests (fast, no AWS)
test:
	go test -v -short ./...

# Integration tests with LocalStack
test-integration:
	docker compose -f lab/docker-compose.yml up -d localstack
	@echo "Waiting for LocalStack to be ready..."
	@sleep 5
	go test -v -tags=integration ./...

# Setup lab environment (run once, or to regenerate certs)
setup:
	cd lab && ./setup.sh

# Start full stack
# Generates PKI only if openvpn.conf or client.ovpn are missing
stack-up:
	@if [ ! -f lab/openvpn-data/openvpn.conf ] || [ ! -f lab/client.ovpn ]; then \
		echo "==> PKI not found, running setup..."; \
		cd lab && ./setup.sh; \
	fi
	docker compose -f lab/docker-compose.yml up -d
	@echo ""
	@echo "==> Stack ready!"
	@echo "    OpenVPN:     udp://localhost:1194"
	@echo "    LocalStack:  http://localhost:4566"
	@echo "    lambda-mock: http://localhost:8080"
	@echo ""
	@echo "Connect: sudo openvpn --config lab/client.ovpn"
	@echo "Logs:    docker compose -f lab/docker-compose.yml logs -f daemon"

# Stop full stack
stack-down:
	docker compose -f lab/docker-compose.yml down

# Build all binaries
build:
	go build -o openvpn-auth-daemon ./cmd/openvpn-auth-daemon
	go build -o mgmt-mock ./cmd/mgmt-mock
	go build -o lambda-mock ./cmd/lambda-mock

clean:
	rm -f openvpn-auth-daemon mgmt-mock lambda-mock
	go clean -testcache
