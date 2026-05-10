.PHONY: test setup setup-multisocket build build-release build-lambda clean \
	stack-up stack-down stack-rebuild \
	stack-up-multisocket stack-down-multisocket stack-rebuild-multisocket verify-multisocket \
	run-daemon run-alb-mock run-mgmt-mock \
	pki-init pki-tls-crypt pki-client pki-upload pki-client-config

BINARY := openvpn-auth-daemon
BINDIR := bin
RELEASE_TMP := $(BINDIR)/release
GO_BUILD_CACHE := $(CURDIR)/.cache/go-build
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
VERSION_NO_V := $(VERSION:v%=%)
LDFLAGS := -s -w

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
		--hmac-secret=test-secret-key!! \
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

setup-multisocket:
	cd lab && ./setup-multisocket.sh

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

# Start OpenVPN 2.7 multi-socket lab stack (Docker)
stack-up-multisocket:
	@if [ ! -f lab/openvpn-data-multisocket/openvpn.conf ] || [ ! -f lab/client-udp.ovpn ] || [ ! -f lab/client-tcp.ovpn ]; then \
		echo "==> Multi-socket PKI not found, running setup..."; \
		cd lab && ./setup-multisocket.sh; \
	fi
	docker compose -f lab/docker-compose.multisocket.yml up -d
	@echo ""
	@echo "==> Multi-socket stack ready!"
	@echo "    OpenVPN UDP: udp://localhost:1194"
	@echo "    OpenVPN TCP: tcp://localhost:1195"
	@echo "    alb-mock:    http://localhost:8080"
	@echo "    daemon cb:   http://localhost:8081"
	@echo ""
	@echo "Connect UDP: sudo openvpn --config lab/client-udp.ovpn"
	@echo "Connect TCP: sudo openvpn --config lab/client-tcp.ovpn"
	@echo "Verify:      VPN_AUTH_MANAGEMENT_RAW_LOG=true RENEG_SEC=30 make stack-rebuild-multisocket verify-multisocket"

# Stop full stack
stack-down:
	docker compose -f lab/docker-compose.yml down

stack-down-multisocket:
	docker compose -f lab/docker-compose.multisocket.yml down

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

stack-rebuild-multisocket:
	cd lab && ./setup-multisocket.sh
	docker compose -f lab/docker-compose.multisocket.yml build --no-cache
	docker compose -f lab/docker-compose.multisocket.yml up -d
	@echo ""
	@echo "==> Multi-socket stack ready!"
	@echo "    OpenVPN UDP: udp://localhost:1194"
	@echo "    OpenVPN TCP: tcp://localhost:1195"
	@echo "    alb-mock:    http://localhost:8080"
	@echo "    daemon cb:   http://localhost:8081"
	@echo ""
	@echo "Verify: VPN_AUTH_MANAGEMENT_RAW_LOG=true RENEG_SEC=30 make verify-multisocket"

verify-multisocket:
	./lab/run-multisocket-verification.sh

# Build all binaries
build:
	go build -o openvpn-auth-daemon ./cmd/openvpn-auth-daemon
	go build -o mgmt-mock ./cmd/mgmt-mock
	go build -o alb-mock ./cmd/alb-mock

clean:
	rm -rf $(BINDIR)
	rm -rf .cache
	rm -f openvpn-auth-daemon mgmt-mock alb-mock
	go clean -testcache

# Build release artifacts for GitHub Releases.
build-release:
	rm -rf $(RELEASE_TMP)
	mkdir -p $(RELEASE_TMP)
	GOCACHE=$(GO_BUILD_CACHE) CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(RELEASE_TMP)/$(BINARY)_linux_amd64 ./cmd/openvpn-auth-daemon
	mkdir -p $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/docs
	cp $(RELEASE_TMP)/$(BINARY)_linux_amd64 $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/$(BINARY)
	cp README.md $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/README.md
	cp LICENSE $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/LICENSE
	if [ -f docs/examples/openvpn-auth.service ]; then cp docs/examples/openvpn-auth.service $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/openvpn-auth.service; fi
	cp docs/configuration.md docs/openvpn-server.md docs/troubleshooting.md $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/docs/
	tar -C $(RELEASE_TMP) -czf $(BINDIR)/$(BINARY)_$(VERSION_NO_V)_linux_amd64.tar.gz $(BINARY)_$(VERSION_NO_V)_linux_amd64
	GOCACHE=$(GO_BUILD_CACHE) CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(RELEASE_TMP)/$(BINARY)_linux_arm64 ./cmd/openvpn-auth-daemon
	mkdir -p $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/docs
	cp $(RELEASE_TMP)/$(BINARY)_linux_arm64 $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/$(BINARY)
	cp README.md $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/README.md
	cp LICENSE $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/LICENSE
	if [ -f docs/examples/openvpn-auth.service ]; then cp docs/examples/openvpn-auth.service $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/openvpn-auth.service; fi
	cp docs/configuration.md docs/openvpn-server.md docs/troubleshooting.md $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/docs/
	tar -C $(RELEASE_TMP) -czf $(BINDIR)/$(BINARY)_$(VERSION_NO_V)_linux_arm64.tar.gz $(BINARY)_$(VERSION_NO_V)_linux_arm64
	$(MAKE) build-lambda
	cp lambda-router/lambda-amd64.zip $(BINDIR)/lambda-router_$(VERSION_NO_V)_linux_amd64.zip
	cp lambda-router/lambda-arm64.zip $(BINDIR)/lambda-router_$(VERSION_NO_V)_linux_arm64.zip
	cd $(BINDIR) && sha256sum $(BINARY)_$(VERSION_NO_V)_linux_amd64.tar.gz $(BINARY)_$(VERSION_NO_V)_linux_arm64.tar.gz lambda-router_$(VERSION_NO_V)_linux_amd64.zip lambda-router_$(VERSION_NO_V)_linux_arm64.zip > checksums.txt

# Build Lambda Router binaries for AWS Lambda (linux/arm64 + linux/amd64)
build-lambda:
	cd lambda-router && GOCACHE=$(GO_BUILD_CACHE) GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap . && zip lambda-arm64.zip bootstrap && rm bootstrap
	cd lambda-router && GOCACHE=$(GO_BUILD_CACHE) GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap . && zip lambda-amd64.zip bootstrap && rm bootstrap

# --- PKI Management (offline, for AWS deployments) ---
PKI_REGION ?= eu-west-1
PKI_PREFIX ?= openvpn-auth-aws

pki-init:
	./scripts/pki.sh init

pki-tls-crypt:
	./scripts/pki.sh tls-crypt $(if $(FORCE),--force,)

pki-client:
	@test -n "$(CN)" || (echo "Usage: make pki-client CN=user@example.com" && exit 1)
	./scripts/pki.sh client "$(CN)"

pki-upload:
	./scripts/pki.sh upload --region "$(PKI_REGION)" --prefix "$(PKI_PREFIX)"

pki-client-config:
	@test -n "$(CN)" || (echo "Usage: make pki-client-config CN=user@example.com REMOTE=<host|ip>[:port]" && exit 1)
	@test -n "$(REMOTE)" || (echo "Usage: make pki-client-config CN=user@example.com REMOTE=<host|ip>[:port]" && exit 1)
	./scripts/pki.sh client-config "$(CN)" --remote "$(REMOTE)"
