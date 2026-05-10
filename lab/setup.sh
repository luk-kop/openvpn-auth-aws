#!/bin/bash
set -e

OVPN_DATA="./openvpn-data"
RENEG_SEC="${RENEG_SEC:-600}"

echo "==> Setting up test OpenVPN environment"

mkdir -p "$OVPN_DATA"

# Generate management password
echo "test-management-password" > "$OVPN_DATA/management-pw"
chmod 644 "$OVPN_DATA/management-pw"

# Initialize PKI + generate all certs in one container run
# Run as root so apk/easyrsa can write freely, then chown to current user
echo "==> Initializing PKI and generating certificates..."
docker run --rm \
  -v "$(pwd)/$OVPN_DATA:/etc/openvpn" \
  -e EASYRSA_BATCH=1 \
  -e EASYRSA_CERT_EXPIRE=825 \
  alpine:latest sh -c "
  apk add --no-cache easy-rsa openvpn
  cd /etc/openvpn
  /usr/share/easy-rsa/easyrsa init-pki
  /usr/share/easy-rsa/easyrsa build-ca nopass
  EASYRSA_EXTRA_EXTS='subjectAltName=DNS:server,IP:127.0.0.1' \
    /usr/share/easy-rsa/easyrsa gen-req server nopass
  EASYRSA_EXTRA_EXTS='subjectAltName=DNS:server,IP:127.0.0.1' \
    /usr/share/easy-rsa/easyrsa sign-req server server
  /usr/share/easy-rsa/easyrsa build-client-full test-user@example.com nopass
  openvpn --genkey tls-crypt /etc/openvpn/tls-crypt.key
  chown -R $(id -u):$(id -g) /etc/openvpn/pki
  chown $(id -u):$(id -g) /etc/openvpn/tls-crypt.key
"

# Read generated certs
# Easy-RSA .crt files contain a human-readable header before the PEM block — strip it
CA_CERT=$(cat "$OVPN_DATA/pki/ca.crt")
SERVER_CERT=$(openssl x509 -in "$OVPN_DATA/pki/issued/server.crt")
SERVER_KEY=$(cat "$OVPN_DATA/pki/private/server.key")
CLIENT_CERT=$(openssl x509 -in "$OVPN_DATA/pki/issued/test-user@example.com.crt")
CLIENT_KEY=$(cat "$OVPN_DATA/pki/private/test-user@example.com.key")
TLS_CRYPT_KEY=$(cat "$OVPN_DATA/tls-crypt.key")

# pki/ is no longer needed — certs are embedded inline in the configs
rm -rf "$OVPN_DATA/pki"

# Server config with inline certs
echo "==> Creating OpenVPN server config..."
cat > "$OVPN_DATA/openvpn.conf" <<EOF
port 1194
proto udp
dev tun

tls-server
server 10.8.0.0 255.255.255.0
topology subnet

keepalive 10 120
persist-tun
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tls-version-min 1.2
verb 3

# TLS renegotiation interval — triggers CLIENT:REAUTH on management interface.
# Daemon re-checks user identity in Cognito on each renegotiation.
# Default is 3600s (1h). Lower value for faster testing of reauth flow.
reneg-sec $RENEG_SEC

# Management interface for auth daemon
management /run/openvpn/management.sock unix /etc/openvpn/management-pw
management-client-auth
management-hold

# Allow connection without username/password — identity comes from TLS certificate CN
auth-user-pass-optional

# Time allowed for browser-based auth to complete.
# MUST match daemon --hand-window (default 300s). If these differ, the shorter
# side will time out and kill the session before auth completes.
hand-window 300

# Do not add duplicate-cn. OpenVPN rejects duplicate certificate CNs by default;
# this project relies on that behavior for single-process duplicate protection.

# Disable finite-field DH; use ECDH/TLS named groups.
dh none
tls-crypt /etc/openvpn/tls-crypt.key

<ca>
$CA_CERT
</ca>

<cert>
$SERVER_CERT
</cert>

<key>
$SERVER_KEY
</key>
EOF

# Client config with inline certs
echo "==> Creating client config..."
cat > client.ovpn <<EOF
client
dev tun
proto udp
remote localhost 1194
resolv-retry infinite
nobind
persist-tun
remote-cert-tls server
verify-x509-name server name
verb 3
push-peer-info
setenv IV_SSO webauth
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tls-version-min 1.2

<ca>
$CA_CERT
</ca>

<cert>
$CLIENT_CERT
</cert>

<key>
$CLIENT_KEY
</key>

<tls-crypt>
$TLS_CRYPT_KEY
</tls-crypt>
EOF

echo ""
echo "==> Done"
echo "    Server config: $OVPN_DATA/openvpn.conf"
echo "    Client config: client.ovpn"
echo ""
echo "Start: docker compose up -d"
echo "Connect: sudo openvpn --config client.ovpn"
