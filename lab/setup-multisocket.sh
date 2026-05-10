#!/bin/bash
set -e

OVPN_DATA="./openvpn-data-multisocket"
RENEG_SEC="${RENEG_SEC:-600}"

echo "==> Setting up OpenVPN 2.7 multi-socket lab environment"

rm -rf "$OVPN_DATA"
mkdir -p "$OVPN_DATA"

echo "test-management-password" > "$OVPN_DATA/management-pw"
chmod 644 "$OVPN_DATA/management-pw"

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
  /usr/share/easy-rsa/easyrsa build-client-full udp-user@example.com nopass
  /usr/share/easy-rsa/easyrsa build-client-full tcp-user@example.com nopass
  openvpn --genkey tls-crypt /etc/openvpn/tls-crypt.key
  chown -R $(id -u):$(id -g) /etc/openvpn/pki
  chown $(id -u):$(id -g) /etc/openvpn/tls-crypt.key
"

CA_CERT=$(cat "$OVPN_DATA/pki/ca.crt")
SERVER_CERT=$(openssl x509 -in "$OVPN_DATA/pki/issued/server.crt")
SERVER_KEY=$(cat "$OVPN_DATA/pki/private/server.key")
UDP_CLIENT_CERT=$(openssl x509 -in "$OVPN_DATA/pki/issued/udp-user@example.com.crt")
UDP_CLIENT_KEY=$(cat "$OVPN_DATA/pki/private/udp-user@example.com.key")
TCP_CLIENT_CERT=$(openssl x509 -in "$OVPN_DATA/pki/issued/tcp-user@example.com.crt")
TCP_CLIENT_KEY=$(cat "$OVPN_DATA/pki/private/tcp-user@example.com.key")
TLS_CRYPT_KEY=$(cat "$OVPN_DATA/tls-crypt.key")

rm -rf "$OVPN_DATA/pki"

echo "==> Creating multi-socket OpenVPN server config..."
cat > "$OVPN_DATA/openvpn.conf" <<EOF
local 0.0.0.0 1194 udp
local 0.0.0.0 1195 tcp-server
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

# TLS renegotiation interval — use RENEG_SEC=30 for faster lab REAUTH capture.
reneg-sec $RENEG_SEC

management /run/openvpn/management.sock unix /etc/openvpn/management-pw
management-client-auth
management-hold
auth-user-pass-optional
hand-window 300

# Keep duplicate-cn disabled. This lab uses different CNs so listener behavior
# can be observed without duplicate-session eviction noise.

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

write_client_config() {
  local path="$1"
  local proto="$2"
  local port="$3"
  local cert="$4"
  local key="$5"

  cat > "$path" <<EOF
client
dev tun
proto $proto
remote localhost $port
resolv-retry infinite
nobind
persist-tun
remote-cert-tls server
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
$cert
</cert>

<key>
$key
</key>

<tls-crypt>
$TLS_CRYPT_KEY
</tls-crypt>
EOF
}

echo "==> Creating UDP and TCP client configs..."
write_client_config client-udp.ovpn udp 1194 "$UDP_CLIENT_CERT" "$UDP_CLIENT_KEY"
write_client_config client-tcp.ovpn tcp-client 1195 "$TCP_CLIENT_CERT" "$TCP_CLIENT_KEY"

echo ""
echo "==> Done"
echo "    Server config: $OVPN_DATA/openvpn.conf"
echo "    UDP client:    client-udp.ovpn"
echo "    TCP client:    client-tcp.ovpn"
echo ""
echo "Start:  docker compose -f docker-compose.multisocket.yml up -d"
echo "Verify: ./run-multisocket-verification.sh"
