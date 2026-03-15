#!/usr/bin/env bash
#
# Offline PKI management for OpenVPN server.
# Generates CA, server and client certificates using easy-rsa in a Docker container.
# Uploads PKI artifacts to AWS Secrets Manager for EC2 boot-time retrieval.
#
# Usage:
#   ./scripts/pki.sh init                                     Initialize CA + server cert + DH + ta.key
#   ./scripts/pki.sh client <common-name>                     Generate a client certificate
#   ./scripts/pki.sh upload --region <r> --prefix <p>         Upload PKI to Secrets Manager
#   ./scripts/pki.sh client-config <cn> --remote <host|ip>[:port]  Generate .ovpn client config
#
set -euo pipefail

PKI_DIR="${PKI_DIR:-pki}"
EASYRSA_IMAGE="alpine:latest"

# easy-rsa parameters matching production server config
EASYRSA_ALGO="ec"
EASYRSA_CURVE="secp384r1"
EASYRSA_DIGEST="sha384"
EASYRSA_CA_EXPIRE="3650"
EASYRSA_CERT_EXPIRE="825"

die() { echo "ERROR: $*" >&2; exit 1; }

cmd_init() {
  if [ -d "$PKI_DIR/pki" ]; then
    die "PKI already initialized at $PKI_DIR/pki. Remove it first to reinitialize."
  fi

  echo "==> Initializing PKI (CA + server cert + ta.key)..."
  mkdir -p "$PKI_DIR"

  docker run --rm \
    -v "$(cd "$PKI_DIR" && pwd):/pki" \
    -e EASYRSA_BATCH=1 \
    "$EASYRSA_IMAGE" sh -c "
    apk add --no-cache easy-rsa openvpn openssl

    cd /pki

    # Configure easy-rsa
    cat > vars <<VARS
set_var EASYRSA_ALGO      $EASYRSA_ALGO
set_var EASYRSA_CURVE     $EASYRSA_CURVE
set_var EASYRSA_DIGEST    $EASYRSA_DIGEST
set_var EASYRSA_CA_EXPIRE $EASYRSA_CA_EXPIRE
set_var EASYRSA_CERT_EXPIRE $EASYRSA_CERT_EXPIRE
set_var EASYRSA_REQ_CN    "OpenVPN-CA"
VARS
    cp vars /pki/vars

    /usr/share/easy-rsa/easyrsa init-pki
    cp /pki/vars pki/vars
    /usr/share/easy-rsa/easyrsa build-ca nopass
    EASYRSA_REQ_CN=server /usr/share/easy-rsa/easyrsa gen-req server nopass
    /usr/share/easy-rsa/easyrsa sign-req server server

    openvpn --genkey tls-auth /pki/ta.key

    # Strip human-readable header from certs (keep only PEM block)
    openssl x509 -in pki/ca.crt > /pki/ca.crt
    openssl x509 -in pki/issued/server.crt > /pki/server.crt
    cp pki/private/server.key /pki/server.key

    chown -R $(id -u):$(id -g) /pki
  "

  echo ""
  echo "==> PKI initialized at $PKI_DIR/"
  echo "    CA cert:     $PKI_DIR/ca.crt"
  echo "    Server cert: $PKI_DIR/server.crt"
  echo "    Server key:  $PKI_DIR/server.key"
  echo "    TLS auth:    $PKI_DIR/ta.key"
  echo ""
  echo "Next: make pki-upload to store in AWS Secrets Manager"
}

cmd_client() {
  local cn="${1:?Usage: pki.sh client <common-name>}"

  [ -d "$PKI_DIR/pki" ] || die "PKI not initialized. Run: make pki-init"

  echo "==> Generating client certificate for CN=$cn..."

  docker run --rm \
    -v "$(cd "$PKI_DIR" && pwd):/pki" \
    -e EASYRSA_BATCH=1 \
    "$EASYRSA_IMAGE" sh -c "
    apk add --no-cache easy-rsa openssl
    cd /pki
    cp vars pki/vars
    EASYRSA_REQ_CN='$cn' /usr/share/easy-rsa/easyrsa build-client-full '$cn' nopass

    # Strip header, copy to top-level clients dir
    mkdir -p /pki/clients
    openssl x509 -in pki/issued/'$cn'.crt > /pki/clients/'$cn'.crt
    cp pki/private/'$cn'.key /pki/clients/'$cn'.key

    chown -R $(id -u):$(id -g) /pki/clients
  "

  echo ""
  echo "==> Client certificate generated:"
  echo "    Cert: $PKI_DIR/clients/$cn.crt"
  echo "    Key:  $PKI_DIR/clients/$cn.key"
  echo ""
  echo "Next: make pki-client-config CN=$cn REMOTE=vpn.example.com"
}

cmd_upload() {
  local region="" prefix=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --region) region="$2"; shift 2 ;;
      --prefix) prefix="$2"; shift 2 ;;
      *) die "Unknown option: $1" ;;
    esac
  done

  [ -n "$region" ] || die "Missing --region"
  [ -n "$prefix" ] || die "Missing --prefix"

  for file in ca.crt server.crt server.key ta.key; do
    [ -f "$PKI_DIR/$file" ] || die "Missing $PKI_DIR/$file. Run: make pki-init"
  done

  echo "==> Uploading PKI artifacts to Secrets Manager (region=$region, prefix=$prefix)..."

  upload_secret() {
    local name="$1" file="$2"
    local secret_id="$prefix/pki/$name"
    local value
    value=$(cat "$file")

    if aws secretsmanager describe-secret --region "$region" --secret-id "$secret_id" >/dev/null 2>&1; then
      aws secretsmanager put-secret-value \
        --region "$region" \
        --secret-id "$secret_id" \
        --secret-string "$value" \
        --output text --query Name | cat
      echo "    Updated: $secret_id"
    else
      aws secretsmanager create-secret \
        --region "$region" \
        --name "$secret_id" \
        --secret-string "$value" \
        --output text --query Name | cat
      echo "    Created: $secret_id"
    fi
  }

  upload_secret "ca-cert"     "$PKI_DIR/ca.crt"
  upload_secret "server-cert" "$PKI_DIR/server.crt"
  upload_secret "server-key"  "$PKI_DIR/server.key"
  upload_secret "ta-key"      "$PKI_DIR/ta.key"

  echo ""
  echo "==> Upload complete. Secrets stored under: $prefix/pki/*"
}

cmd_client_config() {
  local cn="${1:?Usage: pki.sh client-config <common-name> --remote <host|ip>[:port]}"
  shift
  local remote="" proto="udp"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --remote) remote="$2"; shift 2 ;;
      --proto)  proto="$2"; shift 2 ;;
      *) die "Unknown option: $1" ;;
    esac
  done

  [ -n "$remote" ] || die "Missing --remote"
  [ -f "$PKI_DIR/ca.crt" ] || die "Missing $PKI_DIR/ca.crt. Run: make pki-init"
  [ -f "$PKI_DIR/clients/$cn.crt" ] || die "Missing $PKI_DIR/clients/$cn.crt. Run: make pki-client CN=$cn"
  [ -f "$PKI_DIR/clients/$cn.key" ] || die "Missing $PKI_DIR/clients/$cn.key"

  # Parse host:port from --remote
  local host port
  if [[ "$remote" == *:* ]]; then
    host="${remote%:*}"
    port="${remote##*:}"
  else
    host="$remote"
    port="1194"
  fi

  local ca_cert server_ta client_cert client_key
  ca_cert=$(cat "$PKI_DIR/ca.crt")
  client_cert=$(cat "$PKI_DIR/clients/$cn.crt")
  client_key=$(cat "$PKI_DIR/clients/$cn.key")

  mkdir -p "$PKI_DIR/clients"
  local outfile="$PKI_DIR/clients/$cn.ovpn"

  cat > "$outfile" <<EOF
client
dev tun
proto $proto
remote $host $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3

cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305

<ca>
$ca_cert
</ca>

<cert>
$client_cert
</cert>

<key>
$client_key
</key>
EOF

  # Append tls-auth if ta.key exists
  if [ -f "$PKI_DIR/ta.key" ]; then
    local ta_key
    ta_key=$(cat "$PKI_DIR/ta.key")
    cat >> "$outfile" <<EOF

key-direction 1
<tls-auth>
$ta_key
</tls-auth>
EOF
  fi

  echo "==> Client config written to: $outfile"
}

# --- Main ---
case "${1:-}" in
  init)           cmd_init ;;
  client)         shift; cmd_client "$@" ;;
  upload)         shift; cmd_upload "$@" ;;
  client-config)  shift; cmd_client_config "$@" ;;
  *)
    echo "Usage: $0 {init|client|upload|client-config}"
    echo ""
    echo "Commands:"
    echo "  init                                     Initialize CA + server cert + DH + ta.key"
    echo "  client <common-name>                     Generate a client certificate"
    echo "  upload --region <r> --prefix <p>          Upload PKI to Secrets Manager"
    echo "  client-config <cn> --remote <host|ip>[:port]  Generate .ovpn client config"
    exit 1
    ;;
esac
