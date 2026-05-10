# PKI Management

## Overview

OpenVPN requires TLS certificates for transport security. This project uses an **offline PKI** model:

- CA and certificates are generated locally (never on the server)
- PKI artifacts are stored in AWS Secrets Manager
- EC2 instances pull certificates from Secrets Manager at boot
- Client `.ovpn` configs are generated locally with inline certs

This keeps the CA private key off production infrastructure and makes certificate management auditable and reproducible.

## Prerequisites

- Docker (for easy-rsa container)
- AWS CLI (for Secrets Manager upload)
- `make` (for convenience targets)

All `make pki-*` commands must be run from the repository root.

## Quick Start

```bash
# 1. Generate CA + server cert + TLS crypt key
make pki-init

# 2. Deploy Cognito + Secrets Manager only (no ALB/EC2 yet)
cd terraform && terraform apply -var="cost_saving_mode=true" && cd ..

# 3. Upload PKI artifacts to the secrets Terraform created
make pki-upload PKI_REGION=eu-west-1 PKI_PREFIX=openvpn-auth-aws

# 4. Deploy the full stack (EC2 boots with certs already in Secrets Manager)
cd terraform && terraform apply -var="cost_saving_mode=false" && cd ..

# 5. Generate a client certificate
make pki-client CN=user@example.com

# 6. Generate .ovpn config file
make pki-client-config CN=user@example.com REMOTE=vpn.example.com:1194

# 7. Connect
sudo openvpn --config pki/clients/user@example.com.ovpn
```

## Commands

### `make pki-init`

Initializes a new PKI in the `pki/` directory:

- CA certificate and private key (EC secp384r1, 10-year expiry)
- Server certificate signed by CA (825-day expiry)
- TLS crypt static key (`tls-crypt.key`)

DH parameters are generated on the EC2 instance at boot (not a secret, just large primes).

Uses easy-rsa inside a Docker container for portability.

Output files:

| File | Description |
|------|-------------|
| `pki/ca.crt` | CA certificate (distribute to clients) |
| `pki/server.crt` | Server certificate |
| `pki/server.key` | Server private key |
| `pki/tls-crypt.key` | TLS crypt key (distribute to clients) |
| `pki/pki/` | easy-rsa internal state (needed for issuing client certs) |

### `make pki-tls-crypt`

Generates only `pki/tls-crypt.key` without touching the CA or server certificates. Useful when migrating from `tls-auth` (`ta.key`) to `tls-crypt` on an existing PKI, or when rotating the shared control-channel key.

```bash
make pki-tls-crypt          # refuses to overwrite an existing non-empty key
make pki-tls-crypt FORCE=1  # rotate (invalidates existing client .ovpn files)
```

The `tls-crypt` shared key is symmetric and reaches both sides from the same local `pki/tls-crypt.key`:

- **Server**: `make pki-upload` pushes it into Secrets Manager; `fetch-pki.sh` retrieves it at instance boot.
- **Clients**: `make pki-client-config` inlines it into each user's `.ovpn` as a `<tls-crypt>` block.

After generating, run `make pki-upload` and either restart `openvpn-server@udp` / `openvpn-server@tcp` on the instance (after re-running `/usr/local/bin/fetch-pki.sh`) or replace the EC2 instance.

When rotating with `FORCE=1`, every previously distributed `.ovpn` file embeds the old key and will fail to connect once the server picks up the new one. Existing client certificates and keys remain valid — only the `.ovpn` wrappers need regenerating:

```bash
make pki-tls-crypt FORCE=1
make pki-upload
# For each existing user:
make pki-client-config CN=<email> REMOTE=<host>
# Redistribute the new .ovpn files
```

### `make pki-client CN=<email>`

Generates a client certificate signed by the existing CA.

```bash
make pki-client CN=alice@example.com
```

Output: `pki/clients/alice@example.com.crt` and `pki/clients/alice@example.com.key`

The CN should match the user's email in Cognito if `--cn-cross-check` is enabled (default).

### `make pki-upload`

Uploads PKI artifacts to AWS Secrets Manager.

```bash
make pki-upload PKI_REGION=eu-west-1 PKI_PREFIX=openvpn-auth-aws
```

Defaults: `PKI_REGION=eu-west-1`, `PKI_PREFIX=openvpn-auth-aws`

Creates or updates these secrets:

| Secret ID | Content |
|-----------|---------|
| `{prefix}/pki/ca-cert` | CA certificate (PEM) |
| `{prefix}/pki/server-cert` | Server certificate (PEM) |
| `{prefix}/pki/server-key` | Server private key (PEM) |
| `{prefix}/pki/tls-crypt-key` | TLS crypt static key |

Secrets Manager secrets are always created by Terraform, including when `cost_saving_mode=true`; this command populates them with `put-secret-value`.

### `make pki-client-config CN=<email> REMOTE=<host|ip>[:port]`

Generates a ready-to-use `.ovpn` file with inline certificates.
The generated config includes `push-peer-info` and `setenv IV_SSO webauth`, which are recommended for OpenVPN 2.x CLI clients so WebAuth support metadata is sent to the server consistently in the tested flow.

```bash
make pki-client-config CN=alice@example.com REMOTE=vpn.example.com:1194
```

Output: `pki/clients/alice@example.com.ovpn`

The file includes inline `<ca>`, `<cert>`, `<key>`, and `<tls-crypt>` blocks — no separate files needed.

## Deployment Workflow

### First-time setup

```bash
# 1. Initialize PKI
make pki-init

# 2. Deploy Cognito + Secrets Manager only (no ALB/EC2 yet)
cd terraform && terraform apply -var="cost_saving_mode=true" && cd ..

# 3. Upload PKI artifacts to the secrets Terraform created
make pki-upload

# 4. Deploy the full stack (EC2 boots with certs already in place)
cd terraform && terraform apply -var="cost_saving_mode=false" && cd ..
```

### Adding a new user

```bash
make pki-client CN=bob@example.com
make pki-client-config CN=bob@example.com REMOTE=vpn.example.com
# Send pki/clients/bob@example.com.ovpn to the user
```

### Certificate renewal

```bash
# Remove old PKI and reinitialize
rm -rf pki/
make pki-init
make pki-upload
# Terminate EC2 instance to pick up new certs
# Generate new client certs (old ones are invalidated with old CA)
```

## Security Considerations

- The `pki/` directory contains the CA private key. **Never commit it to git** (already in `.gitignore`).
- Store `pki/` securely (encrypted volume, password manager, etc.) — whoever has the CA key can issue valid client certificates.
- Server private key is stored in Secrets Manager with encryption at rest (AWS KMS).
- EC2 instance role has `secretsmanager:GetSecretValue` scoped to the PKI secrets only.
- Consider rotating certificates periodically (e.g., annually).

## Lab vs Production

| Aspect | Lab (`make stack-up`) | Production (Terraform) |
|--------|----------------------|------------------------|
| PKI generation | `lab/setup.sh` (inline in Docker) | `make pki-init` (offline) |
| Cert storage | Inline in `openvpn.conf` / `client.ovpn` | AWS Secrets Manager |
| CA algorithm | RSA (easy-rsa default) | EC secp384r1 |
| DH | `dh none` (ECDH only) | `dh none` (ECDH only) |
| TLS crypt | `tls-crypt.key` | `tls-crypt.key` |
| Client certs | Auto-generated (`user@example.com`) | Per-user via `make pki-client` |

Lab and production PKI are completely independent — lab uses its own throwaway CA generated by `lab/setup.sh`.
