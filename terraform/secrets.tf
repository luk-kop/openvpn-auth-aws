# --- PKI Secrets (populated by scripts/pki.sh upload) ---

resource "aws_secretsmanager_secret" "pki" {
  for_each = toset(["ca-cert", "server-cert", "server-key", "tls-crypt-key"])

  name                    = "${var.project_name}/pki/${each.key}"
  description             = "OpenVPN PKI: ${each.key}"
  recovery_window_in_days = 0

  tags = {
    Project = var.project_name
  }
}
