# --- Lambda Security Group ---

resource "aws_security_group" "lambda" {
  count       = var.cognito_only ? 0 : 1
  name        = "${var.project_name}-lambda"
  description = "Lambda function - allows outbound to daemon callback and AWS APIs"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "lambda_https" {
  count             = var.cognito_only ? 0 : 1
  security_group_id = aws_security_group.lambda[0].id
  description       = "HTTPS to AWS APIs"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "lambda_to_daemon" {
  count                        = var.cognito_only ? 0 : 1
  security_group_id            = aws_security_group.lambda[0].id
  description                  = "Callback to daemon"
  from_port                    = var.daemon_callback_port
  to_port                      = var.daemon_callback_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.daemon[0].id
}

# --- Daemon Security Group ---

resource "aws_security_group" "daemon" {
  count       = var.cognito_only ? 0 : 1
  name        = "${var.project_name}-daemon"
  description = "OpenVPN auth daemon - allows VPN clients and Lambda callbacks"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "daemon_from_lambda" {
  count                        = var.cognito_only ? 0 : 1
  security_group_id            = aws_security_group.daemon[0].id
  description                  = "Lambda callback"
  from_port                    = var.daemon_callback_port
  to_port                      = var.daemon_callback_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.lambda[0].id
}

resource "aws_vpc_security_group_ingress_rule" "openvpn" {
  for_each = var.cognito_only ? toset([]) : toset(var.openvpn_allowed_cidrs)

  security_group_id = aws_security_group.daemon[0].id
  description       = "OpenVPN from ${each.value}"
  from_port         = var.openvpn_port
  to_port           = var.openvpn_port
  ip_protocol       = var.openvpn_protocol
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each = var.cognito_only ? toset([]) : toset(var.ssh_allowed_cidrs)

  security_group_id = aws_security_group.daemon[0].id
  description       = "SSH from ${each.value}"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "daemon_all" {
  count             = var.cognito_only ? 0 : 1
  security_group_id = aws_security_group.daemon[0].id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
