# --- Daemon Security Group ---

resource "aws_security_group" "daemon" {
  count       = var.deploy_compute ? 1 : 0
  name        = "${var.project_name}-daemon"
  description = "OpenVPN auth daemon - allows VPN clients and ALB callbacks"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-daemon"
  }
}

resource "aws_vpc_security_group_ingress_rule" "daemon_from_alb_udp" {
  count                        = var.deploy_compute ? 1 : 0
  security_group_id            = aws_security_group.daemon[0].id
  description                  = "ALB callback to UDP daemon"
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  referenced_security_group_id = module.alb[0].alb_security_group_id
}

resource "aws_vpc_security_group_ingress_rule" "daemon_from_alb_tcp" {
  count                        = var.deploy_compute ? 1 : 0
  security_group_id            = aws_security_group.daemon[0].id
  description                  = "ALB callback to TCP daemon"
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
  referenced_security_group_id = module.alb[0].alb_security_group_id
}

resource "aws_vpc_security_group_ingress_rule" "openvpn_udp" {
  for_each = var.deploy_compute ? toset(var.openvpn_allowed_cidrs) : toset([])

  security_group_id = aws_security_group.daemon[0].id
  description       = "OpenVPN UDP from ${each.value}"
  from_port         = var.openvpn_udp_port
  to_port           = var.openvpn_udp_port
  ip_protocol       = "udp"
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "openvpn_tcp" {
  for_each = var.deploy_compute ? toset(var.openvpn_allowed_cidrs) : toset([])

  security_group_id = aws_security_group.daemon[0].id
  description       = "OpenVPN TCP from ${each.value}"
  from_port         = var.openvpn_tcp_port
  to_port           = var.openvpn_tcp_port
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each = var.deploy_compute ? toset(var.ssh_allowed_cidrs) : toset([])

  security_group_id = aws_security_group.daemon[0].id
  description       = "SSH from ${each.value}"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value
}

#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "daemon_all" {
  count             = var.deploy_compute ? 1 : 0
  security_group_id = aws_security_group.daemon[0].id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
