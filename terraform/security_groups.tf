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

resource "aws_vpc_security_group_ingress_rule" "daemon_from_alb" {
  for_each = var.deploy_compute ? var.openvpn_listeners : {}

  security_group_id            = aws_security_group.daemon[0].id
  description                  = "ALB callback to ${each.key} daemon"
  from_port                    = each.value.daemon_port
  to_port                      = each.value.daemon_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = module.alb[0].alb_security_group_id
}

resource "aws_vpc_security_group_ingress_rule" "openvpn" {
  for_each = var.deploy_compute ? {
    for pair in setproduct(keys(var.openvpn_listeners), var.openvpn_allowed_cidrs) :
    "${pair[0]}-${pair[1]}" => {
      listener = var.openvpn_listeners[pair[0]]
      cidr     = pair[1]
      proto    = pair[0]
    }
  } : {}

  security_group_id = aws_security_group.daemon[0].id
  description       = "OpenVPN ${each.value.proto} from ${each.value.cidr}"
  from_port         = each.value.listener.openvpn_port
  to_port           = each.value.listener.openvpn_port
  ip_protocol       = each.value.listener.ip_protocol
  cidr_ipv4         = each.value.cidr
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
