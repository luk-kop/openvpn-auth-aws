# --- NLB Security Group Rules ---

resource "aws_vpc_security_group_ingress_rule" "nlb_openvpn" {
  for_each = {
    for pair in setproduct(keys(var.listeners), var.openvpn_allowed_cidrs) :
    "${pair[0]}-${pair[1]}" => {
      listener = var.listeners[pair[0]]
      cidr     = pair[1]
      proto    = pair[0]
    }
  }

  security_group_id = var.nlb_security_group_id
  description       = "OpenVPN ${each.value.proto} from ${each.value.cidr}"
  from_port         = each.value.listener.openvpn_port
  to_port           = each.value.listener.openvpn_port
  ip_protocol       = each.value.listener.ip_protocol
  cidr_ipv4         = each.value.cidr
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_ec2_openvpn" {
  for_each = var.listeners

  security_group_id            = var.nlb_security_group_id
  description                  = "NLB to ${each.key} OpenVPN targets"
  from_port                    = each.value.openvpn_port
  to_port                      = each.value.openvpn_port
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = var.ec2_security_group_id
}

resource "aws_vpc_security_group_egress_rule" "nlb_to_ec2_health_check" {
  for_each = var.listeners

  security_group_id            = var.nlb_security_group_id
  description                  = "Health check to ${each.key} daemon"
  from_port                    = each.value.daemon_port
  to_port                      = each.value.daemon_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.ec2_security_group_id
}

# --- Network Load Balancer (multi-instance OpenVPN traffic) ---

resource "aws_lb" "this" {
  name               = "${var.project_name}-nlb"
  internal           = false #trivy:ignore:aws-elb-alb-not-public -- public NLB for VPN client access
  load_balancer_type = "network"
  subnets            = var.subnet_ids
  security_groups    = [var.nlb_security_group_id]

  tags = {
    Name    = "${var.project_name}-nlb"
    Project = var.project_name
  }
}

# --- Route53 alias for NLB ---

resource "aws_route53_record" "nlb" {
  zone_id = var.route53_hosted_zone_id
  name    = var.nlb_domain_name
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}

# --- Target Groups (one per listener) ---

resource "aws_lb_target_group" "this" {
  for_each = var.listeners

  name        = "${var.project_name}-nlb-${each.key}"
  port        = each.value.openvpn_port
  protocol    = upper(each.value.ip_protocol)
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled  = true
    protocol = "HTTP"
    port     = each.value.daemon_port
    path     = "/healthz"
    matcher  = "200"
  }

  tags = {
    Project = var.project_name
  }
}

# --- Listeners (one per protocol) ---

resource "aws_lb_listener" "this" {
  for_each = var.listeners

  load_balancer_arn = aws_lb.this.arn
  port              = each.value.openvpn_port
  protocol          = upper(each.value.ip_protocol)

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[each.key].arn
  }
}
