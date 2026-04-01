# --- Network Load Balancer (multi-instance OpenVPN traffic) ---

resource "aws_lb" "this" {
  name               = "${var.project_name}-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = var.subnet_ids

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
    protocol = "TCP"
    port     = each.value.daemon_port
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
