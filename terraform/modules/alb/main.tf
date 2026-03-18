# --- ALB Security Group ---

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb"
  description = "ALB - allows HTTPS inbound, outbound to daemon target groups"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-alb"
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from internet"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_daemon" {
  for_each = var.listeners

  security_group_id            = aws_security_group.alb.id
  description                  = "ALB to ${each.key} daemon"
  from_port                    = each.value.daemon_port
  to_port                      = each.value.daemon_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.daemon_security_group_id
}

#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "alb_to_cognito" {
  security_group_id = aws_security_group.alb.id
  description       = "ALB to Cognito token endpoint (required by authenticate-cognito action)"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

# --- Application Load Balancer ---

#trivy:ignore:AVD-AWS-0053
resource "aws_lb" "this" {
  name                       = "${var.project_name}-alb"
  internal                   = false
  load_balancer_type         = "application"
  subnets                    = var.subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# --- HTTPS Listener ---
# Default action returns 404 for unmatched paths.
# Path-specific listener rules (created in the root module) chain
# authenticate-cognito → forward to the appropriate VPN server target group.

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}
