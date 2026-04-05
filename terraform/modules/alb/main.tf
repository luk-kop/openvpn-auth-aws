# --- ACM Certificate (DNS validation via Route53) ---

resource "aws_acm_certificate" "this" {
  domain_name       = var.alb_domain_name
  validation_method = "DNS"

  tags = {
    Name = "${var.project_name}-alb"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.this.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  }

  zone_id = var.route53_hosted_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.acm_validation : r.fqdn]
}

# --- ALB Security Group Rules ---

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = var.alb_security_group_id
  description       = "HTTPS from internet"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_daemon" {
  for_each = var.listeners

  security_group_id            = var.alb_security_group_id
  description                  = "ALB to ${each.key} daemon"
  from_port                    = each.value.daemon_port
  to_port                      = each.value.daemon_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.ec2_security_group_id
}

#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "alb_to_cognito" {
  security_group_id = var.alb_security_group_id
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
  security_groups            = [var.alb_security_group_id]
  drop_invalid_header_fields = true

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# --- Route53 alias for ALB ---

resource "aws_route53_record" "alb" {
  zone_id = var.route53_hosted_zone_id
  name    = var.alb_domain_name
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}

# --- HTTPS Listener ---
# Default action returns 404 for unmatched paths.
# Path-specific listener rules are created either statically (vpn-server module)
# or dynamically (instance-routing Lambda).

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.this.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}
