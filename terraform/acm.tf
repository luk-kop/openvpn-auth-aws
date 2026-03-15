# --- ACM Certificate (DNS validation via Route53) ---

resource "aws_acm_certificate" "this" {
  count             = var.deploy_compute ? 1 : 0
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
  for_each = var.deploy_compute ? {
    for dvo in aws_acm_certificate.this[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id = var.route53_hosted_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

# --- Route53 alias for ALB ---

resource "aws_route53_record" "alb" {
  count   = var.deploy_compute ? 1 : 0
  zone_id = var.route53_hosted_zone_id
  name    = var.alb_domain_name
  type    = "A"

  alias {
    name                   = module.alb[0].alb_dns_name
    zone_id                = module.alb[0].alb_zone_id
    evaluate_target_health = true
  }
}

resource "aws_acm_certificate_validation" "this" {
  count                   = var.deploy_compute ? 1 : 0
  certificate_arn         = aws_acm_certificate.this[0].arn
  validation_record_fqdns = [for r in aws_route53_record.acm_validation : r.fqdn]
}
