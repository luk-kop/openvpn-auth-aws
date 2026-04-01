output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.this.arn
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  description = "Hosted zone ID of the Application Load Balancer (for Route53 alias records)"
  value       = aws_lb.this.zone_id
}

output "listener_arn" {
  description = "ARN of the HTTPS listener (used to attach path-based listener rules)"
  value       = aws_lb_listener.https.arn
}

output "alb_security_group_id" {
  description = "Security group ID of the ALB (used to scope daemon ingress rules)"
  value       = aws_security_group.alb.id
}

output "daemon_security_group_id" {
  description = "Security group ID for the daemon EC2 instance"
  value       = aws_security_group.daemon.id
}

output "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN (pass-through for listener rules)"
  value       = var.cognito_user_pool_arn
}

output "cognito_user_pool_client_id" {
  description = "Cognito User Pool Client ID (pass-through for listener rules)"
  value       = var.cognito_user_pool_client_id
}

output "cognito_user_pool_domain" {
  description = "Cognito hosted UI domain (pass-through for listener rules)"
  value       = var.cognito_user_pool_domain
}

output "acm_certificate_arn" {
  description = "ARN of the ACM certificate"
  value       = aws_acm_certificate.this.arn
}
