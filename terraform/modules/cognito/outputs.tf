output "user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = aws_cognito_user_pool.this.arn
}

output "client_id" {
  description = "Cognito User Pool Client ID"
  value       = aws_cognito_user_pool_client.this.id
}

output "client_secret" {
  description = "Cognito User Pool Client secret (required by ALB authenticate-cognito action)"
  value       = aws_cognito_user_pool_client.this.client_secret
  sensitive   = true
}

output "domain_url" {
  description = "Cognito hosted UI domain URL"
  value       = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.aws_region}.amazoncognito.com"
}

output "domain_fqdn" {
  description = "Cognito hosted UI domain FQDN (without https:// scheme, for ALB authenticate-cognito action)"
  value       = "${aws_cognito_user_pool_domain.this.domain}.auth.${var.aws_region}.amazoncognito.com"
}

output "issuer_url" {
  description = "Cognito issuer URL for JWT validation"
  value       = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}
