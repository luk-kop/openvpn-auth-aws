# --- Cognito ---

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = module.cognito.user_pool_id
}

output "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = module.cognito.user_pool_arn
}

output "cognito_client_id" {
  description = "Cognito User Pool Client ID"
  value       = module.cognito.client_id
}

output "cognito_domain_url" {
  description = "Cognito hosted UI domain URL"
  value       = module.cognito.domain_url
}

output "cognito_token_endpoint" {
  description = "Cognito OAuth2 token endpoint"
  value       = module.cognito.token_endpoint
}

output "cognito_issuer_url" {
  description = "Cognito issuer URL for JWT validation"
  value       = module.cognito.issuer_url
}

# --- API Gateway ---

output "api_gateway_url" {
  description = "API Gateway base URL (use as --api-gateway-url)"
  value       = var.cognito_only ? null : module.lambda_api[0].api_gateway_url
}

output "lambda_redirect_uri" {
  description = "OAuth2 redirect URI (Cognito → Lambda callback)"
  value       = var.cognito_only ? null : module.lambda_api[0].lambda_redirect_uri
}

# --- Secrets ---

output "hmac_secret_arn" {
  description = "Secrets Manager ARN for HMAC secret (use as --hmac-secret-arn)"
  value       = var.cognito_only ? null : aws_secretsmanager_secret.hmac[0].arn
}

# --- EC2 ---

output "ec2_instance_id" {
  description = "OpenVPN EC2 instance ID"
  value       = var.cognito_only ? null : module.vpn_server[0].instance_id
}

output "ec2_private_ip" {
  description = "OpenVPN EC2 private IP"
  value       = var.cognito_only ? null : module.vpn_server[0].private_ip
}

output "ec2_public_ip" {
  description = "OpenVPN EC2 public IP (EIP if created, otherwise instance public IP)"
  value       = var.cognito_only ? null : module.vpn_server[0].public_ip
}

output "daemon_instance_profile_name" {
  description = "IAM instance profile name for the daemon EC2 instance"
  value       = var.cognito_only ? null : module.vpn_server[0].instance_profile_name
}

output "daemon_security_group_id" {
  description = "Security group ID for the daemon EC2 instance"
  value       = var.cognito_only ? null : aws_security_group.daemon[0].id
}

output "ssm_session_command" {
  description = "AWS CLI command to start an SSM session"
  value       = var.cognito_only ? null : "aws ssm start-session --target ${module.vpn_server[0].instance_id} --region ${var.aws_region}"
}

# --- Daemon CLI flags ---

output "daemon_flags" {
  description = "CLI flags for openvpn-auth-daemon"
  value = var.cognito_only ? null : join(" \\\n  ", [
    "--api-gateway-url=${module.lambda_api[0].api_gateway_url}",
    "--hmac-secret-arn=${aws_secretsmanager_secret.hmac[0].arn}",
    "--cognito-user-pool-id=${module.cognito.user_pool_id}",
    "--cognito-token-endpoint=${module.cognito.token_endpoint}",
    "--cognito-client-id=${module.cognito.client_id}",
    "--cognito-redirect-uri=${module.lambda_api[0].lambda_redirect_uri}",
    "--cognito-issuer-url=${module.cognito.issuer_url}",
    "--aws-region=${var.aws_region}",
    "--required-group=${var.cognito_vpn_group_name}",
    "--callback-port=${var.daemon_callback_port}",
  ])
}
