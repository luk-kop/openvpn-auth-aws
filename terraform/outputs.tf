# --- Cognito ---

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = var.deploy_cognito ? module.cognito[0].user_pool_id : null
}

output "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN"
  value       = var.deploy_cognito ? module.cognito[0].user_pool_arn : null
}

output "cognito_client_id" {
  description = "Cognito User Pool Client ID"
  value       = var.deploy_cognito ? module.cognito[0].client_id : null
}

output "cognito_domain_url" {
  description = "Cognito hosted UI domain URL"
  value       = var.deploy_cognito ? module.cognito[0].domain_url : null
}

output "cognito_issuer_url" {
  description = "Cognito issuer URL for JWT validation"
  value       = var.deploy_cognito ? module.cognito[0].issuer_url : null
}

# --- ALB ---

output "alb_arn" {
  description = "ALB ARN"
  value       = var.deploy_compute ? module.alb[0].alb_arn : null
}

output "alb_dns_name" {
  description = "ALB DNS name (use as the base for callback URLs)"
  value       = var.deploy_compute ? module.alb[0].alb_dns_name : null
}

output "callback_urls" {
  description = "Full callback URLs per listener (e.g. {udp = \"https://...\", tcp = \"https://...\"})"
  value = var.deploy_compute ? {
    for k, _ in var.openvpn_listeners : k => "https://${var.alb_domain_name}/callback/${var.server_name}/${k}"
  } : null
}

output "vpn_public_ip" {
  description = "Elastic IP address of the VPN server"
  value       = var.deploy_compute ? aws_eip.vpn[0].public_ip : null
}

# --- ASG / EC2 ---

output "asg_name" {
  description = "Auto Scaling Group name for the OpenVPN server"
  value       = var.deploy_compute ? module.vpn_server[0].asg_name : null
}

output "launch_template_id" {
  description = "Launch template ID for the OpenVPN server"
  value       = var.deploy_compute ? module.vpn_server[0].launch_template_id : null
}

output "daemon_instance_profile_name" {
  description = "IAM instance profile name for the daemon EC2 instance"
  value       = var.deploy_compute ? module.vpn_server[0].instance_profile_name : null
}

output "daemon_security_group_id" {
  description = "Security group ID for the daemon EC2 instance"
  value       = var.deploy_compute ? aws_security_group.daemon[0].id : null
}

output "ssm_session_command" {
  description = "AWS CLI command to find the EC2 instance from ASG and start an SSM session"
  value       = var.deploy_compute ? "aws ssm start-session --target $(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names ${module.vpn_server[0].asg_name} --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text) --region ${var.aws_region}" : null
}
