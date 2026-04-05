output "alb_dns_name" {
  description = "ALB DNS name"
  value       = var.cost_saving_mode ? null : module.alb[0].alb_dns_name
}

output "alb_arn" {
  description = "ALB ARN"
  value       = var.cost_saving_mode ? null : module.alb[0].alb_arn
}

output "vpn_public_ip" {
  description = "Elastic IP of the VPN server (null in multi-instance or cost-saving mode)"
  value       = var.cost_saving_mode ? null : module.vpn_server[0].eip_public_ip
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = var.cost_saving_mode ? null : module.vpn_server[0].asg_name
}

output "nlb_dns_name" {
  description = "NLB DNS name (null in single-instance or cost-saving mode)"
  value       = var.multi_instance_mode && !var.cost_saving_mode ? module.nlb[0].nlb_dns_name : null
}

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

output "cognito_issuer_url" {
  description = "Cognito issuer URL for JWT validation"
  value       = module.cognito.issuer_url
}

output "callback_urls" {
  description = "Callback URLs per listener (static in single-instance mode)"
  value = var.cost_saving_mode ? null : (
    var.multi_instance_mode ? {
      note = "Dynamic — resolved per instance at boot from instance ID suffix"
      } : {
      for k, _ in var.openvpn_listeners :
      k => "https://${var.alb_domain_name}/callback/${var.server_name}/${k}"
    }
  )
}

output "ssm_session_command" {
  description = "AWS CLI command to find the VPN instance and start an SSM session"
  value       = var.cost_saving_mode ? null : "aws ec2 describe-instances --filters Name=tag:aws:autoscaling:groupName,Values=${module.vpn_server[0].asg_name} Name=instance-state-name,Values=running --query 'Reservations[0].Instances[0].InstanceId' --output text | xargs -I{} aws ssm start-session --target {}"
}
