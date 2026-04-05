output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.openvpn.name
}

output "asg_arn" {
  description = "Auto Scaling Group ARN"
  value       = aws_autoscaling_group.openvpn.arn
}

output "launch_template_id" {
  description = "Launch template ID"
  value       = aws_launch_template.openvpn.id
}

output "instance_profile_name" {
  description = "IAM instance profile name"
  value       = aws_iam_instance_profile.daemon.name
}

output "target_group_arns" {
  description = "Map of listener key to ALB Target Group ARN (empty when create_target_groups = false)"
  value       = var.create_target_groups ? { for k, tg in aws_lb_target_group.this : k => tg.arn } : {}
}

output "eip_public_ip" {
  description = "Elastic IP address of the VPN server (null when enable_eip_association = false)"
  value       = var.enable_eip_association ? aws_eip.vpn[0].public_ip : null
}

output "eip_allocation_id" {
  description = "Elastic IP allocation ID (null when enable_eip_association = false)"
  value       = var.enable_eip_association ? aws_eip.vpn[0].allocation_id : null
}
