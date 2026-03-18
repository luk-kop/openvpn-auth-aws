output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.openvpn.name
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
  description = "Map of listener key to ALB Target Group ARN"
  value       = { for k, tg in aws_lb_target_group.this : k => tg.arn }
}
