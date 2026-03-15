output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.openvpn.id
}

output "private_ip" {
  description = "EC2 private IP"
  value       = aws_instance.openvpn.private_ip
}

output "instance_profile_name" {
  description = "IAM instance profile name"
  value       = aws_iam_instance_profile.daemon.name
}

output "tg_udp_arn" {
  description = "ALB Target Group ARN for the UDP daemon (port 8080)"
  value       = aws_lb_target_group.udp.arn
}

output "tg_tcp_arn" {
  description = "ALB Target Group ARN for the TCP daemon (port 8081)"
  value       = aws_lb_target_group.tcp.arn
}
