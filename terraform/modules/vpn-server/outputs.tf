output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.openvpn.id
}

output "private_ip" {
  description = "EC2 private IP"
  value       = aws_instance.openvpn.private_ip
}

output "public_ip" {
  description = "EC2 public IP (EIP if created, otherwise instance public IP)"
  value       = var.ec2_create_eip ? aws_eip.openvpn[0].public_ip : aws_instance.openvpn.public_ip
}

output "instance_profile_name" {
  description = "IAM instance profile name"
  value       = aws_iam_instance_profile.daemon.name
}
