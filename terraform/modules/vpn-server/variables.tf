variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "daemon_security_group_id" {
  description = "Security group ID for the daemon EC2 instance"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the EC2 instance"
  type        = string
}

variable "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN (for daemon IAM policy)"
  type        = string
}

variable "alb_arn" {
  description = "ALB ARN passed to daemon --alb-arn for JWT signer validation"
  type        = string
}

variable "callback_url_udp" {
  description = "Full callback URL for the UDP daemon (e.g. https://vpn-auth.example.com/callback/01/udp)"
  type        = string
}

variable "callback_url_tcp" {
  description = "Full callback URL for the TCP daemon (e.g. https://vpn-auth.example.com/callback/01/tcp)"
  type        = string
}

variable "daemon_binary_s3_uri" {
  description = "S3 URI for the daemon binary"
  type        = string
  default     = ""
}

# --- EC2 ---

variable "ec2_ami_id" {
  description = "Custom AMI ID. Leave empty for latest Ubuntu 24.04 LTS."
  type        = string
  default     = ""
}

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "ec2_key_name" {
  description = "SSH key pair name (optional if using SSM only)"
  type        = string
  default     = ""
}

variable "ec2_root_volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}

variable "eip_allocation_id" {
  description = "Pre-allocated Elastic IP allocation ID to associate after health checks pass"
  type        = string
}

# --- OpenVPN ---

variable "openvpn_udp_port" {
  description = "OpenVPN UDP listening port"
  type        = number
  default     = 1194
}

variable "openvpn_tcp_port" {
  description = "OpenVPN TCP listening port"
  type        = number
  default     = 1195
}

variable "openvpn_udp_client_cidr" {
  description = "VPN tunnel client CIDR for the UDP server"
  type        = string
  default     = "10.8.0.0/24"
}

variable "openvpn_tcp_client_cidr" {
  description = "VPN tunnel client CIDR for the TCP server"
  type        = string
  default     = "10.8.1.0/24"
}

variable "hand_window" {
  description = "Seconds allowed for browser-based auth. Used in both OpenVPN server config and daemon --hand-window flag to keep them in sync."
  type        = number
  default     = 300
}

variable "cognito_user_pool_id" {
  description = "Cognito User Pool ID passed to daemon --cognito-user-pool-id"
  type        = string
}

variable "required_group" {
  description = "Cognito group required for VPN access, passed to daemon --required-group"
  type        = string
  default     = ""
}

variable "hmac_secret" {
  description = "HMAC secret for state blob signing, passed to daemon via VPN_AUTH_HMAC_SECRET"
  type        = string
  sensitive   = true
}

variable "pki_secret_arns" {
  description = "ARNs of PKI secrets in Secrets Manager (for IAM policy scoping)"
  type        = list(string)
}

variable "associate_public_ip" {
  description = "Assign a temporary public IP at launch for cloud-init internet access. The EIP replaces this IP once ALB health checks pass. Set to false only if using VPC Endpoints and an apt proxy."
  type        = bool
  default     = true
}
