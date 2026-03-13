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

variable "daemon_callback_port" {
  description = "Port the daemon listens on for Lambda callbacks"
  type        = number
}

variable "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN (for daemon IAM policy)"
  type        = string
}

variable "hmac_secret_arn" {
  description = "Secrets Manager ARN for HMAC secret"
  type        = string
}

variable "daemon_flags" {
  description = "Pre-built CLI flags string for openvpn-auth-daemon"
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

variable "ec2_create_eip" {
  description = "Create and associate an Elastic IP"
  type        = bool
  default     = true
}

# --- OpenVPN ---

variable "openvpn_port" {
  description = "OpenVPN listening port"
  type        = number
  default     = 1194
}

variable "openvpn_protocol" {
  description = "OpenVPN protocol (udp or tcp)"
  type        = string
  default     = "udp"
}

variable "openvpn_client_cidr" {
  description = "VPN tunnel client CIDR"
  type        = string
  default     = "10.8.0.0/24"
}

variable "hand_window" {
  description = "Seconds allowed for browser-based auth. Used in both OpenVPN server config and daemon --hand-window flag to keep them in sync."
  type        = number
  default     = 300
}

