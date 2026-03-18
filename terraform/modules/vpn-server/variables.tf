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

variable "vpc_id" {
  description = "VPC ID for target groups"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for the ASG (public subnets with IGW route required)"
  type        = list(string)
}

variable "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN (for daemon IAM policy)"
  type        = string
}

variable "alb_arn" {
  description = "ALB ARN passed to daemon --alb-arn for JWT signer validation"
  type        = string
}

variable "alb_domain_name" {
  description = "ALB domain name for constructing callback URLs"
  type        = string
}

variable "server_name" {
  description = "Unique server name used in ALB path routing (e.g. '01')"
  type        = string
}

variable "listeners" {
  description = "Map of OpenVPN listeners keyed by protocol name (e.g. 'udp', 'tcp')"
  type = map(object({
    openvpn_port = number
    ip_protocol  = string
    client_cidr  = string
    daemon_port  = number
  }))
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

variable "hand_window" {
  description = "Seconds allowed for browser-based auth. Used in both OpenVPN server config and daemon --hand-window flag to keep them in sync."
  type        = number
  default     = 300
}

variable "cognito_user_pool_id" {
  description = "Cognito User Pool ID passed to daemon --cognito-user-pool-id"
  type        = string
}

variable "cognito_issuer_url" {
  description = "Cognito issuer URL for JWT validation (e.g. https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc123)"
  type        = string
}

variable "required_group" {
  description = "Cognito group required for VPN access, passed to daemon --required-group"
  type        = string
  default     = ""
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

# --- ASG ---

variable "asg_desired_capacity" {
  description = "Desired number of instances in the ASG"
  type        = number
  default     = 1
}

variable "asg_min_size" {
  description = "Minimum number of instances in the ASG"
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "Maximum number of instances in the ASG"
  type        = number
  default     = 2
}

variable "asg_health_check_grace_period" {
  description = "Seconds after instance launch before health checks start"
  type        = number
  default     = 300
}
