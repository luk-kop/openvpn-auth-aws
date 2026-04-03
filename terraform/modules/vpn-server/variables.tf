variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "ec2_security_group_id" {
  description = "Security group ID for the EC2 instance"
  type        = string
}

variable "alb_security_group_id" {
  description = "Security group ID of the ALB (used for EC2 ingress from ALB)"
  type        = string
}

variable "nlb_security_group_id" {
  description = "Security group ID of the NLB (used for EC2 ingress from NLB in multi-instance mode)"
  type        = string
}

variable "multi_instance_mode" {
  description = "Enable multi-instance mode. Controls whether OpenVPN ingress uses NLB SG (true) or allowed CIDRs (false)."
  type        = bool
  default     = false
}

variable "openvpn_allowed_cidrs" {
  description = "CIDR blocks allowed to connect to OpenVPN directly (single-instance mode). Use [\"0.0.0.0/0\"] for public access."
  type        = list(string)
  default     = ["0.0.0.0/0"]
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

variable "alb_listener_arn" {
  description = "ALB HTTPS listener ARN for creating static listener rules"
  type        = string
}

variable "server_name" {
  description = "Unique server name used in ALB path routing (e.g. '01'). Required when callback_mode = 'static'."
  type        = string
  default     = ""
}

variable "listeners" {
  description = "Map of OpenVPN listeners. Must contain exactly the keys 'udp' and 'tcp'."
  type = map(object({
    openvpn_port = number
    ip_protocol  = string
    client_cidr  = string
    daemon_port  = number
  }))

  validation {
    condition     = contains(keys(var.listeners), "udp") && contains(keys(var.listeners), "tcp")
    error_message = "The listeners map must contain both 'udp' and 'tcp' keys."
  }
}

variable "daemon_binary_s3_uri" {
  description = "S3 URI for the daemon binary"
  type        = string
  default     = ""
}

# --- Scaling mode ---

variable "create_target_groups" {
  description = "Create ALB target groups. Set to false in multi-instance mode (Lambda creates TGs dynamically)."
  type        = bool
  default     = true
}

variable "callback_mode" {
  description = "How callback URLs are constructed. 'static' = Terraform-provided URL (single-instance), 'dynamic' = cloud-init resolves instance ID at boot (multi-instance)."
  type        = string
  default     = "static"

  validation {
    condition     = contains(["static", "dynamic"], var.callback_mode)
    error_message = "callback_mode must be 'static' or 'dynamic'."
  }
}

variable "nlb_target_group_arns" {
  description = "NLB target group ARNs to attach to the ASG (multi-instance mode)"
  type        = list(string)
  default     = []
}

variable "enable_eip_association" {
  description = "Enable EIP association service in cloud-config. Disable in multi-instance mode when NLB handles routing."
  type        = bool
  default     = true
}

# --- Cognito (for listener rules) ---

variable "cognito_user_pool_client_id" {
  description = "Cognito User Pool Client ID for ALB listener rule authenticate-cognito action"
  type        = string
}

variable "cognito_user_pool_domain" {
  description = "Cognito hosted UI domain FQDN for ALB listener rule authenticate-cognito action"
  type        = string
}

variable "auth_session_timeout" {
  description = "ALB authenticate-cognito session timeout in seconds"
  type        = number
  default     = 3600
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

# --- OpenVPN ---

variable "openvpn_version" {
  description = "Pinned OpenVPN CE version for apt install (e.g. '2.6.19'). The distro suffix is appended automatically."
  type        = string
  default     = "2.6.19"
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

variable "ec2_root_volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}

variable "hand_window" {
  description = "Seconds allowed for browser-based auth. Used in both OpenVPN server config and daemon --hand-window flag to keep them in sync."
  type        = number
  default     = 300
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
