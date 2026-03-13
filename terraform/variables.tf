variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "cognito_only" {
  description = "Create only Cognito resources (for local development). Skips Lambda, API GW, EC2, SGs, and Secrets Manager."
  type        = bool
  default     = false
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "penvpn-auth-aws"
}

# --- Cognito ---

variable "cognito_domain_prefix" {
  description = "Cognito hosted UI domain prefix (must be globally unique)"
  type        = string
}

variable "cognito_user_pool_name" {
  description = "Name for the Cognito User Pool"
  type        = string
  default     = "openvpn-auth-pool"
}

variable "cognito_vpn_group_name" {
  description = "Cognito group name required for VPN access"
  type        = string
  default     = "vpn-users"
}

variable "cognito_additional_callback_urls" {
  description = "Additional OAuth2 callback URLs beyond the defaults (API Gateway and localhost for Docker testing)"
  type        = list(string)
  default     = []
}

# --- Networking ---

variable "vpc_id" {
  description = "VPC ID where the OpenVPN daemon EC2 instance runs. Not required when cognito_only = true."
  type        = string
  default     = ""

  validation {
    condition     = var.cognito_only || var.vpc_id != ""
    error_message = "vpc_id is required when cognito_only = false."
  }
}

variable "daemon_subnet_ids" {
  description = "Subnet IDs for the daemon EC2 instance (private subnets recommended). Not required when cognito_only = true."
  type        = list(string)
  default     = []

  validation {
    condition     = var.cognito_only || length(var.daemon_subnet_ids) > 0
    error_message = "daemon_subnet_ids is required when cognito_only = false."
  }
}

variable "lambda_subnet_ids" {
  description = "Subnet IDs for Lambda (needs route to daemon callback port). Leave empty for non-VPC Lambda."
  type        = list(string)
  default     = []
}

variable "daemon_callback_port" {
  description = "Port the daemon listens on for Lambda callbacks"
  type        = number
  default     = 8081
}

variable "hand_window" {
  description = "Seconds allowed for browser-based auth. Applied to both OpenVPN server config and daemon --hand-window to keep them in sync."
  type        = number
  default     = 300
}

# --- API Gateway ---

variable "apigw_throttle_burst_limit" {
  description = "API Gateway throttle burst limit (max concurrent requests)"
  type        = number
  default     = 50
}

variable "apigw_throttle_rate_limit" {
  description = "API Gateway throttle rate limit (requests per second)"
  type        = number
  default     = 10
}

# --- Lambda ---

variable "lambda_memory_size" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 128
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

# --- EC2 ---

variable "ec2_ami_id" {
  description = "Custom AMI ID for the OpenVPN instance. Leave empty to use latest Ubuntu 24.04 LTS."
  type        = string
  default     = ""
}

variable "ec2_instance_type" {
  description = "EC2 instance type for the OpenVPN server"
  type        = string
  default     = "t3.small"
}

variable "ec2_key_name" {
  description = "SSH key pair name for the EC2 instance (optional if using SSM only)"
  type        = string
  default     = ""
}

variable "ec2_root_volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}

variable "ec2_create_eip" {
  description = "Create and associate an Elastic IP with the OpenVPN instance"
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

  validation {
    condition     = contains(["udp", "tcp"], var.openvpn_protocol)
    error_message = "Protocol must be udp or tcp."
  }
}

variable "openvpn_client_cidr" {
  description = "VPN tunnel client CIDR (e.g. 10.8.0.0/24)"
  type        = string
  default     = "10.8.0.0/24"
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH into the OpenVPN instance. Leave empty to disable SSH ingress."
  type        = list(string)
  default     = []
}

variable "openvpn_allowed_cidrs" {
  description = "CIDR blocks allowed to connect to OpenVPN. Use [\"0.0.0.0/0\"] for public access."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "daemon_binary_s3_uri" {
  description = "S3 URI for the daemon binary (e.g. s3://bucket/openvpn-auth-daemon). Temporary — will switch to GitHub releases."
  type        = string
  default     = ""
}
