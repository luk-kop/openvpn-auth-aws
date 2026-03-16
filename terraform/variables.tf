variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "deploy_cognito" {
  description = "Create Cognito User Pool and related resources."
  type        = bool
  default     = true
}

variable "deploy_compute" {
  description = "Create ALB and VPN server EC2 instance. Requires deploy_cognito = true."
  type        = bool
  default     = true

  validation {
    condition     = !var.deploy_compute || var.deploy_cognito
    error_message = "deploy_compute requires deploy_cognito = true."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "openvpn-auth-aws"
}

# --- Cognito ---

variable "cognito_domain_prefix" {
  description = "Cognito hosted UI domain prefix (must be globally unique). Required when deploy_cognito = true."
  type        = string
  default     = ""

  validation {
    condition     = !var.deploy_cognito || var.cognito_domain_prefix != ""
    error_message = "cognito_domain_prefix is required when deploy_cognito = true."
  }
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

variable "cognito_alb_callback_urls" {
  description = "OAuth2 callback URLs for the ALB (e.g. https://vpn-auth.example.com/oauth2/idpresponse)"
  type        = list(string)
  default     = []
}

# --- Networking ---

variable "vpc_id" {
  description = "VPC ID for ALB and VPN server. Required when deploy_compute = true."
  type        = string
  default     = ""

  validation {
    condition     = !var.deploy_compute || var.vpc_id != ""
    error_message = "vpc_id is required when deploy_compute = true."
  }
}

variable "daemon_subnet_ids" {
  description = "Subnet IDs for the daemon EC2 instance (public subnets with IGW route required — EIP needs internet connectivity). Required when deploy_compute = true."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.deploy_compute || length(var.daemon_subnet_ids) > 0
    error_message = "daemon_subnet_ids is required when deploy_compute = true."
  }
}

variable "alb_subnet_ids" {
  description = "Public subnet IDs for the ALB (minimum 2 AZs). Required when deploy_compute = true."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.deploy_compute || length(var.alb_subnet_ids) >= 2
    error_message = "alb_subnet_ids requires at least 2 subnets (one per AZ) when deploy_compute = true."
  }
}

variable "alb_domain_name" {
  description = "Domain name for the ALB certificate (e.g. vpn-auth.example.com). Required when deploy_compute = true."
  type        = string
  default     = ""

  validation {
    condition     = !var.deploy_compute || var.alb_domain_name != ""
    error_message = "alb_domain_name is required when deploy_compute = true."
  }
}

variable "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID for ACM DNS validation. Required when deploy_compute = true."
  type        = string
  default     = ""

  validation {
    condition     = !var.deploy_compute || var.route53_hosted_zone_id != ""
    error_message = "route53_hosted_zone_id is required when deploy_compute = true."
  }
}

variable "server_name" {
  description = "Unique server name used in ALB path routing (e.g. '01'). Required when deploy_compute = true."
  type        = string
  default     = "01"
}

variable "hand_window" {
  description = "Seconds allowed for browser-based auth. Applied to both OpenVPN server config and daemon --hand-window to keep them in sync."
  type        = number
  default     = 300
}

variable "alb_auth_session_timeout_hours" {
  description = "ALB authenticate-cognito session timeout in hours."
  type        = number
  default     = 1

  validation {
    condition     = var.alb_auth_session_timeout_hours > 0
    error_message = "alb_auth_session_timeout_hours must be greater than 0."
  }
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

  validation {
    condition     = var.openvpn_tcp_port != var.openvpn_udp_port
    error_message = "openvpn_tcp_port must be different from openvpn_udp_port."
  }
}

variable "openvpn_udp_client_cidr" {
  description = "VPN tunnel client CIDR for the UDP server (e.g. 10.8.0.0/24)"
  type        = string
  default     = "10.8.0.0/24"
}

variable "openvpn_tcp_client_cidr" {
  description = "VPN tunnel client CIDR for the TCP server (e.g. 10.8.1.0/24). Must not overlap with UDP CIDR."
  type        = string
  default     = "10.8.1.0/24"
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

variable "ec2_associate_public_ip" {
  description = "Assign a temporary public IP to the VPN instance at launch. The instance is in a public subnet (required by EIP) but launches without a public IP — the EIP is assigned after ALB health checks pass. Without this flag, cloud-init has no outbound internet access and cannot reach AWS APIs or install packages. The EIP replaces this temporary IP once assigned. Set to false only if using VPC Endpoints and an apt proxy."
  type        = bool
  default     = true
}

variable "daemon_binary_s3_uri" {
  description = "S3 URI for the daemon binary (e.g. s3://bucket/openvpn-auth-daemon). Required when deploy_compute = true."
  type        = string
  default     = ""

  validation {
    condition     = !var.deploy_compute || var.daemon_binary_s3_uri != ""
    error_message = "daemon_binary_s3_uri is required when deploy_compute = true."
  }
}
