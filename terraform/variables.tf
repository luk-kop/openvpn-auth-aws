# --- Global ---

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "openvpn-auth-aws"
}

# --- Cost saving ---

variable "cost_saving_mode" {
  description = "Skip ALB, EIP, and compute resources (ASG). Secrets and Cognito are preserved."
  type        = bool
  default     = false
}

# --- Scaling mode ---

variable "multi_instance_mode" {
  description = "Enable multi-instance ASG mode. When true: NLB is used for OpenVPN client traffic, Lambda Router handles callback routing through a single /callback/* ALB rule, EIP association is disabled, and callback URLs are resolved at boot from the instance private IP. When false (default): static ALB rules are created per listener, EIP association is enabled, and a single server_name is used in the callback path."
  type        = bool
  default     = false
}

# --- Cognito ---

variable "cognito_user_pool_name" {
  description = "Name for the Cognito User Pool"
  type        = string
  default     = "openvpn-auth-pool"
}

variable "cognito_domain_prefix" {
  description = "Cognito hosted UI domain prefix (must be globally unique)"
  type        = string
}

variable "cognito_vpn_group_name" {
  description = "Cognito group name required for VPN access"
  type        = string
  default     = "vpn-users"
}

variable "cognito_additional_callback_urls" {
  description = "Additional OAuth2 callback URLs (e.g. http://localhost:8080/callback for local dev)"
  type        = list(string)
  default     = []
}

# --- Networking ---

variable "vpc_id" {
  description = "VPC ID for ALB and VPN server"
  type        = string
}

variable "alb_subnet_ids" {
  description = "Public subnet IDs for the ALB (minimum 2 AZs)"
  type        = list(string)
}

variable "ec2_subnet_ids" {
  description = "Subnet IDs for the VPN server ASG (public subnets with IGW route required)"
  type        = list(string)
}

# --- DNS / ACM ---

variable "alb_domain_name" {
  description = "Domain name for the ALB certificate and Route53 alias (e.g. vpn.example.com)"
  type        = string
}

variable "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID for ACM DNS validation and ALB alias record"
  type        = string
}

variable "nlb_domain_name" {
  description = "Domain name for the NLB Route53 alias (e.g. vpn-nlb.example.com). Used only in multi-instance mode."
  type        = string
  default     = ""
}

# --- Security ---

variable "pushed_routes" {
  description = "CIDR blocks pushed as routes to VPN clients via OpenVPN 'push route' directive (e.g. [\"10.0.0.0/16\"] to give clients access to the VPC)."
  type        = list(string)
  default     = []
}

variable "ec2_sg_rules" {
  description = "Additional EC2 SG ingress/egress rules for VPN client traffic. Configured separately from pushed_routes for fine-grained protocol and port control."
  type = object({
    ingress = optional(list(object({
      description = string
      cidr_ipv4   = string
      ip_protocol = string
      from_port   = optional(number)
      to_port     = optional(number)
    })), [])
    egress = optional(list(object({
      description = string
      cidr_ipv4   = string
      ip_protocol = string
      from_port   = optional(number)
      to_port     = optional(number)
    })), [])
  })
  # The default catch-all egress rule is required for the EC2 instance itself —
  # AWS API calls, apt package installs, and other system traffic during cloud-init
  # and normal operation. Override this list if you need stricter outbound control,
  # but ensure the instance can still reach AWS endpoints and the internet.
  default = {
    egress = [
      {
        description = "All outbound"
        cidr_ipv4   = "0.0.0.0/0"
        ip_protocol = "-1"
      }
    ]
  }
}

variable "openvpn_allowed_cidrs" {
  description = "CIDR blocks allowed to initiate OpenVPN connections (EC2 security group in single-instance mode, NLB security group in multi-instance mode)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# --- OpenVPN listeners ---

variable "openvpn_listeners" {
  description = "Map of OpenVPN listeners. Must contain 'udp' and 'tcp' keys."
  type = map(object({
    openvpn_port = number
    ip_protocol  = string
    client_cidr  = string
    daemon_port  = number
  }))
  default = {
    udp = {
      openvpn_port = 1194
      ip_protocol  = "udp"
      client_cidr  = "10.8.0.0/24"
      daemon_port  = 8080
    }
    tcp = {
      openvpn_port = 1195
      ip_protocol  = "tcp"
      client_cidr  = "10.8.1.0/24"
      daemon_port  = 8081
    }
  }
}

# --- VPN server (single-instance mode) ---

variable "server_name" {
  description = "Unique server name used in static ALB callback path (e.g. '01'). Used only when multi_instance_mode = false."
  type        = string
  default     = "01"
}

# --- VPN server (shared) ---

variable "daemon_binary_s3_uri" {
  description = "S3 URI for the daemon binary (e.g. s3://bucket/openvpn-auth-daemon)"
  type        = string
  default     = ""
}

variable "required_group" {
  description = "Cognito group required for VPN access, passed to daemon --required-group"
  type        = string
  default     = "vpn-users"
}

variable "hand_window" {
  description = "Seconds allowed for browser-based auth. Synced between OpenVPN server config and daemon --hand-window."
  type        = number
  default     = 300
}

variable "alb_auth_session_timeout" {
  description = "ALB authenticate-cognito session timeout in seconds"
  type        = number
  default     = 3600
}

# --- OpenVPN ---

variable "openvpn_version" {
  description = "Pinned OpenVPN CE version for apt install (e.g. '2.6.19'). The distro suffix is appended automatically."
  type        = string
  default     = "2.6.19"
}

# --- EC2 ---

variable "ec2_instance_type" {
  description = "EC2 instance type for the VPN server"
  type        = string
  default     = "t3.small"
}

variable "ec2_ami_id" {
  description = "Custom AMI ID. Leave empty to use latest Ubuntu 24.04 LTS."
  type        = string
  default     = ""
}

variable "ec2_root_volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}

variable "ec2_associate_public_ip" {
  description = "Assign a temporary public IP at launch for cloud-init internet access. The EIP replaces it once ALB health checks pass."
  type        = bool
  default     = true
}

# --- Lambda Router (multi-instance mode) ---

variable "vpc_cidr" {
  description = "VPC CIDR block used by Lambda Router to validate EC2 private IPs (e.g. 10.0.0.0/16)"
  type        = string
  default     = ""
}

variable "lambda_subnet_ids" {
  description = "Subnet IDs for the Lambda Router function (private subnets with VPC routing)"
  type        = list(string)
  default     = []
}

variable "lambda_router_zip_path" {
  description = "Local path to the pre-built Lambda Router zip file (e.g. lambda-router/lambda-arm64.zip)"
  type        = string
  default     = ""
}

# --- ASG ---

variable "asg_desired_capacity" {
  description = "Desired number of instances. Set > 1 only with multi_instance_mode = true."
  type        = number
  default     = 1
}

variable "asg_min_size" {
  type    = number
  default = 1
}

variable "asg_max_size" {
  type    = number
  default = 2
}
