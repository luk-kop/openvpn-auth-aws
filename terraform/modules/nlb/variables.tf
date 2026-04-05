variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for target groups"
  type        = string
}

variable "subnet_ids" {
  description = "Public subnet IDs for the NLB (minimum 2 AZs)"
  type        = list(string)
}

variable "listeners" {
  description = "Map of OpenVPN listeners with port and protocol configuration"
  type = map(object({
    openvpn_port = number
    ip_protocol  = string
    daemon_port  = number
  }))
}

variable "nlb_domain_name" {
  description = "Domain name for the NLB Route53 alias (e.g. vpn.example.com)"
  type        = string
}

variable "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID for the NLB alias record"
  type        = string
}

variable "nlb_security_group_id" {
  description = "Security group ID for the NLB"
  type        = string
}

variable "ec2_security_group_id" {
  description = "Security group ID of the EC2 instances (NLB egress target)"
  type        = string
}

variable "openvpn_allowed_cidrs" {
  description = "CIDR blocks allowed to connect to OpenVPN via the NLB. Use [\"0.0.0.0/0\"] for public access."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
