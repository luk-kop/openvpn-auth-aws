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
