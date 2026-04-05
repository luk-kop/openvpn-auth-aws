variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "subnet_ids" {
  description = "List of public subnet IDs for the ALB (minimum 2 AZs)"
  type        = list(string)
}

variable "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN for the authenticate-cognito action"
  type        = string
}

variable "cognito_user_pool_client_id" {
  description = "Cognito User Pool Client ID for the authenticate-cognito action"
  type        = string
}

variable "cognito_user_pool_domain" {
  description = "Cognito hosted UI domain (e.g. my-domain.auth.us-east-1.amazoncognito.com)"
  type        = string
}

variable "listeners" {
  description = "Map of OpenVPN listeners (used for ALB egress rules to daemon ports)"
  type = map(object({
    openvpn_port = number
    ip_protocol  = string
    client_cidr  = string
    daemon_port  = number
  }))
}

# --- ACM / DNS ---

variable "alb_domain_name" {
  description = "Domain name for the ALB certificate and Route53 alias (e.g. vpn-auth.example.com)"
  type        = string
}

variable "route53_hosted_zone_id" {
  description = "Route53 hosted zone ID for ACM DNS validation and ALB alias record"
  type        = string
}

# --- Security Group IDs ---

variable "alb_security_group_id" {
  description = "Security group ID for the ALB"
  type        = string
}

variable "ec2_security_group_id" {
  description = "Security group ID for the EC2 instances (used in ALB egress rules)"
  type        = string
}
