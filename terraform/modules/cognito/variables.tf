variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "domain_prefix" {
  description = "Cognito hosted UI domain prefix (must be globally unique)"
  type        = string
}

variable "user_pool_name" {
  description = "Name for the Cognito User Pool"
  type        = string
}

variable "vpn_group_name" {
  description = "Cognito group name required for VPN access"
  type        = string
}

variable "alb_domain_name" {
  description = "ALB domain name used to construct the OAuth2 callback URL (e.g. vpn-auth.example.com). The module constructs https://{domain}/oauth2/idpresponse automatically."
  type        = string
  default     = ""
}

variable "additional_callback_urls" {
  description = "Additional OAuth2 callback URLs beyond the ALB default (e.g. http://localhost:8080/callback for local dev)"
  type        = list(string)
  default     = []
}
