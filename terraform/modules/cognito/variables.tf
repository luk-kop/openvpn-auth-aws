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

variable "additional_callback_urls" {
  description = "Additional OAuth2 callback URLs beyond the API Gateway default"
  type        = list(string)
  default     = []
}

variable "lambda_redirect_uri" {
  description = "Primary OAuth2 redirect URI (API Gateway callback URL)"
  type        = string
}
