variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the ALB will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of public subnet IDs for the ALB (minimum 2 AZs)"
  type        = list(string)
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener"
  type        = string
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

variable "daemon_security_group_id" {
  description = "Security group ID of the daemon EC2 instance (used for ALB egress rules)"
  type        = string
}
