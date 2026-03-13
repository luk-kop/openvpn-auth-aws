variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "lambda_security_group_id" {
  description = "Security group ID for Lambda function"
  type        = string
}

variable "lambda_subnet_ids" {
  description = "Subnet IDs for Lambda"
  type        = list(string)
}

variable "hmac_secret_arn" {
  description = "Secrets Manager ARN for HMAC secret"
  type        = string
}

variable "cognito_domain_url" {
  description = "Cognito hosted UI domain URL"
  type        = string
}

variable "cognito_client_id" {
  description = "Cognito app client ID"
  type        = string
}

variable "lambda_source_dir" {
  description = "Path to the Lambda source directory"
  type        = string
}

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

variable "apigw_throttle_burst_limit" {
  description = "API Gateway throttle burst limit"
  type        = number
  default     = 50
}

variable "apigw_throttle_rate_limit" {
  description = "API Gateway throttle rate limit"
  type        = number
  default     = 10
}
