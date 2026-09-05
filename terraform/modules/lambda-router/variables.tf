variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block passed to Lambda as VPC_CIDR env var for IP validation"
  type        = string
}

variable "lambda_subnet_ids" {
  description = "Subnet IDs for Lambda VPC configuration"
  type        = list(string)
}

variable "lambda_zip_path" {
  description = "Local path to the pre-built Lambda zip (e.g. lambda-router/lambda-arm64.zip). Must match the module's architectures setting (arm64)."
  type        = string
}

variable "alb_listener_arn" {
  description = "ALB HTTPS listener ARN for creating the /callback/* listener rule"
  type        = string
}

variable "lambda_security_group_id" {
  description = "Security group ID for the Lambda router"
  type        = string
}

variable "ec2_security_group_id" {
  description = "Security group ID of the EC2 instances (ingress rules will be added)"
  type        = string
}

variable "daemon_ports" {
  description = "Map of protocol to daemon HTTP port (e.g. {udp = 8080, tcp = 8081})"
  type        = map(number)
}

variable "cognito_user_pool_arn" {
  description = "Cognito User Pool ARN for authenticate-cognito action"
  type        = string
}

variable "cognito_user_pool_client_id" {
  description = "Cognito User Pool Client ID for authenticate-cognito action"
  type        = string
}

variable "cognito_user_pool_domain" {
  description = "Cognito hosted UI domain FQDN for authenticate-cognito action"
  type        = string
}

variable "auth_session_timeout" {
  description = "ALB authenticate-cognito session timeout in seconds"
  type        = number
  default     = 3600
}

variable "upstream_timeout" {
  description = "HTTP timeout for Lambda proxy requests to upstream daemon (time.ParseDuration format)"
  type        = string
  default     = "10s"
}

variable "upstream_connect_timeout" {
  description = "TCP connection timeout for Lambda proxy requests to upstream daemon; must be shorter than upstream_timeout (time.ParseDuration format)"
  type        = string
  default     = "3s"
}

variable "oidc_headers" {
  description = "ALB OIDC headers forwarded by Lambda Router; unsigned legacy headers should be enabled only for diagnostics"
  type        = list(string)
  default     = ["x-amzn-oidc-data"]

  validation {
    condition = (
      contains(var.oidc_headers, "x-amzn-oidc-data") &&
      length(var.oidc_headers) == length(distinct(var.oidc_headers)) &&
      alltrue([
        for header in var.oidc_headers : contains([
          "x-amzn-oidc-data",
          "x-amzn-oidc-accesstoken",
          "x-amzn-oidc-identity",
        ], header)
      ])
    )
    error_message = "oidc_headers must contain x-amzn-oidc-data and may contain each supported x-amzn-oidc-* header at most once."
  }
}
