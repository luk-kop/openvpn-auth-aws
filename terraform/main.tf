# --- Secrets (shared between Lambda and daemon) ---

resource "random_password" "hmac_secret" {
  count   = var.cognito_only ? 0 : 1
  length  = 64
  special = true
}

resource "aws_secretsmanager_secret" "hmac" {
  count       = var.cognito_only ? 0 : 1
  name        = "${var.project_name}/hmac-secret"
  description = "HMAC secret shared between the auth daemon and Lambda for state blob signing and callback verification"
}

resource "aws_secretsmanager_secret_version" "hmac" {
  count         = var.cognito_only ? 0 : 1
  secret_id     = aws_secretsmanager_secret.hmac[0].id
  secret_string = random_password.hmac_secret[0].result
}

# --- Lambda + API Gateway ---

module "lambda_api" {
  count  = var.cognito_only ? 0 : 1
  source = "./modules/lambda-api"

  project_name             = var.project_name
  lambda_security_group_id = aws_security_group.lambda[0].id
  lambda_subnet_ids        = var.lambda_subnet_ids
  hmac_secret_arn          = aws_secretsmanager_secret.hmac[0].arn
  cognito_domain_url       = module.cognito.domain_url
  cognito_client_id        = module.cognito.client_id
  lambda_source_dir        = "${path.module}/lambda"
  lambda_memory_size       = var.lambda_memory_size
  lambda_timeout           = var.lambda_timeout
  apigw_throttle_burst_limit = var.apigw_throttle_burst_limit
  apigw_throttle_rate_limit  = var.apigw_throttle_rate_limit
}

# --- Cognito ---

module "cognito" {
  source = "./modules/cognito"

  project_name             = var.project_name
  aws_region               = var.aws_region
  domain_prefix            = var.cognito_domain_prefix
  user_pool_name           = var.cognito_user_pool_name
  vpn_group_name           = var.cognito_vpn_group_name
  additional_callback_urls = var.cognito_additional_callback_urls
  lambda_redirect_uri      = var.cognito_only ? "" : module.lambda_api[0].lambda_redirect_uri
}

# --- VPN Server (EC2 + OpenVPN + daemon) ---

module "vpn_server" {
  count  = var.cognito_only ? 0 : 1
  source = "./modules/vpn-server"

  project_name             = var.project_name
  aws_region               = var.aws_region
  daemon_security_group_id = aws_security_group.daemon[0].id
  subnet_id                = var.daemon_subnet_ids[0]
  daemon_callback_port     = var.daemon_callback_port
  cognito_user_pool_arn    = module.cognito.user_pool_arn
  hmac_secret_arn          = aws_secretsmanager_secret.hmac[0].arn

  daemon_flags = join(" \\\n    ", [
    "--api-gateway-url=${module.lambda_api[0].api_gateway_url}",
    "--hmac-secret-arn=${aws_secretsmanager_secret.hmac[0].arn}",
    "--cognito-user-pool-id=${module.cognito.user_pool_id}",
    "--cognito-token-endpoint=${module.cognito.token_endpoint}",
    "--cognito-client-id=${module.cognito.client_id}",
    "--cognito-redirect-uri=${module.lambda_api[0].lambda_redirect_uri}",
    "--cognito-issuer-url=${module.cognito.issuer_url}",
    "--aws-region=${var.aws_region}",
    "--required-group=${var.cognito_vpn_group_name}",
    "--callback-port=${var.daemon_callback_port}",
    "--hand-window=${var.hand_window}s",
    "--log-format=json",
    "--emf-metrics",
  ])

  hand_window = var.hand_window

  daemon_binary_s3_uri = var.daemon_binary_s3_uri
  ec2_ami_id           = var.ec2_ami_id
  ec2_instance_type    = var.ec2_instance_type
  ec2_key_name         = var.ec2_key_name
  ec2_root_volume_size = var.ec2_root_volume_size
  ec2_create_eip       = var.ec2_create_eip
  openvpn_port         = var.openvpn_port
  openvpn_protocol     = var.openvpn_protocol
  openvpn_client_cidr  = var.openvpn_client_cidr
}
