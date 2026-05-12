# --- Cognito User Pool ---

resource "aws_cognito_user_pool" "this" {
  name = var.user_pool_name

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  username_configuration {
    case_sensitive = false
  }

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 7
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }
}

# --- Cognito Domain (hosted UI) ---

resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.domain_prefix
  user_pool_id = aws_cognito_user_pool.this.id
}

# --- Cognito User Pool Client (confidential, authorization code — required by ALB authenticate-cognito) ---

locals {
  all_callback_urls = compact(concat(
    var.alb_domain_name != "" ? ["https://${var.alb_domain_name}/oauth2/idpresponse"] : [],
    var.additional_callback_urls,
  ))
}

resource "aws_cognito_user_pool_client" "this" {
  name         = "${var.project_name}-client"
  user_pool_id = aws_cognito_user_pool.this.id

  # Confidential client — ALB authenticate-cognito action requires a client secret
  generate_secret = true

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  # "profile" is added so standard OIDC profile claims and any mapped custom
  # attributes forwarded through the ALB authenticate-cognito action appear in
  # x-amzn-oidc-data. This is not a path to native Cognito `cognito:groups`
  # (see docs/group-authorization.md).
  allowed_oauth_scopes         = ["openid", "email", "profile"]
  supported_identity_providers = ["COGNITO"]

  # At least one callback URL is required by Cognito
  callback_urls = length(local.all_callback_urls) > 0 ? local.all_callback_urls : ["https://localhost/callback"]

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  prevent_user_existence_errors = "ENABLED"
}

# --- Cognito User Group ---

resource "aws_cognito_user_group" "vpn_users" {
  name         = var.vpn_group_name
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Users allowed to connect to OpenVPN"
}
