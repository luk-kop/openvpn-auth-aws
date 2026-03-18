# --- PKI Secrets (always created, populated by scripts/pki.sh upload) ---

resource "aws_secretsmanager_secret" "pki" {
  for_each = toset(["ca-cert", "server-cert", "server-key", "ta-key"])

  name                    = "${var.project_name}/pki/${each.key}"
  description             = "OpenVPN PKI: ${each.key}"
  recovery_window_in_days = 0

  tags = {
    Project = var.project_name
  }
}

# --- Cognito ---

module "cognito" {
  count  = var.deploy_cognito ? 1 : 0
  source = "./modules/cognito"

  project_name             = var.project_name
  aws_region               = var.aws_region
  domain_prefix            = var.cognito_domain_prefix
  user_pool_name           = var.cognito_user_pool_name
  vpn_group_name           = var.cognito_vpn_group_name
  additional_callback_urls = var.cognito_additional_callback_urls
  alb_callback_urls = var.deploy_compute ? [
    "https://${var.alb_domain_name}/oauth2/idpresponse"
  ] : var.cognito_alb_callback_urls
}

# --- ALB ---

module "alb" {
  count  = var.deploy_compute ? 1 : 0
  source = "./modules/alb"

  project_name                = var.project_name
  vpc_id                      = var.vpc_id
  subnet_ids                  = var.alb_subnet_ids
  acm_certificate_arn         = aws_acm_certificate_validation.this[0].certificate_arn
  cognito_user_pool_arn       = module.cognito[0].user_pool_arn
  cognito_user_pool_client_id = module.cognito[0].client_id
  cognito_user_pool_domain    = module.cognito[0].domain_fqdn
  daemon_security_group_id    = aws_security_group.daemon[0].id
  listeners                   = var.openvpn_listeners
}

# --- ALB Listener Rules (one per listener) ---

resource "aws_lb_listener_rule" "vpn" {
  for_each     = var.deploy_compute ? var.openvpn_listeners : {}
  listener_arn = module.alb[0].listener_arn
  priority     = 100 + index(keys(var.openvpn_listeners), each.key)

  action {
    type = "authenticate-cognito"

    authenticate_cognito {
      user_pool_arn       = module.alb[0].cognito_user_pool_arn
      user_pool_client_id = module.alb[0].cognito_user_pool_client_id
      user_pool_domain    = module.alb[0].cognito_user_pool_domain
      scope               = "openid email"
      session_timeout     = var.alb_auth_session_timeout_hours * 3600
    }
  }

  action {
    type             = "forward"
    target_group_arn = module.vpn_server[0].target_group_arns[each.key]
  }

  condition {
    path_pattern {
      values = ["/callback/${var.server_name}/${each.key}"]
    }
  }
}

# --- Elastic IP for VPN server ---

resource "aws_eip" "vpn" {
  count  = var.deploy_compute ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-vpn"
  }
}

# --- VPN Server (EC2 + OpenVPN + daemon) ---

module "vpn_server" {
  count  = var.deploy_compute ? 1 : 0
  source = "./modules/vpn-server"

  project_name             = var.project_name
  aws_region               = var.aws_region
  vpc_id                   = var.vpc_id
  daemon_security_group_id = aws_security_group.daemon[0].id
  subnet_ids               = var.daemon_subnet_ids
  cognito_user_pool_arn    = module.cognito[0].user_pool_arn
  cognito_user_pool_id     = module.cognito[0].user_pool_id
  cognito_issuer_url       = module.cognito[0].issuer_url
  required_group           = var.cognito_vpn_group_name
  listeners                = var.openvpn_listeners

  alb_arn         = module.alb[0].alb_arn
  alb_domain_name = var.alb_domain_name
  server_name     = var.server_name

  eip_allocation_id   = aws_eip.vpn[0].allocation_id
  pki_secret_arns     = [for s in aws_secretsmanager_secret.pki : s.arn]
  associate_public_ip = var.ec2_associate_public_ip

  hand_window          = var.hand_window
  daemon_binary_s3_uri = var.daemon_binary_s3_uri
  ec2_ami_id           = var.ec2_ami_id
  ec2_instance_type    = var.ec2_instance_type
  ec2_key_name         = var.ec2_key_name
  ec2_root_volume_size = var.ec2_root_volume_size
}
