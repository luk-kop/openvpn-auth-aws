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

# --- Secrets (HMAC shared secret for state blob signing) ---

resource "random_password" "hmac_secret" {
  count   = var.deploy_compute ? 1 : 0
  length  = 64
  special = true
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
}

# --- ALB Listener Rules (one UDP + one TCP rule per VPN server) ---

resource "aws_lb_listener_rule" "vpn_udp" {
  count        = var.deploy_compute ? 1 : 0
  listener_arn = module.alb[0].listener_arn
  priority     = 100

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
    target_group_arn = module.vpn_server[0].tg_udp_arn
  }

  condition {
    path_pattern {
      values = ["/callback/${var.server_name}/udp"]
    }
  }
}

resource "aws_lb_listener_rule" "vpn_tcp" {
  count        = var.deploy_compute ? 1 : 0
  listener_arn = module.alb[0].listener_arn
  priority     = 101

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
    target_group_arn = module.vpn_server[0].tg_tcp_arn
  }

  condition {
    path_pattern {
      values = ["/callback/${var.server_name}/tcp"]
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
  daemon_security_group_id = aws_security_group.daemon[0].id
  subnet_id                = var.daemon_subnet_ids[0]
  cognito_user_pool_arn    = module.cognito[0].user_pool_arn
  cognito_user_pool_id     = module.cognito[0].user_pool_id
  required_group           = var.cognito_vpn_group_name
  hmac_secret              = random_password.hmac_secret[0].result

  alb_arn          = module.alb[0].alb_arn
  callback_url_udp = "https://${var.alb_domain_name}/callback/${var.server_name}/udp"
  callback_url_tcp = "https://${var.alb_domain_name}/callback/${var.server_name}/tcp"

  eip_allocation_id   = aws_eip.vpn[0].allocation_id
  pki_secret_arns     = [for s in aws_secretsmanager_secret.pki : s.arn]
  associate_public_ip = var.ec2_associate_public_ip

  hand_window             = var.hand_window
  daemon_binary_s3_uri    = var.daemon_binary_s3_uri
  ec2_ami_id              = var.ec2_ami_id
  ec2_instance_type       = var.ec2_instance_type
  ec2_key_name            = var.ec2_key_name
  ec2_root_volume_size    = var.ec2_root_volume_size
  openvpn_udp_port        = var.openvpn_udp_port
  openvpn_tcp_port        = var.openvpn_tcp_port
  openvpn_udp_client_cidr = var.openvpn_udp_client_cidr
  openvpn_tcp_client_cidr = var.openvpn_tcp_client_cidr
}
