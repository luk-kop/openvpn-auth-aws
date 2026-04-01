module "cognito" {
  source = "./modules/cognito"

  project_name             = var.project_name
  aws_region               = var.aws_region
  user_pool_name           = var.cognito_user_pool_name
  domain_prefix            = var.cognito_domain_prefix
  vpn_group_name           = var.cognito_vpn_group_name
  alb_domain_name          = var.alb_domain_name
  additional_callback_urls = var.cognito_additional_callback_urls
}

module "alb" {
  count  = var.cost_saving_mode ? 0 : 1
  source = "./modules/alb"

  project_name = var.project_name
  vpc_id       = var.vpc_id
  subnet_ids   = var.alb_subnet_ids
  listeners    = var.openvpn_listeners

  alb_domain_name        = var.alb_domain_name
  route53_hosted_zone_id = var.route53_hosted_zone_id

  cognito_user_pool_arn       = module.cognito.user_pool_arn
  cognito_user_pool_client_id = module.cognito.client_id
  cognito_user_pool_domain    = module.cognito.domain_fqdn

  openvpn_allowed_cidrs = var.openvpn_allowed_cidrs
  ssh_allowed_cidrs     = var.ssh_allowed_cidrs
}

module "vpn_server" {
  count  = var.cost_saving_mode ? 0 : 1
  source = "./modules/vpn-server"

  project_name = var.project_name
  aws_region   = var.aws_region
  vpc_id       = var.vpc_id
  subnet_ids   = var.daemon_subnet_ids
  listeners    = var.openvpn_listeners

  daemon_security_group_id = module.alb[0].daemon_security_group_id
  pki_secret_arns          = [for s in aws_secretsmanager_secret.pki : s.arn]

  alb_arn          = module.alb[0].alb_arn
  alb_domain_name  = var.alb_domain_name
  alb_listener_arn = module.alb[0].listener_arn

  cognito_user_pool_arn       = module.cognito.user_pool_arn
  cognito_user_pool_id        = module.cognito.user_pool_id
  cognito_user_pool_client_id = module.cognito.client_id
  cognito_user_pool_domain    = module.cognito.domain_fqdn
  cognito_issuer_url          = module.cognito.issuer_url

  required_group       = var.required_group
  daemon_binary_s3_uri = var.daemon_binary_s3_uri
  hand_window          = var.hand_window
  auth_session_timeout = var.alb_auth_session_timeout

  # Scaling mode toggle
  create_target_groups   = !var.multi_instance_mode
  callback_mode          = var.multi_instance_mode ? "dynamic" : "static"
  enable_eip_association = !var.multi_instance_mode
  server_name            = var.multi_instance_mode ? "" : var.server_name
  nlb_target_group_arns  = var.multi_instance_mode ? module.nlb[0].target_group_arns : []

  ec2_instance_type    = var.ec2_instance_type
  ec2_ami_id           = var.ec2_ami_id
  ec2_key_name         = var.ec2_key_name
  ec2_root_volume_size = var.ec2_root_volume_size
  associate_public_ip  = var.ec2_associate_public_ip

  asg_desired_capacity = var.asg_desired_capacity
  asg_min_size         = var.asg_min_size
  asg_max_size         = var.asg_max_size
}

# NLB — only deployed in multi-instance mode (distributes OpenVPN client traffic)
module "nlb" {
  count  = var.multi_instance_mode && !var.cost_saving_mode ? 1 : 0
  source = "./modules/nlb"

  project_name = var.project_name
  vpc_id       = var.vpc_id
  subnet_ids   = var.alb_subnet_ids

  listeners = {
    for k, v in var.openvpn_listeners : k => {
      openvpn_port = v.openvpn_port
      ip_protocol  = v.ip_protocol
      daemon_port  = v.daemon_port
    }
  }

  nlb_domain_name        = var.nlb_domain_name
  route53_hosted_zone_id = var.route53_hosted_zone_id
}

# Lambda Router — only deployed in multi-instance mode
module "lambda_router" {
  count  = var.multi_instance_mode && !var.cost_saving_mode ? 1 : 0
  source = "./modules/lambda-router"

  project_name      = var.project_name
  vpc_id            = var.vpc_id
  vpc_cidr          = var.vpc_cidr
  lambda_subnet_ids = var.lambda_subnet_ids
  lambda_zip_path   = var.lambda_router_zip_path

  alb_listener_arn         = module.alb[0].listener_arn
  daemon_security_group_id = module.alb[0].daemon_security_group_id

  daemon_ports = {
    for k, v in var.openvpn_listeners : k => v.daemon_port
  }

  cognito_user_pool_arn       = module.cognito.user_pool_arn
  cognito_user_pool_client_id = module.cognito.client_id
  cognito_user_pool_domain    = module.cognito.domain_fqdn
  auth_session_timeout        = var.alb_auth_session_timeout
}
