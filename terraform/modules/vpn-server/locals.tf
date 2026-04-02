locals {
  name_prefix = "${var.project_name}-openvpn"

  callback_urls = var.callback_mode == "static" ? {
    for k, _ in var.listeners : k => "https://${var.alb_domain_name}/callback/${var.server_name}/${k}"
  } : {}

  user_data_base64 = base64encode(templatefile("${path.module}/templates/cloud-config.yml.tftpl", {
    hostname              = "${var.project_name}-vpn"
    aws_region            = var.aws_region
    management_socket_udp = "/run/openvpn/management-udp.sock"
    management_socket_tcp = "/run/openvpn/management-tcp.sock"
    openvpn_udp_port      = var.listeners["udp"].openvpn_port
    openvpn_tcp_port      = var.listeners["tcp"].openvpn_port
    openvpn_udp_cidr      = var.listeners["udp"].client_cidr
    openvpn_tcp_cidr      = var.listeners["tcp"].client_cidr
    daemon_port_udp       = var.listeners["udp"].daemon_port
    daemon_port_tcp       = var.listeners["tcp"].daemon_port
    hand_window           = var.hand_window
    daemon_binary_s3_uri  = var.daemon_binary_s3_uri
    callback_url_udp      = lookup(local.callback_urls, "udp", "")
    callback_url_tcp      = lookup(local.callback_urls, "tcp", "")
    alb_arn               = var.alb_arn
    alb_domain_name       = var.alb_domain_name
    cognito_user_pool_id  = var.cognito_user_pool_id
    cognito_issuer_url    = var.cognito_issuer_url
    required_group        = var.required_group
    openvpn_version       = var.openvpn_version
    pki_secret_prefix     = "${var.project_name}/pki"

    # Scaling mode
    callback_mode          = var.callback_mode
    enable_eip_association = var.enable_eip_association
    eip_allocation_id      = var.enable_eip_association ? aws_eip.vpn[0].allocation_id : ""
    create_target_groups   = var.create_target_groups
    tg_udp_arn             = var.create_target_groups ? aws_lb_target_group.this["udp"].arn : ""
    tg_tcp_arn             = var.create_target_groups ? aws_lb_target_group.this["tcp"].arn : ""
  }))
}
