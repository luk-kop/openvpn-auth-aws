# --- EC2 Instance Role for the auth daemon ---

resource "aws_iam_role" "daemon" {
  name = "${var.project_name}-daemon"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_instance_profile" "daemon" {
  name = "${var.project_name}-daemon"
  role = aws_iam_role.daemon.name
}

# SSM Session Manager access
resource "aws_iam_role_policy_attachment" "daemon_ssm" {
  role       = aws_iam_role.daemon.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Cognito: AdminGetUser + AdminListGroupsForUser (for reauth)
resource "aws_iam_role_policy" "daemon_cognito" {
  name = "cognito-access"
  role = aws_iam_role.daemon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "cognito-idp:AdminGetUser",
        "cognito-idp:AdminListGroupsForUser",
      ]
      Resource = [var.cognito_user_pool_arn]
    }]
  })
}

# EIP association + target health polling
resource "aws_iam_role_policy" "daemon_eip" {
  name = "eip-associate"
  role = aws_iam_role.daemon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:AssociateAddress"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = var.project_name
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["elasticloadbalancing:DescribeTargetHealth"]
        Resource = "*"
      }
    ]
  })
}

# PKI secrets read
resource "aws_iam_role_policy" "daemon_pki_secrets" {
  name = "pki-secrets-read"
  role = aws_iam_role.daemon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = var.pki_secret_arns
    }]
  })
}

# S3 read for daemon binary
resource "aws_iam_role_policy" "daemon_s3" {
  count = var.daemon_binary_s3_uri != "" ? 1 : 0
  name  = "s3-binary-read"
  role  = aws_iam_role.daemon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = [replace(var.daemon_binary_s3_uri, "s3://", "arn:aws:s3:::")]
    }]
  })
}

# --- EC2 Instance ---

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

resource "aws_instance" "openvpn" {
  ami                         = var.ec2_ami_id != "" ? var.ec2_ami_id : data.aws_ssm_parameter.ubuntu.value
  instance_type               = var.ec2_instance_type
  key_name                    = var.ec2_key_name != "" ? var.ec2_key_name : null
  subnet_id                   = var.subnet_id
  iam_instance_profile        = aws_iam_instance_profile.daemon.name
  vpc_security_group_ids      = [var.daemon_security_group_id]
  associate_public_ip_address = var.associate_public_ip

  root_block_device {
    volume_size = var.ec2_root_volume_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data_base64            = data.cloudinit_config.this.rendered
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name    = "${var.project_name}-openvpn"
    Project = var.project_name
  }
}

# --- Target Groups (one per daemon port) ---

resource "aws_lb_target_group" "udp" {
  name        = "${var.project_name}-udp"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.selected.id
  target_type = "instance"

  health_check {
    path                = "/healthz"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200"
  }

  tags = {
    Name    = "${var.project_name}-udp"
    Project = var.project_name
  }
}

resource "aws_lb_target_group" "tcp" {
  name        = "${var.project_name}-tcp"
  port        = 8081
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.selected.id
  target_type = "instance"

  health_check {
    path                = "/healthz"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
    matcher             = "200"
  }

  tags = {
    Name    = "${var.project_name}-tcp"
    Project = var.project_name
  }
}

resource "aws_lb_target_group_attachment" "udp" {
  target_group_arn = aws_lb_target_group.udp.arn
  target_id        = aws_instance.openvpn.id
  port             = 8080
}

resource "aws_lb_target_group_attachment" "tcp" {
  target_group_arn = aws_lb_target_group.tcp.arn
  target_id        = aws_instance.openvpn.id
  port             = 8081
}

data "aws_subnet" "selected" {
  id = var.subnet_id
}

data "aws_vpc" "selected" {
  id = data.aws_subnet.selected.vpc_id
}

# --- Cloud-init ---

data "cloudinit_config" "this" {
  gzip          = false
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/templates/cloud-config.yml.tftpl", {
      hostname              = "${var.project_name}-vpn"
      aws_region            = var.aws_region
      management_socket_udp = "/run/openvpn/management-udp.sock"
      management_socket_tcp = "/run/openvpn/management-tcp.sock"
      openvpn_udp_port      = var.openvpn_udp_port
      openvpn_tcp_port      = var.openvpn_tcp_port
      openvpn_udp_cidr      = var.openvpn_udp_client_cidr
      openvpn_tcp_cidr      = var.openvpn_tcp_client_cidr
      hand_window           = var.hand_window
      daemon_binary_s3_uri  = var.daemon_binary_s3_uri
      callback_url_udp      = var.callback_url_udp
      callback_url_tcp      = var.callback_url_tcp
      alb_arn               = var.alb_arn
      cognito_user_pool_id  = var.cognito_user_pool_id
      cognito_issuer_url    = "https://cognito-idp.${var.aws_region}.amazonaws.com/${var.cognito_user_pool_id}"
      required_group        = var.required_group
      hmac_secret           = var.hmac_secret
      eip_allocation_id     = var.eip_allocation_id
      tg_udp_arn            = aws_lb_target_group.udp.arn
      tg_tcp_arn            = aws_lb_target_group.tcp.arn
      pki_secret_prefix     = "${var.project_name}/pki"
    })
  }
}
