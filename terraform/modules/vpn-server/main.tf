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

resource "aws_iam_role_policy" "daemon" {
  name = "${var.project_name}-daemon"
  role = aws_iam_role.daemon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "CognitoUserLookup"
          Effect = "Allow"
          Action = [
            "cognito-idp:AdminGetUser",
            "cognito-idp:AdminListGroupsForUser",
          ]
          Resource = [var.cognito_user_pool_arn]
        },
        {
          Sid      = "AlbTargetHealth"
          Effect   = "Allow"
          Action   = ["elasticloadbalancing:DescribeTargetHealth"]
          Resource = "*"
        },
        {
          Sid      = "PkiSecretsRead"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = var.pki_secret_arns
        },
      ],
      var.enable_eip_association ? [
        {
          Sid      = "EipAssociate"
          Effect   = "Allow"
          Action   = ["ec2:AssociateAddress"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "aws:ResourceTag/Project" = var.project_name
            }
          }
        },
      ] : [],
      var.daemon_binary_s3_uri != "" ? [
        {
          Sid      = "S3BinaryRead"
          Effect   = "Allow"
          Action   = ["s3:GetObject"]
          Resource = [replace(var.daemon_binary_s3_uri, "s3://", "arn:aws:s3:::")]
        },
      ] : [],
    )
  })
}

# --- EC2 Security Group Rules ---

resource "aws_vpc_security_group_ingress_rule" "ec2_from_alb" {
  for_each = var.listeners

  security_group_id            = var.ec2_security_group_id
  description                  = "ALB callback to ${each.key} daemon"
  from_port                    = each.value.daemon_port
  to_port                      = each.value.daemon_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.alb_security_group_id
}

# Single-instance mode: OpenVPN ingress directly from allowed CIDRs
resource "aws_vpc_security_group_ingress_rule" "ec2_openvpn_cidr" {
  for_each = var.multi_instance_mode ? {} : {
    for pair in setproduct(keys(var.listeners), var.openvpn_allowed_cidrs) :
    "${pair[0]}-${pair[1]}" => {
      listener = var.listeners[pair[0]]
      cidr     = pair[1]
      proto    = pair[0]
    }
  }

  security_group_id = var.ec2_security_group_id
  description       = "OpenVPN ${each.value.proto} from ${each.value.cidr}"
  from_port         = each.value.listener.openvpn_port
  to_port           = each.value.listener.openvpn_port
  ip_protocol       = each.value.listener.ip_protocol
  cidr_ipv4         = each.value.cidr
}

# Multi-instance mode: OpenVPN ingress from NLB SG
resource "aws_vpc_security_group_ingress_rule" "ec2_openvpn_from_nlb" {
  for_each = var.multi_instance_mode ? var.listeners : {}

  security_group_id            = var.ec2_security_group_id
  description                  = "OpenVPN ${each.key} from NLB"
  from_port                    = each.value.openvpn_port
  to_port                      = each.value.openvpn_port
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = var.nlb_security_group_id
}

# Multi-instance mode: NLB health check ingress
resource "aws_vpc_security_group_ingress_rule" "ec2_health_check_from_nlb" {
  for_each = var.multi_instance_mode ? var.listeners : {}

  security_group_id            = var.ec2_security_group_id
  description                  = "NLB health check to ${each.key} daemon"
  from_port                    = each.value.daemon_port
  to_port                      = each.value.daemon_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.nlb_security_group_id
}

#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "ec2_all" {
  security_group_id = var.ec2_security_group_id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# --- Elastic IP for VPN server ---

resource "aws_eip" "vpn" {
  count  = var.enable_eip_association ? 1 : 0
  domain = "vpc"

  tags = {
    Name    = "${var.project_name}-vpn"
    Project = var.project_name
  }
}

# --- Launch Template ---

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/${var.ec2_architecture}/hvm/ebs-gp3/ami-id"
}

resource "aws_launch_template" "openvpn" {
  name_prefix   = "${local.name_prefix}-"
  image_id      = var.ec2_ami_id != "" ? var.ec2_ami_id : data.aws_ssm_parameter.ubuntu.value
  instance_type = var.ec2_instance_type
  user_data     = local.user_data_base64

  iam_instance_profile {
    name = aws_iam_instance_profile.daemon.name
  }

  network_interfaces {
    associate_public_ip_address = var.associate_public_ip
    security_groups             = [var.ec2_security_group_id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size = var.ec2_root_volume_size
      volume_type = "gp3"
      encrypted   = true
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name    = local.name_prefix
      Project = var.project_name
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name    = local.name_prefix
      Project = var.project_name
    }
  }

  tag_specifications {
    resource_type = "network-interface"

    tags = {
      Name    = local.name_prefix
      Project = var.project_name
    }
  }

  tags = {
    Project = var.project_name
  }
}

# --- Auto Scaling Group ---

resource "aws_autoscaling_group" "openvpn" {
  name_prefix         = local.name_prefix
  desired_capacity    = var.asg_desired_capacity
  min_size            = var.asg_min_size
  max_size            = var.asg_max_size
  vpc_zone_identifier = var.subnet_ids
  target_group_arns = concat(
    var.create_target_groups ? [for tg in aws_lb_target_group.this : tg.arn] : [],
    var.nlb_target_group_arns,
  )

  health_check_type         = var.create_target_groups || length(var.nlb_target_group_arns) > 0 ? "ELB" : "EC2"
  health_check_grace_period = var.asg_health_check_grace_period

  launch_template {
    id      = aws_launch_template.openvpn.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"

    preferences {
      min_healthy_percentage = 100
    }
  }

  tag {
    key                 = "Name"
    value               = local.name_prefix
    propagate_at_launch = false
  }

  tag {
    key                 = "Project"
    value               = var.project_name
    propagate_at_launch = false
  }
}

# --- Target Groups (one per listener, single-instance mode only) ---

resource "aws_lb_target_group" "this" {
  for_each = var.create_target_groups ? var.listeners : {}

  name        = "${var.project_name}-${each.key}"
  port        = each.value.daemon_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
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
    Name    = "${var.project_name}-${each.key}"
    Project = var.project_name
  }
}

# --- ALB Listener Rules (static, single-instance mode only) ---

resource "aws_lb_listener_rule" "vpn" {
  for_each     = var.create_target_groups ? var.listeners : {}
  listener_arn = var.alb_listener_arn
  priority     = 100 + index(keys(var.listeners), each.key)

  action {
    type = "authenticate-cognito"

    authenticate_cognito {
      user_pool_arn       = var.cognito_user_pool_arn
      user_pool_client_id = var.cognito_user_pool_client_id
      user_pool_domain    = var.cognito_user_pool_domain
      scope               = "openid email"
      session_timeout     = var.auth_session_timeout
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[each.key].arn
  }

  condition {
    path_pattern {
      values = ["/callback/${var.server_name}/${each.key}"]
    }
  }

  # Require state query param in {base64url_payload}.{base64url_hmac} format.
  # ALB query_string only supports wildcards, so *.* is the best we can enforce here;
  # full HMAC validation happens in the daemon.
  condition {
    query_string {
      key   = "state"
      value = "*.*"
    }
  }

  condition {
    http_request_method {
      values = ["GET"]
    }
  }
}
