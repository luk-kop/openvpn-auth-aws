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

# Secrets Manager: read HMAC secret
resource "aws_iam_role_policy" "daemon_secrets" {
  name = "secrets-access"
  role = aws_iam_role.daemon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [var.hmac_secret_arn]
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
  ami                    = var.ec2_ami_id != "" ? var.ec2_ami_id : data.aws_ssm_parameter.ubuntu.value
  instance_type          = var.ec2_instance_type
  key_name               = var.ec2_key_name != "" ? var.ec2_key_name : null
  subnet_id              = var.subnet_id
  iam_instance_profile   = aws_iam_instance_profile.daemon.name
  vpc_security_group_ids = [var.daemon_security_group_id]

  root_block_device {
    volume_size = var.ec2_root_volume_size
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/templates/user_data.sh.tftpl", {
    aws_region           = var.aws_region
    management_socket    = "/run/openvpn/management.sock"
    management_password  = random_password.mgmt_password.result
    openvpn_port         = var.openvpn_port
    openvpn_protocol     = var.openvpn_protocol
    openvpn_cidr         = var.openvpn_client_cidr
    daemon_callback_port = var.daemon_callback_port
    daemon_flags         = var.daemon_flags
    daemon_binary_s3_uri = var.daemon_binary_s3_uri
  }))

  user_data_replace_on_change = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-openvpn"
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

# --- Elastic IP ---

resource "aws_eip" "openvpn" {
  count = var.ec2_create_eip ? 1 : 0

  tags = {
    Name = "${var.project_name}-openvpn"
  }
}

resource "aws_eip_association" "openvpn" {
  count         = var.ec2_create_eip ? 1 : 0
  allocation_id = aws_eip.openvpn[0].id
  instance_id   = aws_instance.openvpn.id
}

# --- Management password ---

resource "random_password" "mgmt_password" {
  length  = 32
  special = false
}
