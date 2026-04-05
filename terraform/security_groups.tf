# --- Security Groups ---
# All SGs are created unconditionally (SGs are free).
# SG rules are managed by the modules that consume these SGs.

resource "aws_security_group" "ec2" {
  name        = "${var.project_name}-ec2"
  description = "OpenVPN EC2 instances - allows VPN clients and ALB callbacks"
  vpc_id      = var.vpc_id

  tags = {
    Name    = "${var.project_name}-ec2"
    Project = var.project_name
  }
}

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb"
  description = "ALB - allows HTTPS inbound, outbound to EC2 target groups"
  vpc_id      = var.vpc_id

  tags = {
    Name    = "${var.project_name}-alb"
    Project = var.project_name
  }
}

resource "aws_security_group" "nlb" {
  name        = "${var.project_name}-nlb"
  description = "NLB - allows OpenVPN inbound, outbound to EC2 targets"
  vpc_id      = var.vpc_id

  tags = {
    Name    = "${var.project_name}-nlb"
    Project = var.project_name
  }
}

resource "aws_security_group" "lambda" {
  name        = "${var.project_name}-lambda-router"
  description = "Lambda router - egress to EC2 on callback ports and CloudWatch Logs"
  vpc_id      = var.vpc_id

  tags = {
    Name    = "${var.project_name}-lambda-router"
    Project = var.project_name
  }
}
