# --- Locals ---

data "aws_arn" "listener" {
  arn = var.alb_listener_arn
}

locals {
  aws_region     = data.aws_arn.listener.region
  aws_account_id = data.aws_arn.listener.account
  function_name  = "${var.project_name}-lambda-router"
}

# --- IAM Role ---

resource "aws_iam_role" "lambda" {
  name = local.function_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = {
    Name    = local.function_name
    Project = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "cloudwatch_logs" {
  name = "${local.function_name}-logs"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "CloudWatchLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "arn:aws:logs:${local.aws_region}:${local.aws_account_id}:log-group:/aws/lambda/${local.function_name}:*"
    }]
  })
}

# --- Lambda Security Group Rules ---

resource "aws_vpc_security_group_egress_rule" "lambda_to_daemon" {
  for_each = var.daemon_ports

  security_group_id            = var.lambda_security_group_id
  description                  = "Lambda to ${each.key} daemon"
  from_port                    = each.value
  to_port                      = each.value
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.ec2_security_group_id
}

resource "aws_vpc_security_group_egress_rule" "lambda_to_cloudwatch" {
  security_group_id = var.lambda_security_group_id
  description       = "Lambda to CloudWatch Logs endpoint"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

# --- Ingress rules on daemon SG ---

resource "aws_vpc_security_group_ingress_rule" "daemon_from_lambda" {
  for_each = var.daemon_ports

  security_group_id            = var.ec2_security_group_id
  description                  = "Lambda router to ${each.key} daemon"
  from_port                    = each.value
  to_port                      = each.value
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.lambda_security_group_id
}

# --- Lambda Function ---

resource "aws_lambda_function" "router" {
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  function_name    = local.function_name
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  memory_size      = 128
  timeout          = 30
  role             = aws_iam_role.lambda.arn

  vpc_config {
    subnet_ids         = var.lambda_subnet_ids
    security_group_ids = [var.lambda_security_group_id]
  }

  environment {
    variables = {
      VPC_CIDR         = var.vpc_cidr
      DAEMON_PORT_UDP  = tostring(var.daemon_ports["udp"])
      DAEMON_PORT_TCP  = tostring(var.daemon_ports["tcp"])
      UPSTREAM_TIMEOUT = var.upstream_timeout
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.vpc_access,
    aws_iam_role_policy.cloudwatch_logs,
    aws_cloudwatch_log_group.lambda,
  ]

  tags = {
    Name    = local.function_name
    Project = var.project_name
  }
}

# --- CloudWatch Log Group ---

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 14

  tags = {
    Name    = local.function_name
    Project = var.project_name
  }
}

# --- Lambda Target Group ---

resource "aws_lb_target_group" "lambda" {
  name        = "${var.project_name}-lambda-router"
  target_type = "lambda"

  tags = {
    Name    = "${var.project_name}-lambda-router"
    Project = var.project_name
  }
}

resource "aws_lambda_permission" "alb" {
  statement_id  = "AllowALBInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.router.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.lambda.arn
}

resource "aws_lb_target_group_attachment" "lambda" {
  target_group_arn = aws_lb_target_group.lambda.arn
  target_id        = aws_lambda_function.router.arn
  depends_on       = [aws_lambda_permission.alb]
}

# --- ALB Listener Rule ---

resource "aws_lb_listener_rule" "callback" {
  listener_arn = var.alb_listener_arn
  priority     = 100

  action {
    type = "authenticate-cognito"

    authenticate_cognito {
      user_pool_arn       = var.cognito_user_pool_arn
      user_pool_client_id = var.cognito_user_pool_client_id
      user_pool_domain    = var.cognito_user_pool_domain
      # See docs/group-authorization.md — `profile` surfaces standard OIDC
      # profile claims and any mapped custom attributes in x-amzn-oidc-data.
      scope           = "openid email profile"
      session_timeout = var.auth_session_timeout
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lambda.arn
  }

  condition {
    path_pattern {
      regex_values = ["/callback/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/(udp|tcp)"]
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
