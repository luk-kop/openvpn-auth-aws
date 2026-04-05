output "lambda_function_arn" {
  description = "ARN of the Lambda router function"
  value       = aws_lambda_function.router.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda router function"
  value       = aws_lambda_function.router.function_name
}


output "target_group_arn" {
  description = "ARN of the Lambda target group"
  value       = aws_lb_target_group.lambda.arn
}

output "listener_rule_arn" {
  description = "ARN of the ALB listener rule for /callback/*"
  value       = aws_lb_listener_rule.callback.arn
}
