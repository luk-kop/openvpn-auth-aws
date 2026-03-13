output "api_gateway_url" {
  description = "API Gateway base URL"
  value       = aws_apigatewayv2_stage.this.invoke_url
}

output "lambda_redirect_uri" {
  description = "OAuth2 redirect URI (API Gateway /callback)"
  value       = "${aws_apigatewayv2_stage.this.invoke_url}/callback"
}

