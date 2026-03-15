# cognito

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.12.1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 6.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cognito_user_group.vpn_users](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_group) | resource |
| [aws_cognito_user_pool.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool) | resource |
| [aws_cognito_user_pool_client.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_client) | resource |
| [aws_cognito_user_pool_domain.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_domain) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_additional_callback_urls"></a> [additional\_callback\_urls](#input\_additional\_callback\_urls) | Additional OAuth2 callback URLs beyond the ALB default | `list(string)` | `[]` | no |
| <a name="input_alb_callback_urls"></a> [alb\_callback\_urls](#input\_alb\_callback\_urls) | OAuth2 callback URLs for the ALB (e.g. https://vpn-auth.example.com/oauth2/idpresponse) | `list(string)` | `[]` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region | `string` | n/a | yes |
| <a name="input_domain_prefix"></a> [domain\_prefix](#input\_domain\_prefix) | Cognito hosted UI domain prefix (must be globally unique) | `string` | n/a | yes |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming | `string` | n/a | yes |
| <a name="input_user_pool_name"></a> [user\_pool\_name](#input\_user\_pool\_name) | Name for the Cognito User Pool | `string` | n/a | yes |
| <a name="input_vpn_group_name"></a> [vpn\_group\_name](#input\_vpn\_group\_name) | Cognito group name required for VPN access | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_client_id"></a> [client\_id](#output\_client\_id) | Cognito User Pool Client ID |
| <a name="output_client_secret"></a> [client\_secret](#output\_client\_secret) | Cognito User Pool Client secret (required by ALB authenticate-cognito action) |
| <a name="output_domain_fqdn"></a> [domain\_fqdn](#output\_domain\_fqdn) | Cognito hosted UI domain FQDN (without https:// scheme, for ALB authenticate-cognito action) |
| <a name="output_domain_url"></a> [domain\_url](#output\_domain\_url) | Cognito hosted UI domain URL |
| <a name="output_issuer_url"></a> [issuer\_url](#output\_issuer\_url) | Cognito issuer URL for JWT validation |
| <a name="output_user_pool_arn"></a> [user\_pool\_arn](#output\_user\_pool\_arn) | Cognito User Pool ARN |
| <a name="output_user_pool_id"></a> [user\_pool\_id](#output\_user\_pool\_id) | Cognito User Pool ID |
<!-- END_TF_DOCS -->
