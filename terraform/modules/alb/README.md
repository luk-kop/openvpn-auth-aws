# alb

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
| [aws_acm_certificate.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate) | resource |
| [aws_acm_certificate_validation.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate_validation) | resource |
| [aws_lb.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb) | resource |
| [aws_lb_listener.https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener) | resource |
| [aws_route53_record.acm_validation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_route53_record.alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_security_group.alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_vpc_security_group_egress_rule.alb_to_cognito](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_egress_rule.alb_to_daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_egress_rule.daemon_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.alb_https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.daemon_from_alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.ssh](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alb_domain_name"></a> [alb\_domain\_name](#input\_alb\_domain\_name) | Domain name for the ALB certificate and Route53 alias (e.g. vpn-auth.example.com) | `string` | n/a | yes |
| <a name="input_cognito_user_pool_arn"></a> [cognito\_user\_pool\_arn](#input\_cognito\_user\_pool\_arn) | Cognito User Pool ARN for the authenticate-cognito action | `string` | n/a | yes |
| <a name="input_cognito_user_pool_client_id"></a> [cognito\_user\_pool\_client\_id](#input\_cognito\_user\_pool\_client\_id) | Cognito User Pool Client ID for the authenticate-cognito action | `string` | n/a | yes |
| <a name="input_cognito_user_pool_domain"></a> [cognito\_user\_pool\_domain](#input\_cognito\_user\_pool\_domain) | Cognito hosted UI domain (e.g. my-domain.auth.us-east-1.amazoncognito.com) | `string` | n/a | yes |
| <a name="input_listeners"></a> [listeners](#input\_listeners) | Map of OpenVPN listeners (used for ALB egress rules to daemon ports) | <pre>map(object({<br/>    openvpn_port = number<br/>    ip_protocol  = string<br/>    client_cidr  = string<br/>    daemon_port  = number<br/>  }))</pre> | n/a | yes |
| <a name="input_openvpn_allowed_cidrs"></a> [openvpn\_allowed\_cidrs](#input\_openvpn\_allowed\_cidrs) | CIDR blocks allowed to connect to OpenVPN. Use ["0.0.0.0/0"] for public access. | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming and tagging | `string` | n/a | yes |
| <a name="input_route53_hosted_zone_id"></a> [route53\_hosted\_zone\_id](#input\_route53\_hosted\_zone\_id) | Route53 hosted zone ID for ACM DNS validation and ALB alias record | `string` | n/a | yes |
| <a name="input_ssh_allowed_cidrs"></a> [ssh\_allowed\_cidrs](#input\_ssh\_allowed\_cidrs) | CIDR blocks allowed to SSH into the OpenVPN instance. Leave empty to disable SSH ingress. | `list(string)` | `[]` | no |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | List of public subnet IDs for the ALB (minimum 2 AZs) | `list(string)` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID where the ALB will be deployed | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_acm_certificate_arn"></a> [acm\_certificate\_arn](#output\_acm\_certificate\_arn) | ARN of the ACM certificate |
| <a name="output_alb_arn"></a> [alb\_arn](#output\_alb\_arn) | ARN of the Application Load Balancer |
| <a name="output_alb_dns_name"></a> [alb\_dns\_name](#output\_alb\_dns\_name) | DNS name of the Application Load Balancer |
| <a name="output_alb_security_group_id"></a> [alb\_security\_group\_id](#output\_alb\_security\_group\_id) | Security group ID of the ALB (used to scope daemon ingress rules) |
| <a name="output_alb_zone_id"></a> [alb\_zone\_id](#output\_alb\_zone\_id) | Hosted zone ID of the Application Load Balancer (for Route53 alias records) |
| <a name="output_cognito_user_pool_arn"></a> [cognito\_user\_pool\_arn](#output\_cognito\_user\_pool\_arn) | Cognito User Pool ARN (pass-through for listener rules) |
| <a name="output_cognito_user_pool_client_id"></a> [cognito\_user\_pool\_client\_id](#output\_cognito\_user\_pool\_client\_id) | Cognito User Pool Client ID (pass-through for listener rules) |
| <a name="output_cognito_user_pool_domain"></a> [cognito\_user\_pool\_domain](#output\_cognito\_user\_pool\_domain) | Cognito hosted UI domain (pass-through for listener rules) |
| <a name="output_daemon_security_group_id"></a> [daemon\_security\_group\_id](#output\_daemon\_security\_group\_id) | Security group ID for the daemon EC2 instance |
| <a name="output_listener_arn"></a> [listener\_arn](#output\_listener\_arn) | ARN of the HTTPS listener (used to attach path-based listener rules) |
<!-- END_TF_DOCS -->
