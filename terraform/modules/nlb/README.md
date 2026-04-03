# nlb

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
| [aws_lb.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb) | resource |
| [aws_lb_listener.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener) | resource |
| [aws_lb_target_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_route53_record.nlb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_vpc_security_group_egress_rule.nlb_to_ec2_health_check](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_egress_rule.nlb_to_ec2_openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.nlb_openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_ec2_security_group_id"></a> [ec2\_security\_group\_id](#input\_ec2\_security\_group\_id) | Security group ID of the EC2 instances (NLB egress target) | `string` | n/a | yes |
| <a name="input_listeners"></a> [listeners](#input\_listeners) | Map of OpenVPN listeners with port and protocol configuration | <pre>map(object({<br/>    openvpn_port = number<br/>    ip_protocol  = string<br/>    daemon_port  = number<br/>  }))</pre> | n/a | yes |
| <a name="input_nlb_domain_name"></a> [nlb\_domain\_name](#input\_nlb\_domain\_name) | Domain name for the NLB Route53 alias (e.g. vpn.example.com) | `string` | n/a | yes |
| <a name="input_nlb_security_group_id"></a> [nlb\_security\_group\_id](#input\_nlb\_security\_group\_id) | Security group ID for the NLB | `string` | n/a | yes |
| <a name="input_openvpn_allowed_cidrs"></a> [openvpn\_allowed\_cidrs](#input\_openvpn\_allowed\_cidrs) | CIDR blocks allowed to connect to OpenVPN via the NLB. Use ["0.0.0.0/0"] for public access. | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming | `string` | n/a | yes |
| <a name="input_route53_hosted_zone_id"></a> [route53\_hosted\_zone\_id](#input\_route53\_hosted\_zone\_id) | Route53 hosted zone ID for the NLB alias record | `string` | n/a | yes |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | Public subnet IDs for the NLB (minimum 2 AZs) | `list(string)` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID for target groups | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_nlb_arn"></a> [nlb\_arn](#output\_nlb\_arn) | ARN of the Network Load Balancer |
| <a name="output_nlb_dns_name"></a> [nlb\_dns\_name](#output\_nlb\_dns\_name) | DNS name of the Network Load Balancer |
| <a name="output_target_group_arns"></a> [target\_group\_arns](#output\_target\_group\_arns) | List of NLB target group ARNs (attach to ASG) |
<!-- END_TF_DOCS -->
