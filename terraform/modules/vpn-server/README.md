# vpn-server

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
| [aws_autoscaling_group.openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group) | resource |
| [aws_eip.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_iam_instance_profile.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile) | resource |
| [aws_iam_role.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.daemon_ssm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_launch_template.openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template) | resource |
| [aws_lb_listener_rule.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_rule) | resource |
| [aws_lb_target_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_vpc_security_group_egress_rule.ec2_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.ec2_from_alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.ec2_health_check_from_nlb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.ec2_openvpn_cidr](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.ec2_openvpn_from_nlb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_ssm_parameter.ubuntu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alb_arn"></a> [alb\_arn](#input\_alb\_arn) | ALB ARN passed to daemon --alb-arn for JWT signer validation | `string` | n/a | yes |
| <a name="input_alb_domain_name"></a> [alb\_domain\_name](#input\_alb\_domain\_name) | ALB domain name for constructing callback URLs | `string` | n/a | yes |
| <a name="input_alb_listener_arn"></a> [alb\_listener\_arn](#input\_alb\_listener\_arn) | ALB HTTPS listener ARN for creating static listener rules | `string` | n/a | yes |
| <a name="input_alb_security_group_id"></a> [alb\_security\_group\_id](#input\_alb\_security\_group\_id) | Security group ID of the ALB (used for EC2 ingress from ALB) | `string` | n/a | yes |
| <a name="input_asg_desired_capacity"></a> [asg\_desired\_capacity](#input\_asg\_desired\_capacity) | Desired number of instances in the ASG | `number` | `1` | no |
| <a name="input_asg_health_check_grace_period"></a> [asg\_health\_check\_grace\_period](#input\_asg\_health\_check\_grace\_period) | Seconds after instance launch before health checks start | `number` | `300` | no |
| <a name="input_asg_max_size"></a> [asg\_max\_size](#input\_asg\_max\_size) | Maximum number of instances in the ASG | `number` | `2` | no |
| <a name="input_asg_min_size"></a> [asg\_min\_size](#input\_asg\_min\_size) | Minimum number of instances in the ASG | `number` | `1` | no |
| <a name="input_associate_public_ip"></a> [associate\_public\_ip](#input\_associate\_public\_ip) | Assign a temporary public IP at launch for cloud-init internet access. The EIP replaces this IP once ALB health checks pass. Set to false only if using VPC Endpoints and an apt proxy. | `bool` | `true` | no |
| <a name="input_auth_session_timeout"></a> [auth\_session\_timeout](#input\_auth\_session\_timeout) | ALB authenticate-cognito session timeout in seconds | `number` | `3600` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region | `string` | n/a | yes |
| <a name="input_callback_mode"></a> [callback\_mode](#input\_callback\_mode) | How callback URLs are constructed. 'static' = Terraform-provided URL (single-instance), 'dynamic' = cloud-init resolves instance ID at boot (multi-instance). | `string` | `"static"` | no |
| <a name="input_cognito_issuer_url"></a> [cognito\_issuer\_url](#input\_cognito\_issuer\_url) | Cognito issuer URL for JWT validation (e.g. https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc123) | `string` | n/a | yes |
| <a name="input_cognito_user_pool_arn"></a> [cognito\_user\_pool\_arn](#input\_cognito\_user\_pool\_arn) | Cognito User Pool ARN (for daemon IAM policy) | `string` | n/a | yes |
| <a name="input_cognito_user_pool_client_id"></a> [cognito\_user\_pool\_client\_id](#input\_cognito\_user\_pool\_client\_id) | Cognito User Pool Client ID for ALB listener rule authenticate-cognito action | `string` | n/a | yes |
| <a name="input_cognito_user_pool_domain"></a> [cognito\_user\_pool\_domain](#input\_cognito\_user\_pool\_domain) | Cognito hosted UI domain FQDN for ALB listener rule authenticate-cognito action | `string` | n/a | yes |
| <a name="input_cognito_user_pool_id"></a> [cognito\_user\_pool\_id](#input\_cognito\_user\_pool\_id) | Cognito User Pool ID passed to daemon --cognito-user-pool-id | `string` | n/a | yes |
| <a name="input_create_target_groups"></a> [create\_target\_groups](#input\_create\_target\_groups) | Create ALB target groups. Set to false in multi-instance mode (Lambda creates TGs dynamically). | `bool` | `true` | no |
| <a name="input_daemon_binary_s3_uri"></a> [daemon\_binary\_s3\_uri](#input\_daemon\_binary\_s3\_uri) | S3 URI for the daemon binary | `string` | `""` | no |
| <a name="input_ec2_ami_id"></a> [ec2\_ami\_id](#input\_ec2\_ami\_id) | Custom AMI ID. Leave empty for latest Ubuntu 24.04 LTS. | `string` | `""` | no |
| <a name="input_ec2_instance_type"></a> [ec2\_instance\_type](#input\_ec2\_instance\_type) | EC2 instance type | `string` | `"t3.small"` | no |
| <a name="input_ec2_root_volume_size"></a> [ec2\_root\_volume\_size](#input\_ec2\_root\_volume\_size) | Root EBS volume size in GB | `number` | `20` | no |
| <a name="input_ec2_security_group_id"></a> [ec2\_security\_group\_id](#input\_ec2\_security\_group\_id) | Security group ID for the EC2 instance | `string` | n/a | yes |
| <a name="input_enable_eip_association"></a> [enable\_eip\_association](#input\_enable\_eip\_association) | Enable EIP association service in cloud-config. Disable in multi-instance mode when NLB handles routing. | `bool` | `true` | no |
| <a name="input_hand_window"></a> [hand\_window](#input\_hand\_window) | Seconds allowed for browser-based auth. Used in both OpenVPN server config and daemon --hand-window flag to keep them in sync. | `number` | `300` | no |
| <a name="input_listeners"></a> [listeners](#input\_listeners) | Map of OpenVPN listeners. Must contain exactly the keys 'udp' and 'tcp'. | <pre>map(object({<br/>    openvpn_port = number<br/>    ip_protocol  = string<br/>    client_cidr  = string<br/>    daemon_port  = number<br/>  }))</pre> | n/a | yes |
| <a name="input_multi_instance_mode"></a> [multi\_instance\_mode](#input\_multi\_instance\_mode) | Enable multi-instance mode. Controls whether OpenVPN ingress uses NLB SG (true) or allowed CIDRs (false). | `bool` | `false` | no |
| <a name="input_nlb_security_group_id"></a> [nlb\_security\_group\_id](#input\_nlb\_security\_group\_id) | Security group ID of the NLB (used for EC2 ingress from NLB in multi-instance mode) | `string` | n/a | yes |
| <a name="input_nlb_target_group_arns"></a> [nlb\_target\_group\_arns](#input\_nlb\_target\_group\_arns) | NLB target group ARNs to attach to the ASG (multi-instance mode) | `list(string)` | `[]` | no |
| <a name="input_openvpn_allowed_cidrs"></a> [openvpn\_allowed\_cidrs](#input\_openvpn\_allowed\_cidrs) | CIDR blocks allowed to connect to OpenVPN directly (single-instance mode). Use ["0.0.0.0/0"] for public access. | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_openvpn_version"></a> [openvpn\_version](#input\_openvpn\_version) | Pinned OpenVPN CE version for apt install (e.g. '2.6.19'). The distro suffix is appended automatically. | `string` | `"2.6.19"` | no |
| <a name="input_pki_secret_arns"></a> [pki\_secret\_arns](#input\_pki\_secret\_arns) | ARNs of PKI secrets in Secrets Manager (for IAM policy scoping) | `list(string)` | n/a | yes |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming | `string` | n/a | yes |
| <a name="input_required_group"></a> [required\_group](#input\_required\_group) | Cognito group required for VPN access, passed to daemon --required-group | `string` | `""` | no |
| <a name="input_server_name"></a> [server\_name](#input\_server\_name) | Unique server name used in ALB path routing (e.g. '01'). Required when callback\_mode = 'static'. | `string` | `""` | no |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | Subnet IDs for the ASG (public subnets with IGW route required) | `list(string)` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID for target groups | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_asg_arn"></a> [asg\_arn](#output\_asg\_arn) | Auto Scaling Group ARN |
| <a name="output_asg_name"></a> [asg\_name](#output\_asg\_name) | Auto Scaling Group name |
| <a name="output_eip_allocation_id"></a> [eip\_allocation\_id](#output\_eip\_allocation\_id) | Elastic IP allocation ID (null when enable\_eip\_association = false) |
| <a name="output_eip_public_ip"></a> [eip\_public\_ip](#output\_eip\_public\_ip) | Elastic IP address of the VPN server (null when enable\_eip\_association = false) |
| <a name="output_instance_profile_name"></a> [instance\_profile\_name](#output\_instance\_profile\_name) | IAM instance profile name |
| <a name="output_launch_template_id"></a> [launch\_template\_id](#output\_launch\_template\_id) | Launch template ID |
| <a name="output_target_group_arns"></a> [target\_group\_arns](#output\_target\_group\_arns) | Map of listener key to ALB Target Group ARN (empty when create\_target\_groups = false) |
<!-- END_TF_DOCS -->
