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
| [aws_iam_instance_profile.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile) | resource |
| [aws_iam_role.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.daemon_ssm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_launch_template.openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template) | resource |
| [aws_lb_target_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_ssm_parameter.ubuntu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alb_arn"></a> [alb\_arn](#input\_alb\_arn) | ALB ARN passed to daemon --alb-arn for JWT signer validation | `string` | n/a | yes |
| <a name="input_alb_domain_name"></a> [alb\_domain\_name](#input\_alb\_domain\_name) | ALB domain name for constructing callback URLs | `string` | n/a | yes |
| <a name="input_asg_desired_capacity"></a> [asg\_desired\_capacity](#input\_asg\_desired\_capacity) | Desired number of instances in the ASG | `number` | `1` | no |
| <a name="input_asg_health_check_grace_period"></a> [asg\_health\_check\_grace\_period](#input\_asg\_health\_check\_grace\_period) | Seconds after instance launch before health checks start | `number` | `300` | no |
| <a name="input_asg_max_size"></a> [asg\_max\_size](#input\_asg\_max\_size) | Maximum number of instances in the ASG | `number` | `2` | no |
| <a name="input_asg_min_size"></a> [asg\_min\_size](#input\_asg\_min\_size) | Minimum number of instances in the ASG | `number` | `1` | no |
| <a name="input_associate_public_ip"></a> [associate\_public\_ip](#input\_associate\_public\_ip) | Assign a temporary public IP at launch for cloud-init internet access. The EIP replaces this IP once ALB health checks pass. Set to false only if using VPC Endpoints and an apt proxy. | `bool` | `true` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region | `string` | n/a | yes |
| <a name="input_cognito_issuer_url"></a> [cognito\_issuer\_url](#input\_cognito\_issuer\_url) | Cognito issuer URL for JWT validation (e.g. https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc123) | `string` | n/a | yes |
| <a name="input_cognito_user_pool_arn"></a> [cognito\_user\_pool\_arn](#input\_cognito\_user\_pool\_arn) | Cognito User Pool ARN (for daemon IAM policy) | `string` | n/a | yes |
| <a name="input_cognito_user_pool_id"></a> [cognito\_user\_pool\_id](#input\_cognito\_user\_pool\_id) | Cognito User Pool ID passed to daemon --cognito-user-pool-id | `string` | n/a | yes |
| <a name="input_daemon_binary_s3_uri"></a> [daemon\_binary\_s3\_uri](#input\_daemon\_binary\_s3\_uri) | S3 URI for the daemon binary | `string` | `""` | no |
| <a name="input_daemon_security_group_id"></a> [daemon\_security\_group\_id](#input\_daemon\_security\_group\_id) | Security group ID for the daemon EC2 instance | `string` | n/a | yes |
| <a name="input_ec2_ami_id"></a> [ec2\_ami\_id](#input\_ec2\_ami\_id) | Custom AMI ID. Leave empty for latest Ubuntu 24.04 LTS. | `string` | `""` | no |
| <a name="input_ec2_instance_type"></a> [ec2\_instance\_type](#input\_ec2\_instance\_type) | EC2 instance type | `string` | `"t3.small"` | no |
| <a name="input_ec2_key_name"></a> [ec2\_key\_name](#input\_ec2\_key\_name) | SSH key pair name (optional if using SSM only) | `string` | `""` | no |
| <a name="input_ec2_root_volume_size"></a> [ec2\_root\_volume\_size](#input\_ec2\_root\_volume\_size) | Root EBS volume size in GB | `number` | `20` | no |
| <a name="input_eip_allocation_id"></a> [eip\_allocation\_id](#input\_eip\_allocation\_id) | Pre-allocated Elastic IP allocation ID to associate after health checks pass | `string` | n/a | yes |
| <a name="input_hand_window"></a> [hand\_window](#input\_hand\_window) | Seconds allowed for browser-based auth. Used in both OpenVPN server config and daemon --hand-window flag to keep them in sync. | `number` | `300` | no |
| <a name="input_listeners"></a> [listeners](#input\_listeners) | Map of OpenVPN listeners keyed by protocol name (e.g. 'udp', 'tcp') | <pre>map(object({<br/>    openvpn_port = number<br/>    ip_protocol  = string<br/>    client_cidr  = string<br/>    daemon_port  = number<br/>  }))</pre> | n/a | yes |
| <a name="input_pki_secret_arns"></a> [pki\_secret\_arns](#input\_pki\_secret\_arns) | ARNs of PKI secrets in Secrets Manager (for IAM policy scoping) | `list(string)` | n/a | yes |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming | `string` | n/a | yes |
| <a name="input_required_group"></a> [required\_group](#input\_required\_group) | Cognito group required for VPN access, passed to daemon --required-group | `string` | `""` | no |
| <a name="input_server_name"></a> [server\_name](#input\_server\_name) | Unique server name used in ALB path routing (e.g. '01') | `string` | n/a | yes |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | Subnet IDs for the ASG (public subnets with IGW route required) | `list(string)` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID for target groups | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_asg_name"></a> [asg\_name](#output\_asg\_name) | Auto Scaling Group name |
| <a name="output_instance_profile_name"></a> [instance\_profile\_name](#output\_instance\_profile\_name) | IAM instance profile name |
| <a name="output_launch_template_id"></a> [launch\_template\_id](#output\_launch\_template\_id) | Launch template ID |
| <a name="output_target_group_arns"></a> [target\_group\_arns](#output\_target\_group\_arns) | Map of listener key to ALB Target Group ARN |
<!-- END_TF_DOCS -->
