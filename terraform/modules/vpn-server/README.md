# vpn-server

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.12.1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.0 |
| <a name="requirement_cloudinit"></a> [cloudinit](#requirement\_cloudinit) | ~> 2.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 6.0 |
| <a name="provider_cloudinit"></a> [cloudinit](#provider\_cloudinit) | ~> 2.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_iam_instance_profile.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile) | resource |
| [aws_iam_role.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.daemon_cognito](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.daemon_eip](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.daemon_pki_secrets](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.daemon_s3](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.daemon_ssm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_instance.openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance) | resource |
| [aws_lb_target_group.tcp](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_lb_target_group.udp](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_lb_target_group_attachment.tcp](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group_attachment) | resource |
| [aws_lb_target_group_attachment.udp](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group_attachment) | resource |
| [aws_ssm_parameter.ubuntu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ssm_parameter) | data source |
| [aws_subnet.selected](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/subnet) | data source |
| [aws_vpc.selected](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/vpc) | data source |
| [cloudinit_config.this](https://registry.terraform.io/providers/hashicorp/cloudinit/latest/docs/data-sources/config) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alb_arn"></a> [alb\_arn](#input\_alb\_arn) | ALB ARN passed to daemon --alb-arn for JWT signer validation | `string` | n/a | yes |
| <a name="input_associate_public_ip"></a> [associate\_public\_ip](#input\_associate\_public\_ip) | Assign a temporary public IP at launch for cloud-init internet access. The EIP replaces this IP once ALB health checks pass. Set to false only if using VPC Endpoints and an apt proxy. | `bool` | `true` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region | `string` | n/a | yes |
| <a name="input_callback_url_tcp"></a> [callback\_url\_tcp](#input\_callback\_url\_tcp) | Full callback URL for the TCP daemon (e.g. https://vpn-auth.example.com/callback/01/tcp) | `string` | n/a | yes |
| <a name="input_callback_url_udp"></a> [callback\_url\_udp](#input\_callback\_url\_udp) | Full callback URL for the UDP daemon (e.g. https://vpn-auth.example.com/callback/01/udp) | `string` | n/a | yes |
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
| <a name="input_hmac_secret"></a> [hmac\_secret](#input\_hmac\_secret) | HMAC secret for state blob signing, passed to daemon via VPN\_AUTH\_HMAC\_SECRET | `string` | n/a | yes |
| <a name="input_openvpn_tcp_client_cidr"></a> [openvpn\_tcp\_client\_cidr](#input\_openvpn\_tcp\_client\_cidr) | VPN tunnel client CIDR for the TCP server | `string` | `"10.8.1.0/24"` | no |
| <a name="input_openvpn_tcp_port"></a> [openvpn\_tcp\_port](#input\_openvpn\_tcp\_port) | OpenVPN TCP listening port | `number` | `1195` | no |
| <a name="input_openvpn_udp_client_cidr"></a> [openvpn\_udp\_client\_cidr](#input\_openvpn\_udp\_client\_cidr) | VPN tunnel client CIDR for the UDP server | `string` | `"10.8.0.0/24"` | no |
| <a name="input_openvpn_udp_port"></a> [openvpn\_udp\_port](#input\_openvpn\_udp\_port) | OpenVPN UDP listening port | `number` | `1194` | no |
| <a name="input_pki_secret_arns"></a> [pki\_secret\_arns](#input\_pki\_secret\_arns) | ARNs of PKI secrets in Secrets Manager (for IAM policy scoping) | `list(string)` | n/a | yes |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming | `string` | n/a | yes |
| <a name="input_required_group"></a> [required\_group](#input\_required\_group) | Cognito group required for VPN access, passed to daemon --required-group | `string` | `""` | no |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | Subnet ID for the EC2 instance | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_instance_id"></a> [instance\_id](#output\_instance\_id) | EC2 instance ID |
| <a name="output_instance_profile_name"></a> [instance\_profile\_name](#output\_instance\_profile\_name) | IAM instance profile name |
| <a name="output_private_ip"></a> [private\_ip](#output\_private\_ip) | EC2 private IP |
| <a name="output_tg_tcp_arn"></a> [tg\_tcp\_arn](#output\_tg\_tcp\_arn) | ALB Target Group ARN for the TCP daemon (port 8081) |
| <a name="output_tg_udp_arn"></a> [tg\_udp\_arn](#output\_tg\_udp\_arn) | ALB Target Group ARN for the UDP daemon (port 8080) |
<!-- END_TF_DOCS -->
