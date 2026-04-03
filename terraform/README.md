# terraform

## Networking prerequisites

The VPN EC2 instance must be in a **public subnet** (route `0.0.0.0/0 → igw`) because the Elastic IP requires an Internet Gateway.

The instance launches without a public IP by default — the EIP is assigned only after ALB health checks pass. During this window the instance has no outbound internet access, so cloud-init cannot reach AWS APIs (Secrets Manager, S3, SSM) or install packages.

**Options (pick one):**

| Option | Variable | Cost |
|--------|----------|------|
| Temporary public IP at launch (EIP replaces it later) | `ec2_associate_public_ip = true` | $0.005/h per public IPv4 |
| VPC Endpoints (see below) | (none — networking outside this module) | ~$22/mo |

**Required VPC Endpoints** (if not using public IP):

- `com.amazonaws.<region>.s3` (Gateway) — daemon binary download
- `com.amazonaws.<region>.secretsmanager` (Interface) — PKI secret fetch
- `com.amazonaws.<region>.cognito-idp` (Interface) — AdminGetUser, AdminListGroupsForUser
- `com.amazonaws.<region>.ec2` (Interface) — EIP AssociateAddress
- `com.amazonaws.<region>.elasticloadbalancing` (Interface) — DescribeTargetHealth
- `com.amazonaws.<region>.ssm` (Interface) — SSM Session Manager
- `com.amazonaws.<region>.ssmmessages` (Interface) — SSM Session Manager

> **Note:** Even with all VPC Endpoints, cloud-init still needs internet access to download AWS CLI v2 (`awscli.amazonaws.com`) and install packages from external apt repos (Ubuntu archive, OpenVPN repo). This can be solved by configuring a forward proxy (for curl and apt via `Acquire::http::Proxy`), using a custom AMI with all dependencies pre-installed, or simply setting `ec2_associate_public_ip = true`.

## ALB auth session

The ALB `authenticate-cognito` action stores browser login state in `AWSELBAuthSessionCookie-*` cookies. This repo configures the ALB OAuth scope as `openid email` so the `email` claim is available in the `x-amzn-oidc-data` header forwarded to the daemon.

The cookie lifetime is controlled by `alb_auth_session_timeout_hours` and defaults to `1` hour. This is intentionally much shorter than the AWS default (`7` days) so stale callback URLs stop reaching the daemon through an old ALB browser session sooner. This timeout is separate from the daemon's own `state` lifetime, which is controlled by `--auth-timeout`.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.12.1 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | ~> 2.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.39.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_alb"></a> [alb](#module\_alb) | ./modules/alb | n/a |
| <a name="module_cognito"></a> [cognito](#module\_cognito) | ./modules/cognito | n/a |
| <a name="module_lambda_router"></a> [lambda\_router](#module\_lambda\_router) | ./modules/lambda-router | n/a |
| <a name="module_nlb"></a> [nlb](#module\_nlb) | ./modules/nlb | n/a |
| <a name="module_vpn_server"></a> [vpn\_server](#module\_vpn\_server) | ./modules/vpn-server | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_secretsmanager_secret.pki](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_security_group.alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.ec2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.nlb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alb_auth_session_timeout"></a> [alb\_auth\_session\_timeout](#input\_alb\_auth\_session\_timeout) | ALB authenticate-cognito session timeout in seconds | `number` | `3600` | no |
| <a name="input_alb_domain_name"></a> [alb\_domain\_name](#input\_alb\_domain\_name) | Domain name for the ALB certificate and Route53 alias (e.g. vpn.example.com) | `string` | n/a | yes |
| <a name="input_alb_subnet_ids"></a> [alb\_subnet\_ids](#input\_alb\_subnet\_ids) | Public subnet IDs for the ALB (minimum 2 AZs) | `list(string)` | n/a | yes |
| <a name="input_asg_desired_capacity"></a> [asg\_desired\_capacity](#input\_asg\_desired\_capacity) | Desired number of instances. Set > 1 only with multi\_instance\_mode = true. | `number` | `1` | no |
| <a name="input_asg_max_size"></a> [asg\_max\_size](#input\_asg\_max\_size) | n/a | `number` | `2` | no |
| <a name="input_asg_min_size"></a> [asg\_min\_size](#input\_asg\_min\_size) | n/a | `number` | `1` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region | `string` | `"eu-west-1"` | no |
| <a name="input_cognito_additional_callback_urls"></a> [cognito\_additional\_callback\_urls](#input\_cognito\_additional\_callback\_urls) | Additional OAuth2 callback URLs (e.g. http://localhost:8080/callback for local dev) | `list(string)` | `[]` | no |
| <a name="input_cognito_domain_prefix"></a> [cognito\_domain\_prefix](#input\_cognito\_domain\_prefix) | Cognito hosted UI domain prefix (must be globally unique) | `string` | n/a | yes |
| <a name="input_cognito_user_pool_name"></a> [cognito\_user\_pool\_name](#input\_cognito\_user\_pool\_name) | Name for the Cognito User Pool | `string` | `"openvpn-auth-pool"` | no |
| <a name="input_cognito_vpn_group_name"></a> [cognito\_vpn\_group\_name](#input\_cognito\_vpn\_group\_name) | Cognito group name required for VPN access | `string` | `"vpn-users"` | no |
| <a name="input_cost_saving_mode"></a> [cost\_saving\_mode](#input\_cost\_saving\_mode) | Skip ALB, EIP, and compute resources (ASG). Secrets and Cognito are preserved. | `bool` | `false` | no |
| <a name="input_daemon_binary_s3_uri"></a> [daemon\_binary\_s3\_uri](#input\_daemon\_binary\_s3\_uri) | S3 URI for the daemon binary (e.g. s3://bucket/openvpn-auth-daemon) | `string` | `""` | no |
| <a name="input_ec2_ami_id"></a> [ec2\_ami\_id](#input\_ec2\_ami\_id) | Custom AMI ID. Leave empty to use latest Ubuntu 24.04 LTS. | `string` | `""` | no |
| <a name="input_ec2_associate_public_ip"></a> [ec2\_associate\_public\_ip](#input\_ec2\_associate\_public\_ip) | Assign a temporary public IP at launch for cloud-init internet access. The EIP replaces it once ALB health checks pass. | `bool` | `true` | no |
| <a name="input_ec2_instance_type"></a> [ec2\_instance\_type](#input\_ec2\_instance\_type) | EC2 instance type for the VPN server | `string` | `"t3.small"` | no |
| <a name="input_ec2_root_volume_size"></a> [ec2\_root\_volume\_size](#input\_ec2\_root\_volume\_size) | Root EBS volume size in GB | `number` | `20` | no |
| <a name="input_ec2_subnet_ids"></a> [ec2\_subnet\_ids](#input\_ec2\_subnet\_ids) | Subnet IDs for the VPN server ASG (public subnets with IGW route required) | `list(string)` | n/a | yes |
| <a name="input_hand_window"></a> [hand\_window](#input\_hand\_window) | Seconds allowed for browser-based auth. Synced between OpenVPN server config and daemon --hand-window. | `number` | `300` | no |
| <a name="input_lambda_router_zip_path"></a> [lambda\_router\_zip\_path](#input\_lambda\_router\_zip\_path) | Local path to the pre-built Lambda Router zip file (e.g. lambda-router/lambda-arm64.zip) | `string` | `""` | no |
| <a name="input_lambda_subnet_ids"></a> [lambda\_subnet\_ids](#input\_lambda\_subnet\_ids) | Subnet IDs for the Lambda Router function (private subnets with VPC routing) | `list(string)` | `[]` | no |
| <a name="input_multi_instance_mode"></a> [multi\_instance\_mode](#input\_multi\_instance\_mode) | Enable multi-instance ASG mode. When true: NLB is used for OpenVPN client traffic, Lambda Router handles callback routing through a single /callback/* ALB rule, EIP association is disabled, and callback URLs are resolved at boot from the instance private IP. When false (default): static ALB rules are created per listener, EIP association is enabled, and a single server\_name is used in the callback path. | `bool` | `false` | no |
| <a name="input_nlb_domain_name"></a> [nlb\_domain\_name](#input\_nlb\_domain\_name) | Domain name for the NLB Route53 alias (e.g. vpn-nlb.example.com). Used only in multi-instance mode. | `string` | `""` | no |
| <a name="input_openvpn_allowed_cidrs"></a> [openvpn\_allowed\_cidrs](#input\_openvpn\_allowed\_cidrs) | CIDR blocks allowed to connect to OpenVPN | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_openvpn_listeners"></a> [openvpn\_listeners](#input\_openvpn\_listeners) | Map of OpenVPN listeners. Must contain 'udp' and 'tcp' keys. | <pre>map(object({<br/>    openvpn_port = number<br/>    ip_protocol  = string<br/>    client_cidr  = string<br/>    daemon_port  = number<br/>  }))</pre> | <pre>{<br/>  "tcp": {<br/>    "client_cidr": "10.8.1.0/24",<br/>    "daemon_port": 8081,<br/>    "ip_protocol": "tcp",<br/>    "openvpn_port": 1195<br/>  },<br/>  "udp": {<br/>    "client_cidr": "10.8.0.0/24",<br/>    "daemon_port": 8080,<br/>    "ip_protocol": "udp",<br/>    "openvpn_port": 1194<br/>  }<br/>}</pre> | no |
| <a name="input_openvpn_version"></a> [openvpn\_version](#input\_openvpn\_version) | Pinned OpenVPN CE version for apt install (e.g. '2.6.19'). The distro suffix is appended automatically. | `string` | `"2.6.19"` | no |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming and tagging | `string` | `"openvpn-auth-aws"` | no |
| <a name="input_required_group"></a> [required\_group](#input\_required\_group) | Cognito group required for VPN access, passed to daemon --required-group | `string` | `"vpn-users"` | no |
| <a name="input_route53_hosted_zone_id"></a> [route53\_hosted\_zone\_id](#input\_route53\_hosted\_zone\_id) | Route53 hosted zone ID for ACM DNS validation and ALB alias record | `string` | n/a | yes |
| <a name="input_server_name"></a> [server\_name](#input\_server\_name) | Unique server name used in static ALB callback path (e.g. '01'). Used only when multi\_instance\_mode = false. | `string` | `"01"` | no |
| <a name="input_vpc_cidr"></a> [vpc\_cidr](#input\_vpc\_cidr) | VPC CIDR block used by Lambda Router to validate EC2 private IPs (e.g. 10.0.0.0/16) | `string` | `""` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID for ALB and VPN server | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_alb_arn"></a> [alb\_arn](#output\_alb\_arn) | ALB ARN |
| <a name="output_alb_dns_name"></a> [alb\_dns\_name](#output\_alb\_dns\_name) | ALB DNS name |
| <a name="output_asg_name"></a> [asg\_name](#output\_asg\_name) | Auto Scaling Group name |
| <a name="output_callback_urls"></a> [callback\_urls](#output\_callback\_urls) | Callback URLs per listener (static in single-instance mode) |
| <a name="output_cognito_client_id"></a> [cognito\_client\_id](#output\_cognito\_client\_id) | Cognito User Pool Client ID |
| <a name="output_cognito_issuer_url"></a> [cognito\_issuer\_url](#output\_cognito\_issuer\_url) | Cognito issuer URL for JWT validation |
| <a name="output_cognito_user_pool_arn"></a> [cognito\_user\_pool\_arn](#output\_cognito\_user\_pool\_arn) | Cognito User Pool ARN |
| <a name="output_cognito_user_pool_id"></a> [cognito\_user\_pool\_id](#output\_cognito\_user\_pool\_id) | Cognito User Pool ID |
| <a name="output_nlb_dns_name"></a> [nlb\_dns\_name](#output\_nlb\_dns\_name) | NLB DNS name (null in single-instance or cost-saving mode) |
| <a name="output_ssm_session_command"></a> [ssm\_session\_command](#output\_ssm\_session\_command) | AWS CLI command to find the VPN instance and start an SSM session |
| <a name="output_vpn_public_ip"></a> [vpn\_public\_ip](#output\_vpn\_public\_ip) | Elastic IP of the VPN server (null in multi-instance or cost-saving mode) |
<!-- END_TF_DOCS -->
