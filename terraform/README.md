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
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.36.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_alb"></a> [alb](#module\_alb) | ./modules/alb | n/a |
| <a name="module_cognito"></a> [cognito](#module\_cognito) | ./modules/cognito | n/a |
| <a name="module_vpn_server"></a> [vpn\_server](#module\_vpn\_server) | ./modules/vpn-server | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_acm_certificate.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate) | resource |
| [aws_acm_certificate_validation.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acm_certificate_validation) | resource |
| [aws_eip.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_lb_listener_rule.vpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_rule) | resource |
| [aws_route53_record.acm_validation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_route53_record.alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_secretsmanager_secret.pki](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_security_group.daemon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_vpc_security_group_egress_rule.daemon_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_egress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.daemon_from_alb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.openvpn](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [aws_vpc_security_group_ingress_rule.ssh](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alb_auth_session_timeout_hours"></a> [alb\_auth\_session\_timeout\_hours](#input\_alb\_auth\_session\_timeout\_hours) | ALB authenticate-cognito session timeout in hours. | `number` | `1` | no |
| <a name="input_alb_domain_name"></a> [alb\_domain\_name](#input\_alb\_domain\_name) | Domain name for the ALB certificate (e.g. vpn-auth.example.com). Required when deploy\_compute = true. | `string` | `""` | no |
| <a name="input_alb_subnet_ids"></a> [alb\_subnet\_ids](#input\_alb\_subnet\_ids) | Public subnet IDs for the ALB (minimum 2 AZs). Required when deploy\_compute = true. | `list(string)` | `[]` | no |
| <a name="input_aws_region"></a> [aws\_region](#input\_aws\_region) | AWS region | `string` | `"eu-west-1"` | no |
| <a name="input_cognito_additional_callback_urls"></a> [cognito\_additional\_callback\_urls](#input\_cognito\_additional\_callback\_urls) | Additional OAuth2 callback URLs beyond the defaults (API Gateway and localhost for Docker testing) | `list(string)` | `[]` | no |
| <a name="input_cognito_alb_callback_urls"></a> [cognito\_alb\_callback\_urls](#input\_cognito\_alb\_callback\_urls) | OAuth2 callback URLs for the ALB (e.g. https://vpn-auth.example.com/oauth2/idpresponse) | `list(string)` | `[]` | no |
| <a name="input_cognito_domain_prefix"></a> [cognito\_domain\_prefix](#input\_cognito\_domain\_prefix) | Cognito hosted UI domain prefix (must be globally unique). Required when deploy\_cognito = true. | `string` | `""` | no |
| <a name="input_cognito_user_pool_name"></a> [cognito\_user\_pool\_name](#input\_cognito\_user\_pool\_name) | Name for the Cognito User Pool | `string` | `"openvpn-auth-pool"` | no |
| <a name="input_cognito_vpn_group_name"></a> [cognito\_vpn\_group\_name](#input\_cognito\_vpn\_group\_name) | Cognito group name required for VPN access | `string` | `"vpn-users"` | no |
| <a name="input_daemon_binary_s3_uri"></a> [daemon\_binary\_s3\_uri](#input\_daemon\_binary\_s3\_uri) | S3 URI for the daemon binary (e.g. s3://bucket/openvpn-auth-daemon). Required when deploy\_compute = true. | `string` | `""` | no |
| <a name="input_daemon_subnet_ids"></a> [daemon\_subnet\_ids](#input\_daemon\_subnet\_ids) | Subnet IDs for the daemon EC2 instance (public subnets with IGW route required — EIP needs internet connectivity). Required when deploy\_compute = true. | `list(string)` | `[]` | no |
| <a name="input_deploy_cognito"></a> [deploy\_cognito](#input\_deploy\_cognito) | Create Cognito User Pool and related resources. | `bool` | `true` | no |
| <a name="input_deploy_compute"></a> [deploy\_compute](#input\_deploy\_compute) | Create ALB and VPN server EC2 instance. Requires deploy\_cognito = true. | `bool` | `true` | no |
| <a name="input_ec2_ami_id"></a> [ec2\_ami\_id](#input\_ec2\_ami\_id) | Custom AMI ID for the OpenVPN instance. Leave empty to use latest Ubuntu 24.04 LTS. | `string` | `""` | no |
| <a name="input_ec2_associate_public_ip"></a> [ec2\_associate\_public\_ip](#input\_ec2\_associate\_public\_ip) | Assign a temporary public IP to the VPN instance at launch. The instance is in a public subnet (required by EIP) but launches without a public IP — the EIP is assigned after ALB health checks pass. Without this flag, cloud-init has no outbound internet access and cannot reach AWS APIs or install packages. The EIP replaces this temporary IP once assigned. Set to false only if using VPC Endpoints and an apt proxy. | `bool` | `true` | no |
| <a name="input_ec2_instance_type"></a> [ec2\_instance\_type](#input\_ec2\_instance\_type) | EC2 instance type for the OpenVPN server | `string` | `"t3.small"` | no |
| <a name="input_ec2_key_name"></a> [ec2\_key\_name](#input\_ec2\_key\_name) | SSH key pair name for the EC2 instance (optional if using SSM only) | `string` | `""` | no |
| <a name="input_ec2_root_volume_size"></a> [ec2\_root\_volume\_size](#input\_ec2\_root\_volume\_size) | Root EBS volume size in GB | `number` | `20` | no |
| <a name="input_hand_window"></a> [hand\_window](#input\_hand\_window) | Seconds allowed for browser-based auth. Applied to both OpenVPN server config and daemon --hand-window to keep them in sync. | `number` | `300` | no |
| <a name="input_openvpn_allowed_cidrs"></a> [openvpn\_allowed\_cidrs](#input\_openvpn\_allowed\_cidrs) | CIDR blocks allowed to connect to OpenVPN. Use ["0.0.0.0/0"] for public access. | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_openvpn_listeners"></a> [openvpn\_listeners](#input\_openvpn\_listeners) | Map of OpenVPN listeners. Each key (e.g. 'udp', 'tcp') defines an OpenVPN server instance with its VPN port, transport protocol, tunnel CIDR, and auth daemon HTTP port. | <pre>map(object({<br/>    openvpn_port = number<br/>    ip_protocol  = string<br/>    client_cidr  = string<br/>    daemon_port  = number<br/>  }))</pre> | <pre>{<br/>  "tcp": {<br/>    "client_cidr": "10.8.1.0/24",<br/>    "daemon_port": 8081,<br/>    "ip_protocol": "tcp",<br/>    "openvpn_port": 1195<br/>  },<br/>  "udp": {<br/>    "client_cidr": "10.8.0.0/24",<br/>    "daemon_port": 8080,<br/>    "ip_protocol": "udp",<br/>    "openvpn_port": 1194<br/>  }<br/>}</pre> | no |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming | `string` | `"openvpn-auth-aws"` | no |
| <a name="input_route53_hosted_zone_id"></a> [route53\_hosted\_zone\_id](#input\_route53\_hosted\_zone\_id) | Route53 hosted zone ID for ACM DNS validation. Required when deploy\_compute = true. | `string` | `""` | no |
| <a name="input_server_name"></a> [server\_name](#input\_server\_name) | Unique server name used in ALB path routing (e.g. '01'). Required when deploy\_compute = true. | `string` | `"01"` | no |
| <a name="input_ssh_allowed_cidrs"></a> [ssh\_allowed\_cidrs](#input\_ssh\_allowed\_cidrs) | CIDR blocks allowed to SSH into the OpenVPN instance. Leave empty to disable SSH ingress. | `list(string)` | `[]` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID for ALB and VPN server. Required when deploy\_compute = true. | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_alb_arn"></a> [alb\_arn](#output\_alb\_arn) | ALB ARN |
| <a name="output_alb_dns_name"></a> [alb\_dns\_name](#output\_alb\_dns\_name) | ALB DNS name (use as the base for callback URLs) |
| <a name="output_asg_name"></a> [asg\_name](#output\_asg\_name) | Auto Scaling Group name for the OpenVPN server |
| <a name="output_callback_urls"></a> [callback\_urls](#output\_callback\_urls) | Full callback URLs per listener (e.g. {udp = "https://...", tcp = "https://..."}) |
| <a name="output_cognito_client_id"></a> [cognito\_client\_id](#output\_cognito\_client\_id) | Cognito User Pool Client ID |
| <a name="output_cognito_domain_url"></a> [cognito\_domain\_url](#output\_cognito\_domain\_url) | Cognito hosted UI domain URL |
| <a name="output_cognito_issuer_url"></a> [cognito\_issuer\_url](#output\_cognito\_issuer\_url) | Cognito issuer URL for JWT validation |
| <a name="output_cognito_user_pool_arn"></a> [cognito\_user\_pool\_arn](#output\_cognito\_user\_pool\_arn) | Cognito User Pool ARN |
| <a name="output_cognito_user_pool_id"></a> [cognito\_user\_pool\_id](#output\_cognito\_user\_pool\_id) | Cognito User Pool ID |
| <a name="output_daemon_instance_profile_name"></a> [daemon\_instance\_profile\_name](#output\_daemon\_instance\_profile\_name) | IAM instance profile name for the daemon EC2 instance |
| <a name="output_daemon_security_group_id"></a> [daemon\_security\_group\_id](#output\_daemon\_security\_group\_id) | Security group ID for the daemon EC2 instance |
| <a name="output_launch_template_id"></a> [launch\_template\_id](#output\_launch\_template\_id) | Launch template ID for the OpenVPN server |
| <a name="output_ssm_session_command"></a> [ssm\_session\_command](#output\_ssm\_session\_command) | AWS CLI command to find the EC2 instance from ASG and start an SSM session |
| <a name="output_vpn_public_ip"></a> [vpn\_public\_ip](#output\_vpn\_public\_ip) | Elastic IP address of the VPN server |
<!-- END_TF_DOCS -->
