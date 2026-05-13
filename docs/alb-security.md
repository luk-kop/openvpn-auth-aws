# ALB Security

## Table of Contents

- [ALB-Level Settings](#alb-level-settings)
- [VPC-Internal Traffic (not encrypted)](#vpc-internal-traffic-not-encrypted)
- [AWS WAF](#aws-waf)
- [See Also](#see-also)

Security hardening for the Application Load Balancer that handles the OIDC callback and Cognito authenticate action.

## ALB-Level Settings

These are configured directly on the `aws_lb` resource and listener — no extra cost.

### Drop invalid header fields

Already enabled in `terraform/modules/alb/main.tf`:

```hcl
resource "aws_lb" "this" {
  drop_invalid_header_fields = true
  ...
}
```

Drops requests with malformed or non-compliant HTTP headers before they reach the target. Prevents header injection attacks.

### TLS policy

Already configured on the HTTPS listener:

```hcl
resource "aws_lb_listener" "https" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  ...
}
```

Enforces TLS 1.2+ and disables weak cipher suites. TLS 1.3 is preferred when the client supports it.

### Default action — 404 for unmatched paths

Already configured — the listener returns `404 Not Found` for any path that doesn't match a listener rule. This prevents accidental exposure of unintended routes.

### HTTPS only — no HTTP listener

No port 80 listener is created. The ALB only accepts HTTPS on port 443. There is no HTTP-to-HTTPS redirect because the ALB is not intended to be accessed directly by end users typing URLs — clients are redirected here by the OpenVPN client via the `WEB_AUTH::` URL.

### Security group

The ALB security group (`aws_security_group.alb`) allows:

- Inbound: HTTPS (443) from `0.0.0.0/0` — required for browser-based auth flow
- Outbound: only to EC2 daemon ports (per listener) via security group reference, and to Cognito token endpoint (443/tcp `0.0.0.0/0`)

The Cognito egress rule uses `0.0.0.0/0` because Cognito does not publish static IP ranges — this is intentional and suppressed in trivy (`AVD-AWS-0104`). No other inbound or outbound rules are created.

### Listener rule conditions

The ALB listener rule for `/callback` (defined in `terraform/modules/vpn-server/main.tf`) enforces three conditions before forwarding to the daemon:

- Path pattern: `/callback/{server}/{proto}` — only exact known paths are matched; everything else hits the default 404
- Query string: `state=*.*` — requires the `state` parameter to be present and in `{payload}.{hmac}` format (dot-separated); requests without a valid-looking state blob are rejected at the ALB before reaching the daemon
- HTTP method: `GET` only — POST, PUT, and other methods are not matched

The `state` condition uses a wildcard (`*.*`) because ALB query string conditions don't support regex. Full HMAC validation happens in the daemon — the ALB check is a cheap pre-filter.

In multi-instance mode the listener rule is defined in `terraform/modules/lambda-router/main.tf` and uses a stricter path condition:

```hcl
condition {
  path_pattern {
    regex_values = ["/callback/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/(udp|tcp)"]
  }
}
```

Instead of a named server, the path encodes the EC2 instance IP. The regex enforces the IP format at the ALB level — only paths matching `/callback/{ip}/{udp|tcp}` are forwarded to Lambda. The `state` and `GET`-only conditions are identical in both modes.

### Access logs (recommended)

Not currently enabled. To enable, add to the `aws_lb` resource:

```hcl
access_logs {
  bucket  = aws_s3_bucket.alb_logs.id
  prefix  = var.project_name
  enabled = true
}
```

Useful for auditing auth attempts and debugging WAF rule false positives.

---

## VPC-Internal Traffic (not encrypted)

### Current situation

The full callback request path is:

```
Browser → ALB (HTTPS/TLS 1.2+)
ALB → Lambda (AWS internal invoke — not HTTP, no plaintext exposure)
Lambda → EC2 daemon (plain HTTP)
ALB → EC2 daemon directly (plain HTTP — target group protocol = "HTTP")
```

The first hop (browser → ALB) is encrypted. The ALB-to-Lambda leg is not HTTP at all — ALB invokes Lambda via the AWS Lambda API as a JSON event payload, so there is no plaintext HTTP on that path regardless.

The two unencrypted hops are both VPC-internal:

- `lambda-router/main.go` constructs `http://{ec2-ip}:{port}/callback/` — OIDC headers (`x-amzn-oidc-data`, `x-amzn-oidc-accesstoken`) are forwarded over plain HTTP from Lambda to the daemon.
- `terraform/modules/vpn-server/main.tf` defines the ALB target group with `protocol = "HTTP"` — in single-instance mode the ALB forwards the callback directly to the daemon over plain HTTP.

In both cases the `x-amzn-oidc-data` JWT is already ES256-signed by the ALB's EC key, so a network-level attacker cannot forge or replay it. The confidentiality of the token (not its integrity) is the concern.

### Why this is acceptable for now

The security group configuration already enforces that only the ALB security group and the Lambda security group can reach the daemon ports — no other source can initiate a connection to those ports. Passive sniffing within the VPC requires a compromised EC2 instance or a compromised VPC flow path, which is outside the current threat model.

### How to harden (future work)

To encrypt the VPC-internal hops, the daemon's callback server would need to serve TLS. The changes required:

1. Add `--callback-tls-cert` and `--callback-tls-key` flags to the daemon config and switch `http.Serve` to `http.ServeTLS` in `internal/callback/server.go`.
2. In `lambda-router/main.go`, change `http://` to `https://` in the upstream URL and configure the `httpClient` transport with either `InsecureSkipVerify: true` (encrypts the wire, skips cert verification) or a pinned CA cert loaded from an environment variable (full mutual verification).
3. In `terraform/modules/vpn-server/main.tf`, change the target group `protocol` from `"HTTP"` to `"HTTPS"` and set `protocol_version = "HTTP1"`. The ALB supports HTTPS target groups with optional cert verification via `load_balancing.tls.cert_bound_responses`.

The existing PKI infrastructure (`pki/ca.crt`, managed via SSM) could serve as the CA for daemon TLS certs, avoiding the need for a separate certificate authority.

---

## AWS WAF

### Managed Rule Groups

| Rule Group | Priority | Rationale |
| --- | --- | --- |
| `AWSManagedRulesAmazonIpReputationList` | 10 | Blocks known malicious IPs (TOR, botnets, scanners) — cheapest filter, runs first |
| `AWSManagedRulesCommonRuleSet` | 20 | Protection against SQLi, XSS, bad inputs — standard baseline defense |
| `AWSManagedRulesKnownBadInputsRuleSet` | 30 | Blocks known exploit payloads (Log4Shell, Spring4Shell, etc.) |

### Custom Rules

#### 1. Rate limiting on `/callback` (priority 1)

The `/callback` endpoint is publicly reachable and processes JWTs. Without a rate limit it can be flooded, putting load on JWT validation and Cognito group checks.

```hcl
rule {
  name     = "RateLimitCallback"
  priority = 1

  action { block {} }

  statement {
    rate_based_statement {
      limit              = 100   # requests per 5 minutes per IP
      aggregate_key_type = "IP"

      scope_down_statement {
        byte_match_statement {
          search_string         = "/callback"
          positional_constraint = "STARTS_WITH"
          field_to_match { uri_path {} }
          text_transformation { priority = 0; type = "LOWERCASE" }
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "RateLimitCallback"
    sampled_requests_enabled   = true
  }
}
```

#### 2. Block `/callback` without `x-amzn-oidc-data` header (priority 2)

The ALB always injects `x-amzn-oidc-data` after a successful Cognito authentication. Direct requests from the internet (e.g. attempts to bypass the ALB auth flow) will not carry this header.

> This rule only makes sense if EC2 traffic flows exclusively through the ALB (security group blocks direct access). Otherwise an attacker could simply add a fake header — but the daemon will still reject the request via ES256 signature verification, provided `--alb-arn` is set so the JWT `signer` field is cross-checked against the expected ALB. See [`docs/configuration.md`](configuration.md) for the flag and [`docs/architecture.md`](architecture.md) for the full validation pipeline.

```hcl
rule {
  name     = "BlockCallbackWithoutOidcHeader"
  priority = 2

  action { block {} }

  statement {
    and_statement {
      statement {
        byte_match_statement {
          search_string         = "/callback"
          positional_constraint = "STARTS_WITH"
          field_to_match { uri_path {} }
          text_transformation { priority = 0; type = "LOWERCASE" }
        }
      }
      statement {
        not_statement {
          statement {
            size_constraint_statement {
              comparison_operator = "GT"
              size                = 0
              field_to_match {
                single_header { name = "x-amzn-oidc-data" }
              }
              text_transformation { priority = 0; type = "NONE" }
            }
          }
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "BlockCallbackWithoutOidcHeader"
    sampled_requests_enabled   = true
  }
}
```

#### 3. Size constraint on `x-amzn-oidc-data` (priority 3)

The JWT injected by the ALB has a predictable size (typically < 4 KB). Oversized headers are anomalous and may indicate buffer overflow attempts or fuzzing.

```hcl
rule {
  name     = "BlockOversizedOidcHeader"
  priority = 3

  action { block {} }

  statement {
    size_constraint_statement {
      comparison_operator = "GT"
      size                = 8192  # 8 KB — well above a typical ALB JWT
      field_to_match {
        single_header { name = "x-amzn-oidc-data" }
      }
      text_transformation { priority = 0; type = "NONE" }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "BlockOversizedOidcHeader"
    sampled_requests_enabled   = true
  }
}
```

#### 4. Geo-blocking (optional, priority 4)

If the VPN is intended only for users in specific countries, traffic from elsewhere can be dropped. Reduces the attack surface without affecting legitimate users.

```hcl
rule {
  name     = "GeoBlock"
  priority = 4

  action { block {} }

  statement {
    not_statement {
      statement {
        geo_match_statement {
          country_codes = ["PL", "DE", "US"]  # adjust to your needs
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "GeoBlock"
    sampled_requests_enabled   = true
  }
}
```

### Terraform — Web ACL

```hcl
resource "aws_wafv2_web_acl" "alb" {
  name  = "${var.project_name}-alb-waf"
  scope = "REGIONAL"

  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 10
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 20
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 30
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Custom rules — see sections above
  # rule { ... RateLimitCallback ... }
  # rule { ... BlockCallbackWithoutOidcHeader ... }
  # rule { ... BlockOversizedOidcHeader ... }
  # rule { ... GeoBlock ... }  # optional

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-alb-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "${var.project_name}-alb-waf"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
}
```

### Where to place in the project

The association (`aws_wafv2_web_acl_association`) requires the ALB ARN, so it naturally belongs in the `alb` module as a separate file:

```text
terraform/modules/alb/
├── main.tf
├── waf.tf        # ← Web ACL + association
├── variables.tf  # add: var.waf_rate_limit, var.waf_geo_countries
└── outputs.tf    # add: output "waf_web_acl_arn"
```

### Cost Estimate

Pricing for a single Web ACL attached to one ALB (us-east-1, as of 2025):

| Component | Cost/month |
| --- | --- |
| Web ACL | $5.00 |
| `AWSManagedRulesAmazonIpReputationList` | $1.00 |
| `AWSManagedRulesCommonRuleSet` | $1.00 |
| `AWSManagedRulesKnownBadInputsRuleSet` | $1.00 |
| Rate limit rule (custom) | $1.00 |
| Requests ($0.60/million) | ~$0.00 (callback endpoint has minimal traffic) |
| Total | ~$9.00/month |

If you run multiple VPN instances with separate ALBs, each requires its own Web ACL — costs multiply accordingly.

`AWSManagedRulesBotControlRuleSet` was deliberately excluded: it costs $10/month + $1/million requests and is overkill here. Every `/callback` request requires a prior Cognito hosted UI authentication flow, so bots are filtered out before they ever reach the endpoint.

### Notes

- Use `scope = "REGIONAL"` for ALB — do not confuse with `CLOUDFRONT` scope
- Start with `count` mode (instead of `block`) for custom rules to observe false positives before enabling blocking
- WAF logs can be sent to CloudWatch Logs, S3, or Kinesis Firehose — useful for debugging and auditing

## See Also

- [`docs/configuration.md`](configuration.md) — `--alb-arn` / `VPN_AUTH_ALB_ARN` flag: ALB ARN used by the daemon to validate the `signer` field in ALB-issued JWTs. If absent, JWT signature validation is skipped (dev/test only).
- [`docs/architecture.md`](architecture.md) — full callback validation pipeline (state HMAC → session lookup → `x-amzn-oidc-data` → ES256 signature + `signer` check → CN cross-check → group check).
