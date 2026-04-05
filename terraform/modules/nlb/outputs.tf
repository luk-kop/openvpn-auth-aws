output "target_group_arns" {
  description = "List of NLB target group ARNs (attach to ASG)"
  value       = [for tg in aws_lb_target_group.this : tg.arn]
}

output "nlb_dns_name" {
  description = "DNS name of the Network Load Balancer"
  value       = aws_lb.this.dns_name
}

output "nlb_arn" {
  description = "ARN of the Network Load Balancer"
  value       = aws_lb.this.arn
}
