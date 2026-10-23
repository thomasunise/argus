resource "aws_acm_certificate" "this" {
  count             = var.acm_certificate_arn == "" ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = var.acm_certificate_arn == "" && var.hosted_zone_id != "" ? {
    for dvo in aws_acm_certificate.this[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}
  zone_id         = var.hosted_zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  count                   = var.acm_certificate_arn == "" && var.hosted_zone_id != "" ? 1 : 0
  certificate_arn         = aws_acm_certificate.this[0].arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

# The HTTPS listener must reference an ISSUED certificate. With a hosted zone the validation
# resource waits for issuance, so the listener depends on it through this local. Without a
# hosted zone (and without acm_certificate_arn) Terraform cannot validate the certificate:
# create the CNAME records from `aws acm describe-certificate` in your DNS while the apply is
# running (the listener fails on a PENDING_VALIDATION certificate; re-run apply once ISSUED).
locals {
  certificate_arn = (
    var.acm_certificate_arn != "" ? var.acm_certificate_arn :
    var.hosted_zone_id != "" ? aws_acm_certificate_validation.this[0].certificate_arn :
    aws_acm_certificate.this[0].arn
  )
}

resource "aws_lb" "this" {
  name                       = substr(local.prefix, 0, 32)
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
  idle_timeout               = 120
  enable_deletion_protection = true
  # ALB access logs: add access_logs { bucket = ... } pointing at a logging bucket for your account.
}

resource "aws_lb_target_group" "api" {
  name                 = substr("${local.prefix}-api", 0, 32)
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = aws_vpc.this.id
  deregistration_delay = 30

  health_check {
    path                = "/ready"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# /metrics is cluster-internal: block it at the edge.
resource "aws_lb_listener_rule" "block_metrics" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
  condition {
    path_pattern {
      values = ["/metrics"]
    }
  }
}

resource "aws_route53_record" "api" {
  count   = var.hosted_zone_id != "" ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}
