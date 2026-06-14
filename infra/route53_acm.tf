# Public hosted zone for the platform's domain. After apply, set your registrar's
# NS records to this zone's name servers (see the route53_name_servers output).
resource "aws_route53_zone" "main" {
  name = var.domain_name
  tags = var.tags
}

# Wildcard cert covering the apex and *.domain, validated via DNS in the zone above.
resource "aws_acm_certificate" "wildcard" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

# DNS validation records (one per distinct domain in the cert).
resource "aws_route53_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.wildcard.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  }

  zone_id         = aws_route53_zone.main.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

# Blocks until the cert is validated. NOTE: validation only completes once your
# registrar's NS records point at this zone, so the first apply may wait here —
# set the NS records, then it proceeds (or target this resource on a second apply).
resource "aws_acm_certificate_validation" "wildcard" {
  certificate_arn         = aws_acm_certificate.wildcard.arn
  validation_record_fqdns = [for r in aws_route53_record.acm_validation : r.fqdn]
}
