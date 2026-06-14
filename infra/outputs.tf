output "cluster_name" {
  value = module.eks.cluster_name
}

output "configure_kubectl" {
  description = "Run this to point kubectl at the new cluster"
  value       = "aws eks update-kubeconfig --name ${module.eks.cluster_name} --region ${var.region}"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.diag.repository_url
}

output "namespace" {
  value = kubernetes_namespace.diag.metadata[0].name
}

output "diag_app_role_arn" {
  description = "Annotate the diagnostics ServiceAccount with this (IRSA)"
  value       = module.diag_irsa.iam_role_arn
}

output "rds_endpoint" {
  description = "Substitute into the DB ExternalSecret template"
  value       = aws_db_instance.oauth.address
}

output "rds_master_secret_arn" {
  description = "AWS-managed RDS password secret; ESO reads the DB password from here"
  value       = aws_db_instance.oauth.master_user_secret[0].secret_arn
}

output "domain_name" {
  value = var.domain_name
}

output "route53_name_servers" {
  description = "Point your registrar's NS records at these to activate DNS + cert validation"
  value       = aws_route53_zone.main.name_servers
}

output "acm_certificate_arn" {
  description = "Reference this on the Ingress (alb.ingress.kubernetes.io/certificate-arn)"
  value       = aws_acm_certificate.wildcard.arn
}
