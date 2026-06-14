# External Secrets Operator. The chart's ServiceAccount is annotated with an IRSA
# role that can read ONLY the RDS-managed password secret (for the AWS provider
# store). The Vault store authenticates via Kubernetes auth (configured in
# vault-config/), not IRSA.

resource "kubernetes_namespace" "eso" {
  metadata {
    name = "external-secrets"
  }
}

module "eso_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.44"

  role_name = "${var.name}-eso"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["external-secrets:external-secrets"]
    }
  }

  role_policy_arns = {
    sm = aws_iam_policy.eso_read_sm.arn
  }

  tags = var.tags
}

resource "aws_iam_policy" "eso_read_sm" {
  name        = "${var.name}-eso-read-sm"
  description = "ESO reads the RDS-managed DB password secret"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = [aws_db_instance.oauth.master_user_secret[0].secret_arn]
    }]
  })
  tags = var.tags
}

resource "helm_release" "eso" {
  name       = "external-secrets"
  repository = "https://charts.external-secrets.io"
  chart      = "external-secrets"
  namespace  = kubernetes_namespace.eso.metadata[0].name
  version    = var.eso_chart_version

  set {
    name  = "installCRDs"
    value = "true"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eso_irsa.iam_role_arn
  }

  depends_on = [module.eks]
}
