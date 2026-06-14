# Vault on EKS: HA Raft storage + KMS auto-unseal, reached in-cluster by ESO.
# Internal only (ClusterIP); not exposed publicly. TLS is disabled on the internal
# listener for simplicity here — enable TLS for production.

resource "kubernetes_namespace" "vault" {
  metadata {
    name = "vault"
  }
}

# IRSA role Vault assumes to call KMS for unseal.
module "vault_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.44"

  role_name = "${var.name}-vault-unseal"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["vault:vault"]
    }
  }

  role_policy_arns = {
    kms = aws_iam_policy.vault_kms.arn
  }

  tags = var.tags
}

resource "aws_iam_policy" "vault_kms" {
  name        = "${var.name}-vault-kms"
  description = "Vault auto-unseal via KMS"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
      Resource = [aws_kms_key.vault_unseal.arn]
    }]
  })
  tags = var.tags
}

locals {
  # HCL config injected into the Vault server. The awskms seal stanza makes Vault
  # auto-unseal; service_registration lets the chart manage active/standby labels.
  vault_config = <<-EOT
    ui = true
    listener "tcp" {
      tls_disable     = 1
      address         = "[::]:8200"
      cluster_address = "[::]:8201"
    }
    storage "raft" {
      path = "/vault/data"
    }
    seal "awskms" {
      region     = "${var.region}"
      kms_key_id = "${aws_kms_key.vault_unseal.key_id}"
    }
    service_registration "kubernetes" {}
  EOT
}

resource "helm_release" "vault" {
  name       = "vault"
  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  namespace  = kubernetes_namespace.vault.metadata[0].name
  version    = var.vault_chart_version

  values = [yamlencode({
    server = {
      serviceAccount = {
        create = true
        name   = "vault"
        annotations = {
          "eks.amazonaws.com/role-arn" = module.vault_irsa.iam_role_arn
        }
      }
      # authDelegator (default true) binds system:auth-delegator so Vault can use
      # the TokenReview API for the Kubernetes auth method.
      ha = {
        enabled = true
        raft = {
          enabled   = true
          setNodeId = true
          config    = local.vault_config
        }
      }
    }
    # ESO talks to Vault directly; the agent injector isn't needed.
    injector = {
      enabled = false
    }
  })]

  depends_on = [module.eks]
}
