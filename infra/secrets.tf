# Application secrets are no longer created by Terraform. They come from:
#   - Vault (OAuth RSA signing key)             -> via ESO ClusterSecretStore "vault-backend"
#   - AWS Secrets Manager (RDS managed password) -> via ESO ClusterSecretStore "aws-secrets"
# ESO materializes both into Kubernetes Secrets in this namespace.
resource "kubernetes_namespace" "diag" {
  metadata {
    name = var.namespace
  }
}
