# Stage 2 — run AFTER `vault operator init` + unseal (auto-unseal via KMS handles
# unseal; you still init once). Configures Vault so ESO can authenticate and read.

# KV v2 engine at secret/ for application secrets.
resource "vault_mount" "kv" {
  path = "secret"
  type = "kv-v2"
}

# Kubernetes auth method: lets in-cluster ServiceAccounts authenticate to Vault.
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

# When Vault runs in-cluster, it validates SA tokens against the cluster API using
# its own pod credentials (the chart's authDelegator binding grants this).
resource "vault_kubernetes_auth_backend_config" "this" {
  backend         = vault_auth_backend.kubernetes.path
  kubernetes_host = "https://kubernetes.default.svc"
}

# Read-only policy on the app secret path.
resource "vault_policy" "eso" {
  name   = "eso-read"
  policy = <<-EOT
    path "secret/data/oauth/*" {
      capabilities = ["read"]
    }
  EOT
}

# Bind the ESO ServiceAccount to that policy. `audience` must match the ESO
# ClusterSecretStore's auth.kubernetes... (we use "vault").
resource "vault_kubernetes_auth_backend_role" "eso" {
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = "external-secrets"
  bound_service_account_names      = ["external-secrets"]
  bound_service_account_namespaces = ["external-secrets"]
  token_policies                   = [vault_policy.eso.name]
  token_ttl                        = 3600
  audience                         = "vault"
}
