# KMS key for Vault auto-unseal (so Vault unseals itself on restart instead of a
# manual unseal). Vault's pod assumes the IRSA role in vault.tf to use it.
resource "aws_kms_key" "vault_unseal" {
  description             = "${var.name} Vault auto-unseal"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "vault_unseal" {
  name          = "alias/${var.name}-vault-unseal"
  target_key_id = aws_kms_key.vault_unseal.key_id
}
