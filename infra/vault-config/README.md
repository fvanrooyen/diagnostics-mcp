# Stage 2 — Vault configuration

Run after Vault is deployed (infra apply) and initialized.

```bash
# 1. Init Vault ONCE (auto-unseal via KMS means no manual unseal keys to enter,
#    but you still get recovery keys + a root token — store them securely).
kubectl -n vault exec -it vault-0 -- vault operator init

# 2. Reach Vault and configure it
kubectl -n vault port-forward svc/vault 8200:8200 &
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root-token-from-init>

terraform init && terraform apply   # creates KV mount, k8s auth, ESO role/policy

# 3. Seed the OAuth signing key into Vault (kept out of Terraform state on purpose)
openssl genrsa 2048 > /tmp/signing_key.pem
vault kv put secret/oauth/signing signing_key.pem=@/tmp/signing_key.pem
shred -u /tmp/signing_key.pem
```
