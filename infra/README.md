# Diagnostics Platform — Infrastructure (Terraform)

Provisions the AWS foundation the diagnostics services run on:

- **VPC** (3 AZs, public + private subnets, single NAT) tagged for EKS load balancers
- **EKS** cluster (module v20) with a managed node group, IRSA (OIDC), core add-ons
- **ECR** repository for the diagnostics container image
- **RDS Postgres** for the OAuth authorization server's state
- **IRSA roles** for the AWS Load Balancer Controller and the diagnostics pods
- **AWS Load Balancer Controller** (Helm) so Ingress -> ALB works
- **Secrets**: the OAuth RSA signing key + DB URL in Secrets Manager, mirrored into
  a Kubernetes Secret the services mount

The application Deployments/Services/Ingress are the **services layer** (next step),
not part of this. This stops at a ready cluster + image registry + secrets + DB.

## Prerequisites

- Terraform >= 1.6, AWS CLI v2 (authenticated), kubectl, helm
- An S3 backend for state (recommended — the OAuth signing key is in state, so use
  SSE-KMS and locked-down access). Add a `backend "s3"` block to versions.tf.

## Stand it up

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # edit as needed
terraform init
terraform plan
terraform apply

# point kubectl at the cluster (see the output)
$(terraform output -raw configure_kubectl)
kubectl get nodes
```

## What you get out

`terraform output` gives you the cluster name, the ECR repo URL to push the image
to, the namespace, the diagnostics IRSA role ARN (to annotate the ServiceAccount),
the RDS endpoint, and the secret ARNs — everything the services layer consumes.

## Notes & honest caveats

- **Not apply-tested in this environment** (no AWS creds / registry access here).
  The HCL is syntax-checked and faithful to the pinned module schemas, but run
  `terraform plan` and expect to nudge a couple of pinned versions (the ALB chart
  version and the RDS `engine_version` especially) to what's current in your account.
- **Module pinning**: EKS module is pinned to `~> 20.31` deliberately. v21 removed
  native IRSA in favor of EKS Pod Identity and renamed inputs; upgrading means
  revisiting `iam.tf` and the ServiceAccount annotations.
- **Secrets in state**: `tls_private_key` puts the OAuth signing key in tfstate.
  Encrypt state; for prod consider generating the key in-cluster or signing via KMS,
  and/or External Secrets Operator instead of the Terraform-managed k8s Secret.
- **Cost**: a NAT gateway, an EKS control plane, 2x t3.large nodes, and an RDS
  instance run ~$10–15/day. `single_nat_gateway = true` and small nodes keep it down;
  `terraform destroy` when you're done experimenting.
- **Public endpoint**: `cluster_endpoint_public_access = true` for convenience; set
  `cluster_endpoint_public_access_cidrs` to your IP for anything real.

---

## Secrets (Vault + ESO), DNS & certificates

This build now provisions HashiCorp **Vault** (HA Raft + KMS auto-unseal) as the
source of truth for the OAuth signing key, **External Secrets Operator** to sync
secrets into the cluster, a **Route 53** public zone, and a DNS-validated **ACM**
wildcard cert. Because Vault must be initialized by hand once, this is staged.

### Secret flow
- OAuth RSA signing key: lives in **Vault** (`secret/oauth/signing`), seeded by you
  (never in tfstate) → ESO `vault-backend` store → `Secret/oauth-signing`.
- DB password: **AWS-managed** by RDS in Secrets Manager (never in tfstate) → ESO
  `aws-secrets` store → templated into `Secret/oauth-db` as a full `database_url`.

### Order of operations

```bash
# 1. Stand up the platform (cluster, RDS, Vault, ESO, Route53 zone, ACM cert)
cd infra
terraform init
terraform apply            # may pause on aws_acm_certificate_validation — see step 2

# 2. Activate DNS: point your registrar's NS records at the zone's name servers
terraform output route53_name_servers
#    Once propagated, ACM validation completes (re-run apply if it timed out).

# 3. Point kubectl at the cluster
$(terraform output -raw configure_kubectl)

# 4. Initialize Vault ONCE, then configure it (stage 2)
kubectl -n vault exec -it vault-0 -- vault operator init    # store recovery keys + root token safely
cd vault-config
kubectl -n vault port-forward svc/vault 8200:8200 &
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root-token>
terraform init && terraform apply        # KV mount + k8s auth + ESO role/policy

# 5. Seed the signing key into Vault (kept out of all state)
openssl genrsa 2048 > /tmp/k.pem
vault kv put secret/oauth/signing signing_key.pem=@/tmp/k.pem && shred -u /tmp/k.pem

# 6. Apply the ESO stores + external secrets (substitute the placeholders first)
cd ../eso-manifests
#    set region in clustersecretstore-aws.yaml; set <RDS_ENDPOINT>/<RDS_SECRET_NAME>
#    in externalsecret-db.yaml (from `terraform output`).
kubectl apply -f clustersecretstore-vault.yaml -f clustersecretstore-aws.yaml
kubectl apply -f externalsecret-signing.yaml -f externalsecret-db.yaml

# 7. Verify the secrets materialized
kubectl -n diagnostics get externalsecret      # SYNCED=True
kubectl -n diagnostics get secret oauth-signing oauth-db
```

After this, the services layer just mounts `oauth-signing` and `oauth-db`, and
Ingresses reference the ACM cert via `alb.ingress.kubernetes.io/certificate-arn`.

### Caveats (read these)
- **Vault/ESO/Helm pieces are version-sensitive and not functionally tested here.**
  Verify chart versions (`vault_chart_version`, `eso_chart_version`) and the ESO
  CRD apiVersion (`external-secrets.io/v1`) against what installs in your cluster.
- **Vault TLS is disabled on the internal listener** for simplicity; enable TLS and
  lock down the Vault service for production.
- **`vault operator init` is a one-time manual step** by design — the recovery keys
  and root token are the keys to the kingdom; store them in a separate secure place.
- The ESO `aws-secrets` store region is hard-coded in the manifest — keep it in sync
  with `var.region`.
