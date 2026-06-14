# diagnostics (services layer Helm chart)

Deploys the application tier on top of the Terraform foundation in `infra/`:

- the self-hosted **OAuth authorization server** (`oauth_server.py`), Postgres-backed
  and running multiple replicas behind a shared signing key, and
- the **OAuth-protected MCP diagnostic servers** (`serve_http_auth.py <module>`),

all fronted by a **single AWS ALB** (one Ingress, one `group.name`) terminating TLS
with the ACM wildcard cert. Each service is exposed at `https://<name>.<domain>`.

This chart does **not** create the namespace, the database, or the secrets — those
come from `infra/` (RDS) and External Secrets Operator (`infra/eso-manifests/`).

## What it consumes from Terraform

| Value | Source |
| --- | --- |
| `image.repository` | `terraform output -raw ecr_repository_url` |
| `domain` | `terraform output -raw domain_name` |
| `ingress.certificateArn` | `terraform output -raw acm_certificate_arn` |
| `serviceAccount.roleArn` | `terraform output -raw diag_app_role_arn` (IRSA) |
| `secrets.signing` / `secrets.db` | ESO `Secret/oauth-signing`, `Secret/oauth-db` |

## Prerequisites

1. The infra runbook (`infra/README.md`) is complete: cluster up, ESO secrets
   `oauth-signing` and `oauth-db` materialized in the `diagnostics` namespace,
   ALB controller installed, DNS + ACM validated.
2. Create the demo-user secret the AS reads (kept out of git):

   ```bash
   kubectl -n diagnostics create secret generic oauth-admin \
     --from-literal=username=admin \
     --from-literal=password_hash="$(python oauth_server.py hash 'CHANGE-ME')"
   ```

## Install

```bash
helm install diagnostics charts/diagnostics -n diagnostics \
  --set image.repository=$(terraform -chdir=infra output -raw ecr_repository_url) \
  --set domain=$(terraform -chdir=infra output -raw domain_name) \
  --set ingress.certificateArn=$(terraform -chdir=infra output -raw acm_certificate_arn) \
  --set serviceAccount.roleArn=$(terraform -chdir=infra output -raw diag_app_role_arn)
```

Render locally without installing: `helm template diagnostics charts/diagnostics -f your-values.yaml`.

## Notes

- **Health checks**: every pod serves an unauthenticated `GET /healthz` (200); the
  ALB uses it as the target-group health check. `/mcp` stays bearer-token gated.
- **Replicas are safe** because the AS is Postgres-backed (single-use codes/refresh
  tokens are enforced atomically in the DB) and all replicas share one signing key.
- **`raw: true` servers** (`nmap`, `tshark`, `netdiag`) get `NET_RAW`/`NET_ADMIN`
  but, in EKS, only see the cluster network — host networking is intentionally not
  enabled. Host them inside the network you want to diagnose for real LAN visibility.
  These pods also require the namespace not to enforce the `restricted` Pod Security
  Standard.
- Trim `servers:` in values to deploy only a subset.
