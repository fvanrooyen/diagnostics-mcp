terraform {
  required_version = ">= 1.6"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.4"
    }
  }
}

# Reads VAULT_ADDR and VAULT_TOKEN from the environment. After `vault operator
# init`, export the root (or a sufficiently-privileged) token and port-forward:
#   kubectl -n vault port-forward svc/vault 8200:8200
#   export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root-token>
provider "vault" {}
