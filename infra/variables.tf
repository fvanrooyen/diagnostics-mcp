variable "name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "diag-platform"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC"
  type        = string
  default     = "10.20.0.0/16"
}

variable "kubernetes_version" {
  description = "EKS control plane version (must be a supported version)"
  type        = string
  default     = "1.33"
}

variable "node_instance_types" {
  description = "Instance types for the managed node group"
  type        = list(string)
  default     = ["t3.large"]
}

variable "node_min_size" {
  type    = number
  default = 2
}

variable "node_max_size" {
  type    = number
  default = 4
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "namespace" {
  description = "Kubernetes namespace for the diagnostics services"
  type        = string
  default     = "diagnostics"
}

variable "db_instance_class" {
  description = "RDS instance class for the OAuth state database"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_multi_az" {
  description = "Run RDS across multiple AZs (recommended for prod)"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default = {
    Project = "diagnostics-platform"
    Managed = "terraform"
  }
}

variable "domain_name" {
  description = "Public hosted zone to create and issue certs for. MUST be a domain you control (point your registrar's NS records at the zone's name servers after apply)."
  type        = string
  default     = "diag.example.com"
}

variable "vault_chart_version" {
  description = "hashicorp/vault Helm chart version (verify current with `helm search repo hashicorp/vault`)"
  type        = string
  default     = "0.28.1"
}

variable "eso_chart_version" {
  description = "external-secrets Helm chart version (verify current)"
  type        = string
  default     = "0.10.5"
}
