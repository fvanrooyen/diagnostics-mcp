data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 3)
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${var.name}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  # /20 private (nodes, RDS) and /24 public (ALBs, NAT) per AZ.
  private_subnets = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i + 48)]

  enable_nat_gateway   = true
  single_nat_gateway   = true # one NAT to save cost; use one-per-AZ for HA
  enable_dns_hostnames = true
  enable_dns_support   = true

  # The AWS Load Balancer Controller discovers subnets by these tags.
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = var.tags
}
