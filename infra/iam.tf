# IRSA role for the AWS Load Balancer Controller.
module "lb_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.44"

  role_name                              = "${var.name}-alb-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = var.tags
}

# IRSA role for the diagnostics pods. They consume secrets via the ESO-materialized
# Kubernetes Secrets (not directly from AWS), so this role carries no secret perms;
# it's the identity hook for the services layer (and any future AWS access).
module "diag_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.44"

  role_name = "${var.name}-diag-app"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["${var.namespace}:diagnostics"]
    }
  }

  tags = var.tags
}
