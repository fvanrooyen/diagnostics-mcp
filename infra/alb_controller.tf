# Installs the AWS Load Balancer Controller so Kubernetes Ingress objects (added
# in the services layer) provision ALBs. The ServiceAccount is annotated with the
# IRSA role from iam.tf.
#
# Check the current chart version before applying:
#   helm repo add eks https://aws.github.io/eks-charts && helm repo update
#   helm search repo eks/aws-load-balancer-controller
resource "helm_release" "alb_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "1.8.1" # verify/update to the current chart version

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.lb_controller_irsa.iam_role_arn
  }
  set {
    name  = "region"
    value = var.region
  }
  set {
    name  = "vpcId"
    value = module.vpc.vpc_id
  }

  depends_on = [module.eks]
}
