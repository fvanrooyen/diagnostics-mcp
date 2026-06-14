resource "aws_ecr_repository" "diag" {
  name                 = "${var.name}/diagnostics"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = var.tags
}

# Keep the repo from growing unbounded: expire untagged images.
resource "aws_ecr_lifecycle_policy" "diag" {
  repository = aws_ecr_repository.diag.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 14
      }
      action = { type = "expire" }
    }]
  })
}
