# RDS Postgres backs the OAuth authorization server's state. The master password
# is AWS-managed (manage_master_user_password = true), so it lives in an
# AWS-managed Secrets Manager secret and NEVER enters Terraform state. External
# Secrets Operator reads it from there (see eso-manifests/).

resource "aws_db_subnet_group" "oauth" {
  name       = "${var.name}-oauth"
  subnet_ids = module.vpc.private_subnets
  tags       = var.tags
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.name}-rds-"
  description = "Postgres access from EKS nodes only"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Postgres from EKS nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "oauth" {
  identifier     = "${var.name}-oauth"
  engine         = "postgres"
  engine_version = "16" # picks latest 16.x minor; verify availability in-region
  instance_class = var.db_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = "oauth"
  username = "oauthadmin"
  # AWS generates + manages the password in Secrets Manager (JSON: username/password)
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.oauth.name
  vpc_security_group_ids  = [aws_security_group.rds.id]
  multi_az                = var.db_multi_az
  publicly_accessible     = false
  backup_retention_period = 7
  deletion_protection     = false # set true for prod
  skip_final_snapshot     = true  # set false for prod

  tags = var.tags
}
