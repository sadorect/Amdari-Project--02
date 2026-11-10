# Per-service Postgres roles. The secret containers are created here; the
# roles and their passwords are created by scripts/db_admin.sh, which runs
# inside the VPC as the db-admin task. The task generates each password and
# writes it straight to Secrets Manager, so it never appears in Terraform
# state, a command line, or a log.

resource "aws_secretsmanager_secret" "db_app" {
  for_each = local.services

  name                    = "${local.name}/db/${each.key}"
  description             = "Postgres login for ${each.key} (JSON: username, password)"
  kms_key_id              = aws_kms_key.this["secrets"].arn
  recovery_window_in_days = var.deletion_protection ? 30 : 0
}

locals {
  # Until the roles exist, app tasks keep using the RDS master secret.
  db_secret_arn = {
    for s in local.services : s => var.service_db_roles ? aws_secretsmanager_secret.db_app[s].arn : aws_db_instance.this.master_user_secret[0].secret_arn
  }
}

# --- db-admin: the only task allowed to read the master credential --------

resource "aws_cloudwatch_log_group" "db_admin" {
  name              = "/${local.name}/db-admin"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.this["logs"].arn
}

resource "aws_iam_role" "db_admin_execution" {
  name               = "${local.name}-db-admin-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "db_admin_execution" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = [aws_ecr_repository.this["kyc-api"].arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.db_admin.arn}:*"]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.this.master_user_secret[0].secret_arn]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this["secrets"].arn]
  }
}

resource "aws_iam_role_policy" "db_admin_execution" {
  name   = "pull-and-inject-master"
  role   = aws_iam_role.db_admin_execution.id
  policy = data.aws_iam_policy_document.db_admin_execution.json
}

resource "aws_iam_role" "db_admin_task" {
  name               = "${local.name}-db-admin-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "db_admin_task" {
  statement {
    actions   = ["secretsmanager:PutSecretValue", "secretsmanager:DescribeSecret"]
    resources = [for s in aws_secretsmanager_secret.db_app : s.arn]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.this["secrets"].arn]
  }
}

resource "aws_iam_role_policy" "db_admin_task" {
  name   = "write-service-db-secrets"
  role   = aws_iam_role.db_admin_task.id
  policy = data.aws_iam_policy_document.db_admin_task.json
}

# No service runs this; scripts/db_admin.sh starts it on demand with a
# command override. It reuses the kyc-api image (psycopg2 + boto3).
resource "aws_ecs_task_definition" "db_admin" {
  family                   = "${local.name}-db-admin"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.db_admin_execution.arn
  task_role_arn            = aws_iam_role.db_admin_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name                   = "db-admin"
    image                  = "${aws_ecr_repository.this["kyc-api"].repository_url}:${var.image_tag}"
    essential              = true
    readonlyRootFilesystem = true
    user                   = "app"
    command                = ["python", "-c", "print('db-admin: pass a command override')"]

    environment = [
      { name = "AWS_REGION", value = var.region },
      { name = "DB_HOST", value = aws_db_instance.this.address },
      { name = "DB_NAME", value = "sentinelpay" },
      { name = "DB_SSLMODE", value = "require" },
    ]
    secrets = [
      { name = "DB_USER", valueFrom = "${aws_db_instance.this.master_user_secret[0].secret_arn}:username::" },
      { name = "DB_PASSWORD", valueFrom = "${aws_db_instance.this.master_user_secret[0].secret_arn}:password::" },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.db_admin.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "db-admin"
      }
    }
  }])
}
