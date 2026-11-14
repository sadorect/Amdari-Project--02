# V-CLD-05 / V-PIP-03: no wildcard policies, no long-lived keys.
#   - one task role per service, scoped to exactly what that service uses
#   - a shared execution role that can only pull images and read the secrets
#     it injects
#   - a GitHub OIDC deploy role limited to this repo's main branch

# --- GitHub OIDC ---------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates GitHub's chain from its trusted CA library; the value is
  # required by the API but no longer used for verification.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "github_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Pushes to any branch build and sign images; only main may deploy
    # (enforced by the deploy job's own `if`, and by this trust policy
    # for the deploy role below).
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${var.github_oidc_subject_prefix}:*"]
    }
  }
}

resource "aws_iam_role" "github_build" {
  name                 = "sentinelpay-github-actions-build"
  assume_role_policy   = data.aws_iam_policy_document.github_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_build" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # API does not support resource-level scoping
  }
  statement {
    sid = "EcrPushPull"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer", "ecr:InitiateLayerUpload", "ecr:PutImage",
      "ecr:UploadLayerPart", "ecr:DescribeImages",
    ]
    resources = [for r in aws_ecr_repository.this : r.arn]
  }
  statement {
    sid       = "EcrKms"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.this["data"].arn]
  }
}

resource "aws_iam_role_policy" "github_build" {
  name   = "ecr-push"
  role   = aws_iam_role.github_build.id
  policy = data.aws_iam_policy_document.github_build.json
}

# Deploy role: main branch only.
data "aws_iam_policy_document" "github_deploy_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${var.github_oidc_subject_prefix}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name                 = "sentinelpay-github-actions-deploy"
  assume_role_policy   = data.aws_iam_policy_document.github_deploy_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_deploy" {
  statement {
    sid       = "EcsRedeploy"
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = [for s in aws_ecs_service.this : s.id]
  }
  statement {
    # These two actions do not support resource-level permissions.
    sid       = "EcsTaskDefinitions"
    actions   = ["ecs:DescribeTaskDefinition", "ecs:RegisterTaskDefinition"]
    resources = ["*"]
  }
  statement {
    sid     = "PassTaskRoles"
    actions = ["iam:PassRole"]
    resources = concat(
      [aws_iam_role.execution.arn],
      [for r in aws_iam_role.task : r.arn],
    )
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
  statement {
    sid       = "EcrRead"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "EcrPull"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:DescribeImages"]
    resources = [for r in aws_ecr_repository.this : r.arn]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  name   = "ecs-redeploy"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy.json
}

# --- ECS execution role (shared) ---------------------------------------------------

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "execution" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = [for r in aws_ecr_repository.this : r.arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for g in aws_cloudwatch_log_group.service : "${g.arn}:*"]
  }
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    # The master credential is only readable here during bootstrap
    # (service_db_roles = false); afterwards only the db-admin task has it.
    resources = concat(
      var.service_db_roles ? [for s in aws_secretsmanager_secret.db_app : s.arn] : [aws_db_instance.this.master_user_secret[0].secret_arn],
      [
        aws_secretsmanager_secret.redis_auth.arn,
        aws_secretsmanager_secret.jwt_public.arn,
        aws_secretsmanager_secret.jwt_private.arn,
      ],
    )
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this["secrets"].arn]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "pull-and-inject"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# --- Task roles (one per service) ------------------------------------------------------

resource "aws_iam_role" "task" {
  for_each = local.services

  name               = "${local.name}-${each.key}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

# Only kyc-api touches S3, and only the KYC bucket.
data "aws_iam_policy_document" "kyc_task" {
  statement {
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.kyc.arn}/*"]
  }
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.this["data"].arn]
  }
}

resource "aws_iam_role_policy" "kyc_task" {
  name   = "kyc-bucket"
  role   = aws_iam_role.task["kyc-api"].id
  policy = data.aws_iam_policy_document.kyc_task.json
}
