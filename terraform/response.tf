# Automated containment for high-severity GuardDuty findings and honeytoken
# use. See lambda/response.py for exactly what it will and will not do.

variable "protected_iam_users" {
  description = "IAM users the response function must never quarantine (the human admin, break-glass)."
  type        = list(string)
  default     = ["cloudproject"]
}

variable "response_dry_run" {
  description = "Log what the response function would do without doing it."
  type        = bool
  default     = false
}

data "archive_file" "response" {
  type        = "zip"
  source_file = "${path.module}/lambda/response.py"
  output_path = "${path.module}/.build/response.zip"
}

resource "aws_cloudwatch_log_group" "response" {
  name              = "/aws/lambda/${local.name}-response"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.this["logs"].arn
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "response" {
  name               = "${local.name}-security-response"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "response" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.response.arn}:*"]
  }
  statement {
    sid       = "ContainIamUsers"
    actions   = ["iam:UpdateAccessKey", "iam:PutUserPolicy"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/*"]
  }
  # Belt and braces with PROTECTED_USERS: the IAM policy itself refuses to
  # touch the human admin, even if the code or its config is wrong.
  statement {
    sid       = "NeverTouchProtectedUsers"
    effect    = "Deny"
    actions   = ["iam:*"]
    resources = [for u in var.protected_iam_users : "arn:${local.partition}:iam::${local.account_id}:user/${u}"]
  }
  statement {
    sid       = "StopTasksInThisCluster"
    actions   = ["ecs:StopTask"]
    resources = ["arn:${local.partition}:ecs:${var.region}:${local.account_id}:task/${aws_ecs_cluster.this.name}/*"]
  }
}

resource "aws_iam_role_policy" "response" {
  name   = "contain"
  role   = aws_iam_role.response.id
  policy = data.aws_iam_policy_document.response.json
}

resource "aws_lambda_function" "response" {
  function_name    = "${local.name}-response"
  role             = aws_iam_role.response.arn
  runtime          = "python3.12"
  handler          = "response.handler"
  filename         = data.archive_file.response.output_path
  source_code_hash = data.archive_file.response.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      PROTECTED_USERS = join(",", var.protected_iam_users)
      DRY_RUN         = tostring(var.response_dry_run)
    }
  }

  depends_on = [aws_cloudwatch_log_group.response, aws_iam_role_policy.response]
}

resource "aws_lambda_permission" "guardduty" {
  statement_id  = "AllowGuardDutyRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high.arn
}

resource "aws_lambda_permission" "honeytoken" {
  statement_id  = "AllowHoneytokenRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.honeytoken_used.arn
}

resource "aws_cloudwatch_event_target" "guardduty_response" {
  rule = aws_cloudwatch_event_rule.guardduty_high.name
  arn  = aws_lambda_function.response.arn
}
