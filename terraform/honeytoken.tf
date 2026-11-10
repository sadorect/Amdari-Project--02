# A decoy IAM user whose key sits in an unremarkable secret. It has no
# permissions at all (explicit deny), so the only thing it can do is get
# used, and any use is a high-confidence signal that credentials were read
# by someone who should not have. Nothing in the application reads it.
#
# Limits: the access key's secret is in Terraform state (encrypted if you move
# state to the S3 backend), and EventBridge only sees events in this region
# plus global ones the trail delivers here; a call to a regional endpoint in
# another region would not fire the rule.

resource "aws_iam_user" "honeytoken" {
  name = "svc-backup-sync"
  path = "/service/"
}

data "aws_iam_policy_document" "honeytoken_deny" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "honeytoken" {
  name   = "deny-all"
  user   = aws_iam_user.honeytoken.name
  policy = data.aws_iam_policy_document.honeytoken_deny.json
}

resource "aws_iam_access_key" "honeytoken" {
  user = aws_iam_user.honeytoken.name
}

resource "aws_secretsmanager_secret" "honeytoken" {
  name                    = "${local.name}/legacy/backup-sync-credentials"
  description             = "Legacy backup sync credentials"
  kms_key_id              = aws_kms_key.this["secrets"].arn
  recovery_window_in_days = var.deletion_protection ? 30 : 0
}

resource "aws_secretsmanager_secret_version" "honeytoken" {
  secret_id = aws_secretsmanager_secret.honeytoken.id
  secret_string = jsonencode({
    aws_access_key_id     = aws_iam_access_key.honeytoken.id
    aws_secret_access_key = aws_iam_access_key.honeytoken.secret
  })
}

resource "aws_cloudwatch_event_rule" "honeytoken_used" {
  name        = "${local.name}-honeytoken-used"
  description = "Any API call made with the decoy svc-backup-sync credentials"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail        = { userIdentity = { userName = [aws_iam_user.honeytoken.name] } }
  })
}

resource "aws_cloudwatch_event_target" "honeytoken_sns" {
  rule = aws_cloudwatch_event_rule.honeytoken_used.name
  arn  = aws_sns_topic.security.arn
}

resource "aws_cloudwatch_event_target" "honeytoken_response" {
  rule = aws_cloudwatch_event_rule.honeytoken_used.name
  arn  = aws_lambda_function.response.arn
}
