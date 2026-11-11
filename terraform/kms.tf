# One customer-managed key per data domain so a compromise or a key policy
# mistake in one does not widen access to the others.

locals {
  kms_keys = {
    data    = "RDS, ElastiCache, KYC bucket"
    logs    = "CloudTrail, VPC flow logs, CloudWatch logs"
    secrets = "Secrets Manager"
  }
}

data "aws_iam_policy_document" "kms" {
  for_each = local.kms_keys

  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []
    content {
      sid       = "AllowLogServices"
      actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
      resources = ["*"]
      principals {
        type = "Service"
        identifiers = [
          "cloudtrail.amazonaws.com",
          "delivery.logs.amazonaws.com",
          "logs.${var.region}.amazonaws.com",
          # the security SNS topic is encrypted with this key; EventBridge
          # rules and CloudWatch alarms publish to it
          "config.amazonaws.com",
          "events.amazonaws.com",
          "cloudwatch.amazonaws.com",
        ]
      }
    }
  }
}

resource "aws_kms_key" "this" {
  for_each = local.kms_keys

  description             = "${local.name} ${each.key}: ${each.value}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms[each.key].json
}

resource "aws_kms_alias" "this" {
  for_each = local.kms_keys

  name          = "alias/${local.name}-${each.key}"
  target_key_id = aws_kms_key.this[each.key].key_id
}
