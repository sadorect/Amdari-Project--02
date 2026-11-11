# Account-level settings that Security Hub's FSBP and CIS standards check.

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  max_password_age               = 90
  allow_users_to_change_password = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ssm_service_setting" "block_public_documents" {
  setting_id    = "arn:${local.partition}:ssm:${var.region}:${local.account_id}:servicesetting/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

# CIS 1.17: a role that can manage AWS Support cases.
data "aws_iam_policy_document" "support_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "support" {
  name               = "${local.name}-aws-support"
  assume_role_policy = data.aws_iam_policy_document.support_assume.json
}

resource "aws_iam_role_policy_attachment" "support" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AWSSupportAccess"
}

# ECR image and Lambda package vulnerability scanning.
resource "aws_inspector2_enabler" "this" {
  account_ids    = [local.account_id]
  resource_types = ["ECR", "LAMBDA", "LAMBDA_CODE", "EC2"]
}

# Controls that do not apply to this estate (no EKS, no EC2 instances, no
# Systems Manager) are disabled with the reason recorded, not left failing.
locals {
  fsbp_arn = "arn:${local.partition}:securityhub:${var.region}:${local.account_id}:subscription/aws-foundational-security-best-practices/v/1.0.0"
  not_applicable = {
    "GuardDuty.7"  = "No EKS clusters; the estate runs on ECS Fargate"
    "GuardDuty.13" = "No EC2 instances; Fargate runtime monitoring is enabled instead"
    "SSM.6"        = "Systems Manager Automation is not used"
    "EC2.57"       = "Systems Manager is not used; no endpoint needed"
    "EC2.58"       = "Systems Manager Incident Manager is not used"
    "EC2.60"       = "Systems Manager Incident Manager is not used"
  }
}

resource "aws_securityhub_standards_control_association" "not_applicable" {
  for_each = local.not_applicable

  standards_arn       = aws_securityhub_standards_subscription.fsbp.standards_arn
  security_control_id = each.key
  association_status  = "DISABLED"
  updated_reason      = each.value
}

# EC2.182: no public EBS snapshots, ever.
resource "aws_ebs_snapshot_block_public_access" "this" {
  state = "block-all-sharing"
}
