# Three buckets, all private by construction:
#   kyc        - customer KYC documents (V-CLD-02, V-CLD-03)
#   logs       - S3 access logs and VPC flow logs
#   cloudtrail - audit trail, Object Lock in Governance mode (V-CLD-06)

locals {
  buckets = {
    kyc = { kms = "data", object_lock = false }
    # SSE-S3, not KMS: S3 server access logs and ALB access logs cannot be
    # delivered to a KMS-encrypted bucket.
    logs       = { kms = null, object_lock = false }
    cloudtrail = { kms = "logs", object_lock = true }
  }
}

resource "aws_s3_bucket" "kyc" {
  bucket              = "${local.name}-kyc-${local.account_id}"
  object_lock_enabled = local.buckets.kyc.object_lock
}

resource "aws_s3_bucket" "logs" {
  bucket              = "${local.name}-logs-${local.account_id}"
  object_lock_enabled = local.buckets.logs.object_lock
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket              = "${local.name}-cloudtrail-${local.account_id}"
  object_lock_enabled = local.buckets.cloudtrail.object_lock
}

locals {
  bucket_ids = {
    kyc        = aws_s3_bucket.kyc.id
    logs       = aws_s3_bucket.logs.id
    cloudtrail = aws_s3_bucket.cloudtrail.id
  }
  bucket_arns = {
    kyc        = aws_s3_bucket.kyc.arn
    logs       = aws_s3_bucket.logs.arn
    cloudtrail = aws_s3_bucket.cloudtrail.arn
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = local.bucket_ids

  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACLs disabled entirely: ownership is the bucket owner's, always.
resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.bucket_ids

  bucket = each.value
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = local.bucket_ids

  bucket = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.buckets[each.key].kms == null ? "AES256" : "aws:kms"
      kms_master_key_id = local.buckets[each.key].kms == null ? null : aws_kms_key.this[local.buckets[each.key].kms].arn
    }
    bucket_key_enabled = local.buckets[each.key].kms != null
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = local.bucket_ids

  bucket = each.value
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
  depends_on = [aws_s3_bucket_versioning.this]
}

# Server access logs for the two data buckets land in the logs bucket.
resource "aws_s3_bucket_logging" "kyc" {
  bucket        = aws_s3_bucket.kyc.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/kyc/"
}

resource "aws_s3_bucket_logging" "cloudtrail" {
  bucket        = aws_s3_bucket.cloudtrail.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/cloudtrail/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration { days = 400 }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "kyc" {
  bucket = aws_s3_bucket.kyc.id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

# --- Bucket policies ----------------------------------------------------

data "aws_iam_policy_document" "tls_only" {
  for_each = local.bucket_arns

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value, "${each.value}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

data "aws_iam_policy_document" "kyc" {
  source_policy_documents = [data.aws_iam_policy_document.tls_only["kyc"].json]

  # Defence in depth on top of the key policy: refuse any write that is
  # not SSE-KMS.
  statement {
    sid       = "DenyUnencryptedUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.kyc.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

data "aws_elb_service_account" "main" {}

data "aws_iam_policy_document" "logs" {
  source_policy_documents = [data.aws_iam_policy_document.tls_only["logs"].json]

  statement {
    sid       = "S3ServerAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/s3-access/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # ALB access logs. Regions opened before Aug 2022 (eu-west-2 included)
  # write as a regional ELB account, not a service principal.
  statement {
    sid       = "AlbAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/alb/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.main.arn]
    }
  }

  statement {
    sid       = "ConfigAclCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "ConfigWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/config/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "VpcFlowLogsWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/vpc-flow/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "VpcFlowLogsAclCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "cloudtrail" {
  source_policy_documents = [data.aws_iam_policy_document.tls_only["cloudtrail"].json]

  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.name}"]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.name}"]
    }
  }
}

resource "aws_s3_bucket_policy" "kyc" {
  bucket     = aws_s3_bucket.kyc.id
  policy     = data.aws_iam_policy_document.kyc.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.logs.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket     = aws_s3_bucket.cloudtrail.id
  policy     = data.aws_iam_policy_document.cloudtrail.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}
