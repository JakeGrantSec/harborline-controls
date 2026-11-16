# Audit logging: a CloudTrail trail and the S3 bucket it delivers to.
# The account ID, region and partition are read from data sources and never hardcoded.

data "aws_region" "current" {}

data "aws_partition" "current" {}

locals {
  harborline_audit_trail_name = "harborline-audit-trail"

  # Built from parts rather than referencing the trail resource, because the trail
  # depends on the bucket policy and a direct reference would create a cycle.
  harborline_audit_trail_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/${local.harborline_audit_trail_name}"
}

resource "aws_s3_bucket" "harborline_audit_logs" {
  bucket = "harborline-audit-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    purpose = "audit-log"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "harborline_audit_logs" {
  bucket = aws_s3_bucket.harborline_audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3 by requirement; no KMS on this bucket.
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "harborline_audit_logs" {
  bucket = aws_s3_bucket.harborline_audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "harborline_audit_logs" {
  bucket = aws_s3_bucket.harborline_audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "harborline_audit_logs" {
  bucket = aws_s3_bucket.harborline_audit_logs.id

  rule {
    id     = "harborline-expire-audit-logs-365-days"
    status = "Enabled"

    # Empty filter applies the rule to every object in the bucket.
    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Lifecycle rules on a versioned bucket need versioning in place first.
  depends_on = [aws_s3_bucket_versioning.harborline_audit_logs]
}

data "aws_iam_policy_document" "harborline_audit_logs" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.harborline_audit_logs.arn,
      "${aws_s3_bucket.harborline_audit_logs.arn}/*",
    ]

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

  # Standard CloudTrail bucket policy, limited to this account's trail by source ARN.
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.harborline_audit_logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.harborline_audit_trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.harborline_audit_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

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
      values   = [local.harborline_audit_trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "harborline_audit_logs" {
  bucket = aws_s3_bucket.harborline_audit_logs.id
  policy = data.aws_iam_policy_document.harborline_audit_logs.json

  # Apply the public access block first so the policy is never evaluated without it.
  depends_on = [aws_s3_bucket_public_access_block.harborline_audit_logs]
}

resource "aws_cloudtrail" "harborline_audit_trail" {
  #checkov:skip=CKV_AWS_35:The requirement for the audit log bucket is SSE-S3 (AES256) with no KMS. Setting a KMS key on the trail would make CloudTrail write SSE-KMS log files and contradict that. Log files are still encrypted at rest with SSE-S3; revisit if a customer managed key is required.
  #checkov:skip=CKV_AWS_252:No consumer for log delivery notifications exists yet, so an SNS topic would have no subscriber. Delivery does not depend on SNS; revisit when alerting on log delivery is added.
  name                          = local.harborline_audit_trail_name
  s3_bucket_name                = aws_s3_bucket.harborline_audit_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  # Management events (read and write) plus S3 object-level data events
  # (read and write) for the loan documents bucket only.
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.harborline_loan_documents.arn}/"]
    }
  }

  # CloudTrail checks the bucket policy when the trail is created.
  depends_on = [aws_s3_bucket_policy.harborline_audit_logs]
}
