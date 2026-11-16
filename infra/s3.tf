# Loan document bucket. The account ID is read at plan time and never hardcoded.
resource "aws_s3_bucket" "harborline_loan_documents" {
  bucket = "harborline-loan-documents-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "harborline_loan_documents" {
  bucket = aws_s3_bucket.harborline_loan_documents.id

  rule {
    apply_server_side_encryption_by_default {
      # No kms_master_key_id, so S3 uses the AWS managed key (aws/s3).
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "harborline_loan_documents" {
  bucket = aws_s3_bucket.harborline_loan_documents.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "harborline_loan_documents" {
  bucket = aws_s3_bucket.harborline_loan_documents.id

  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "harborline_loan_documents_tls_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.harborline_loan_documents.arn,
      "${aws_s3_bucket.harborline_loan_documents.arn}/*",
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
}

resource "aws_s3_bucket_policy" "harborline_loan_documents" {
  bucket = aws_s3_bucket.harborline_loan_documents.id
  policy = data.aws_iam_policy_document.harborline_loan_documents_tls_only.json

  # Apply the public access block first so the policy is never evaluated without it.
  depends_on = [aws_s3_bucket_public_access_block.harborline_loan_documents]
}
