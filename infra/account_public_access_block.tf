# Account-level S3 Block Public Access, all four settings on (C-06).
#
# ACCOUNT-WIDE SETTING: applies to every S3 bucket and access point in this
# account, in every region, including buckets not managed by this Terraform.
# S3 applies the most restrictive combination of account and bucket settings.
#
# account_id is not set, so the provider uses the caller's account (read at run
# time, never hardcoded). Only one of these may exist per account.
resource "aws_s3_account_public_access_block" "harborline" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
