resource "aws_dynamodb_table" "harborline_loan_records" {
  #checkov:skip=CKV_AWS_119:The requirement for this table is encryption with the AWS managed KMS key (aws/dynamodb), not a customer managed key. Data is still encrypted at rest with KMS; revisit if a customer managed key is required.
  name         = "harborline-loan-records"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "loan_id"

  attribute {
    name = "loan_id"
    type = "S"
  }

  # No kms_key_arn, so DynamoDB uses the AWS managed key (aws/dynamodb).
  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}
