# Synthetic sample data. Every value below is fake and exists only for testing.

locals {
  harborline_sample_loans = {
    "FAKE-0001" = {
      borrower = "Test Borrower Alpha"
      amount   = 100000
      status   = "approved"
    }
    "FAKE-0002" = {
      borrower = "Test Borrower Bravo"
      amount   = 250000
      status   = "pending"
    }
    "FAKE-0003" = {
      borrower = "Test Borrower Charlie"
      amount   = 50000
      status   = "declined"
    }
  }
}

resource "aws_s3_object" "harborline_sample_loan_documents" {
  for_each = local.harborline_sample_loans

  bucket       = aws_s3_bucket.harborline_loan_documents.id
  key          = "harborline-sample/loan-${each.key}.txt"
  content_type = "text/plain"
  content      = <<-EOT
    SYNTHETIC TEST DOCUMENT - NOT A REAL LOAN
    Loan ID:  ${each.key}
    Borrower: ${each.value.borrower}
    Amount:   ${each.value.amount} (fake)
    Status:   ${each.value.status}
  EOT

  # Objects inherit the bucket's default encryption, so wait for it to be in place.
  depends_on = [aws_s3_bucket_server_side_encryption_configuration.harborline_loan_documents]
}

resource "aws_dynamodb_table_item" "harborline_sample_loan_records" {
  for_each = local.harborline_sample_loans

  table_name = aws_dynamodb_table.harborline_loan_records.name
  hash_key   = aws_dynamodb_table.harborline_loan_records.hash_key

  item = jsonencode({
    loan_id      = { S = each.key }
    borrower     = { S = each.value.borrower }
    amount       = { N = tostring(each.value.amount) }
    status       = { S = each.value.status }
    document_key = { S = "harborline-sample/loan-${each.key}.txt" }
    synthetic    = { BOOL = true }
  })
}
