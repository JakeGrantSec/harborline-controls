# IAM Access Analyzer for this account: reports resources shared outside the account.

resource "aws_accessanalyzer_analyzer" "harborline" {
  analyzer_name = "harborline-access-analyzer"
  type          = "ACCOUNT"
}
