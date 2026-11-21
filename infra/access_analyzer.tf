# IAM Access Analyzer for this account: reports resources shared outside the account.

resource "aws_accessanalyzer_analyzer" "harborline" {
  analyzer_name = "harborline-access-analyzer"
  type          = "ACCOUNT"
}

locals {
  harborline_iam_arn_prefix = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}"
}

# Archives the expected findings for roles that IAM Identity Center creates from
# permission sets. Each of these roles trusts the account's Identity Center SAML
# provider, which Access Analyzer reports as access by a federated principal.
#
# Only NEW findings are archived. Creating the rule does not archive existing
# active findings; that needs a separate ApplyArchiveRule call, which this
# resource does not make.
resource "aws_accessanalyzer_archive_rule" "harborline_archive_identity_center_roles" {
  analyzer_name = aws_accessanalyzer_analyzer.harborline.analyzer_name
  rule_name     = "harborline-archive-identity-center-roles"

  filter {
    criteria = "resourceType"
    eq       = ["AWS::IAM::Role"]
  }

  # Identity Center roles in this account only. The region segment after this
  # path varies (and is absent for us-east-1), so an exact match is not possible.
  filter {
    criteria = "resource"
    contains = ["${local.harborline_iam_arn_prefix}:role/aws-reserved/sso.amazonaws.com/"]
  }

  # This account's Identity Center SAML provider (AWSSSO_<id>) only.
  filter {
    criteria = "principal.Federated"
    contains = ["${local.harborline_iam_arn_prefix}:saml-provider/AWSSSO_"]
  }

  # Never archive a finding that reports public access.
  filter {
    criteria = "isPublic"
    eq       = ["false"]
  }
}
