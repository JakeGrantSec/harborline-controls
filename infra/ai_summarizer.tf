# AI loan document summarizer: the API key secret, the Lambda function, its
# execution role and its log group. The account ID, region and partition are
# read from data sources and never hardcoded.

locals {
  harborline_summarizer_name = "harborline-loan-summarizer"

  # Built from parts rather than referencing the function, because the role is
  # created before the function and a direct reference would create a cycle.
  harborline_summarizer_function_arn = "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${local.harborline_summarizer_name}"
}

# --- Secret --------------------------------------------------------------------

# The secret only. No secret version and no value are managed by Terraform; the
# value (the API key as a plain string) is set by hand after deployment.
resource "aws_secretsmanager_secret" "harborline_ai_feature_api_key" {
  #checkov:skip=CKV_AWS_149:The requirement for this secret is encryption with the AWS managed key (aws/secretsmanager), not a customer managed key. The value is still encrypted at rest with KMS; revisit if a customer managed key is required.
  name                    = "harborline-ai-feature-api-key"
  description             = "API key for the Claude Messages API, used by harborline-loan-summarizer. Value is set by hand."
  recovery_window_in_days = 7

  # No kms_key_id, so Secrets Manager uses the AWS managed key (aws/secretsmanager).
}

# --- Log group -----------------------------------------------------------------

resource "aws_cloudwatch_log_group" "harborline_loan_summarizer" {
  #checkov:skip=CKV_AWS_158:CloudWatch Logs encrypts log data at rest by default with a service-owned key. A customer managed key was not required; the function never logs the API key or document text. Revisit if a customer managed key is required.
  # Lambda's standard log group name; it has to start with /aws/lambda/, so it
  # cannot start with harborline-.
  name              = "/aws/lambda/${local.harborline_summarizer_name}"
  retention_in_days = 365
}

# --- Execution role ------------------------------------------------------------

data "aws_iam_policy_document" "harborline_loan_summarizer_assume_role" {
  statement {
    sid     = "LambdaServiceOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    # Confused deputy protection: only this account's summarizer function.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.harborline_summarizer_function_arn]
    }
  }
}

resource "aws_iam_role" "harborline_loan_summarizer" {
  name               = "harborline-loan-summarizer-role"
  assume_role_policy = data.aws_iam_policy_document.harborline_loan_summarizer_assume_role.json
}

data "aws_iam_policy_document" "harborline_loan_summarizer" {
  statement {
    sid       = "ReadLoanDocuments"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.harborline_loan_documents.arn}/*"]
  }

  statement {
    sid       = "ReadApiKeySecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.harborline_ai_feature_api_key.arn]
  }

  # Log streams are created by Lambda with generated names, so the streams are
  # matched with a suffix inside this one log group.
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.harborline_loan_summarizer.arn}:*"]
  }

  # No KMS statements: the loan documents bucket and the secret both use AWS
  # managed keys (aws/s3 and aws/secretsmanager), whose key policies already allow
  # decryption by principals in this account when the call comes through S3 or
  # Secrets Manager. The S3 and Secrets Manager permissions above remain the
  # controlling permissions.
}

resource "aws_iam_role_policy" "harborline_loan_summarizer" {
  name   = "harborline-loan-summarizer-policy"
  role   = aws_iam_role.harborline_loan_summarizer.id
  policy = data.aws_iam_policy_document.harborline_loan_summarizer.json
}

# --- Function ------------------------------------------------------------------

data "archive_file" "harborline_loan_summarizer" {
  type        = "zip"
  source_file = "${path.module}/lambda/loan_summarizer/handler.py"
  output_path = "${path.module}/.build/harborline-loan-summarizer.zip"
}

resource "aws_lambda_function" "harborline_loan_summarizer" {
  #checkov:skip=CKV_AWS_117:The function calls only public AWS endpoints (S3, Secrets Manager) and the Claude API over HTTPS, and has no access to private network resources. A VPC would need a NAT gateway for the API call and adds cost without reducing exposure here; revisit if it needs private resources.
  #checkov:skip=CKV_AWS_116:The function is invoked synchronously and returns its result to the caller, so there are no asynchronous events to send to a dead-letter queue.
  #checkov:skip=CKV_AWS_173:The environment variables hold only non-secret settings (model ID, bucket name, secret ARN). The API key is never put in an environment variable. Lambda still encrypts environment variables at rest with the AWS managed key.
  #checkov:skip=CKV_AWS_272:Code signing is not set up for this project yet. Changes to the function code go through pull request approval (C-07); see the known gaps in the pull request.
  #checkov:skip=CKV_AWS_115:The account's concurrency limit is too low to reserve any concurrency for this function, so no function-level limit is set. There is no per-function cost guard; see the known gaps in the pull request.
  #checkov:skip=CKV_AWS_50:X-Ray tracing needs xray:PutTraceSegments and xray:PutTelemetryRecords, which only support a wildcard resource, and the role must have no wildcard resources. Logs in CloudWatch cover this function; revisit if tracing is needed.
  function_name = local.harborline_summarizer_name
  description   = "Summarizes one loan document with the Claude Messages API."
  role          = aws_iam_role.harborline_loan_summarizer.arn

  runtime       = "python3.14"
  architectures = ["arm64"]
  handler       = "handler.lambda_handler"

  filename         = data.archive_file.harborline_loan_summarizer.output_path
  source_code_hash = data.archive_file.harborline_loan_summarizer.output_base64sha256

  timeout     = 30
  memory_size = 256

  # Non-secret settings only. The API key is read from Secrets Manager at run time.
  environment {
    variables = {
      MODEL_ID          = "claude-haiku-5-5"
      DOCUMENTS_BUCKET  = aws_s3_bucket.harborline_loan_documents.id
      API_KEY_SECRET_ID = aws_secretsmanager_secret.harborline_ai_feature_api_key.arn
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.harborline_loan_summarizer.name
  }

  # The role's permissions must exist before the function first runs.
  depends_on = [aws_iam_role_policy.harborline_loan_summarizer]
}
