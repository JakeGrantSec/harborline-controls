# Customer API: a regional REST API with one IAM-authorized POST /summarize
# method that invokes harborline-loan-summarizer, deployed to a prod stage with
# throttling and JSON access logs. The account ID and region are read from data
# sources and never hardcoded.

locals {
  harborline_customer_api_stage = "prod"
}

# --- API -----------------------------------------------------------------------

resource "aws_api_gateway_rest_api" "harborline_customer_api" {
  name        = "harborline-customer-api"
  description = "Customer API for loan document summaries. IAM (SigV4) authorization only."

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  # Minimum TLS 1.2 on the default execute-api endpoint. Enhanced security
  # policies (SecurityPolicy_*) require an endpoint access mode; STRICT rejects
  # requests whose host does not match this API's endpoint type.
  security_policy      = "SecurityPolicy_TLS13_1_2_2021_06"
  endpoint_access_mode = "STRICT"

  # If the API is ever replaced, create the new one before removing the old.
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_resource" "harborline_summarize" {
  rest_api_id = aws_api_gateway_rest_api.harborline_customer_api.id
  parent_id   = aws_api_gateway_rest_api.harborline_customer_api.root_resource_id
  path_part   = "summarize"
}

resource "aws_api_gateway_method" "harborline_summarize_post" {
  # No request body validator: it needs a model, and API Gateway model names
  # must be alphanumeric, so a model cannot carry the harborline- prefix. The
  # function validates document_key itself.
  rest_api_id   = aws_api_gateway_rest_api.harborline_customer_api.id
  resource_id   = aws_api_gateway_resource.harborline_summarize.id
  http_method   = "POST"
  authorization = "AWS_IAM"
}

# Non-proxy Lambda integration. The request template passes the JSON request
# body to the function unchanged, so the function receives the same event shape
# as a direct invoke: {"document_key": "..."}. Content types other than
# application/json are rejected with 415 (passthrough NEVER).
resource "aws_api_gateway_integration" "harborline_summarize_post" {
  rest_api_id             = aws_api_gateway_rest_api.harborline_customer_api.id
  resource_id             = aws_api_gateway_resource.harborline_summarize.id
  http_method             = aws_api_gateway_method.harborline_summarize_post.http_method
  type                    = "AWS"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.harborline_loan_summarizer.invoke_arn
  passthrough_behavior    = "NEVER"

  request_templates = {
    "application/json" = "$input.body"
  }
}

resource "aws_api_gateway_method_response" "harborline_summarize_post_200" {
  rest_api_id = aws_api_gateway_rest_api.harborline_customer_api.id
  resource_id = aws_api_gateway_resource.harborline_summarize.id
  http_method = aws_api_gateway_method.harborline_summarize_post.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_method_response" "harborline_summarize_post_500" {
  rest_api_id = aws_api_gateway_rest_api.harborline_customer_api.id
  resource_id = aws_api_gateway_resource.harborline_summarize.id
  http_method = aws_api_gateway_method.harborline_summarize_post.http_method
  status_code = "500"

  response_models = {
    "application/json" = "Empty"
  }
}

# Default response: the function's JSON result is returned unchanged with 200.
resource "aws_api_gateway_integration_response" "harborline_summarize_post_200" {
  rest_api_id = aws_api_gateway_rest_api.harborline_customer_api.id
  resource_id = aws_api_gateway_resource.harborline_summarize.id
  http_method = aws_api_gateway_method.harborline_summarize_post.http_method
  status_code = aws_api_gateway_method_response.harborline_summarize_post_200.status_code

  depends_on = [aws_api_gateway_integration.harborline_summarize_post]
}

# Unhandled function errors (a non-empty errorMessage) return a fixed body, so
# error messages and stack traces are never sent to the caller.
resource "aws_api_gateway_integration_response" "harborline_summarize_post_500" {
  rest_api_id       = aws_api_gateway_rest_api.harborline_customer_api.id
  resource_id       = aws_api_gateway_resource.harborline_summarize.id
  http_method       = aws_api_gateway_method.harborline_summarize_post.http_method
  status_code       = aws_api_gateway_method_response.harborline_summarize_post_500.status_code
  selection_pattern = ".+"

  response_templates = {
    "application/json" = jsonencode({ ok = false, error = "internal_error" })
  }

  depends_on = [aws_api_gateway_integration.harborline_summarize_post]
}

# Only this API's prod stage, POST /summarize, may invoke the function.
resource "aws_lambda_permission" "harborline_customer_api_invoke_summarizer" {
  statement_id   = "harborline-customer-api-invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.harborline_loan_summarizer.function_name
  principal      = "apigateway.amazonaws.com"
  source_arn     = "${aws_api_gateway_rest_api.harborline_customer_api.execution_arn}/${local.harborline_customer_api_stage}/POST${aws_api_gateway_resource.harborline_summarize.path}"
  source_account = data.aws_caller_identity.current.account_id
}

# --- Deployment and stage ------------------------------------------------------

resource "aws_api_gateway_deployment" "harborline_customer_api" {
  rest_api_id = aws_api_gateway_rest_api.harborline_customer_api.id
  description = "harborline-customer-api deployment"

  # Redeploy whenever the API definition changes. Only the IDs and the arguments
  # set in this file are hashed. Hashing whole resource objects also picked up
  # attributes AWS normalizes after apply (for example empty lists and maps),
  # which changed the hash, and replaced the deployment, on every plan.
  # Add any new API setting to this list so changing it still redeploys.
  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.harborline_summarize.id,
      aws_api_gateway_resource.harborline_summarize.path_part,

      aws_api_gateway_method.harborline_summarize_post.id,
      aws_api_gateway_method.harborline_summarize_post.http_method,
      aws_api_gateway_method.harborline_summarize_post.authorization,

      aws_api_gateway_integration.harborline_summarize_post.id,
      aws_api_gateway_integration.harborline_summarize_post.type,
      aws_api_gateway_integration.harborline_summarize_post.integration_http_method,
      aws_api_gateway_integration.harborline_summarize_post.uri,
      aws_api_gateway_integration.harborline_summarize_post.passthrough_behavior,
      aws_api_gateway_integration.harborline_summarize_post.request_templates,

      aws_api_gateway_method_response.harborline_summarize_post_200.id,
      aws_api_gateway_method_response.harborline_summarize_post_200.status_code,
      aws_api_gateway_method_response.harborline_summarize_post_200.response_models,

      aws_api_gateway_method_response.harborline_summarize_post_500.id,
      aws_api_gateway_method_response.harborline_summarize_post_500.status_code,
      aws_api_gateway_method_response.harborline_summarize_post_500.response_models,

      aws_api_gateway_integration_response.harborline_summarize_post_200.id,
      aws_api_gateway_integration_response.harborline_summarize_post_200.status_code,

      aws_api_gateway_integration_response.harborline_summarize_post_500.id,
      aws_api_gateway_integration_response.harborline_summarize_post_500.status_code,
      aws_api_gateway_integration_response.harborline_summarize_post_500.selection_pattern,
      aws_api_gateway_integration_response.harborline_summarize_post_500.response_templates,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.harborline_summarize_post,
    aws_api_gateway_integration_response.harborline_summarize_post_200,
    aws_api_gateway_integration_response.harborline_summarize_post_500,
  ]
}

resource "aws_cloudwatch_log_group" "harborline_customer_api_access_logs" {
  #checkov:skip=CKV_AWS_158:CloudWatch Logs encrypts log data at rest by default with a service-owned key. A customer managed key was not required, and the access log format contains no request or response bodies. Revisit if a customer managed key is required.
  name              = "harborline-customer-api-access-logs"
  retention_in_days = 365
}

resource "aws_api_gateway_stage" "harborline_customer_api_prod" {
  #checkov:skip=CKV_AWS_120:Caching is off on purpose. Each response is a summary of one loan document; a cache would add cost and keep copies of summaries outside the function, and the 1 request per second throttle already limits load.
  # No WAF web ACL: every method requires IAM authorization and the method is
  # throttled; see the known gaps in the pull request.
  rest_api_id   = aws_api_gateway_rest_api.harborline_customer_api.id
  deployment_id = aws_api_gateway_deployment.harborline_customer_api.id
  stage_name    = local.harborline_customer_api_stage
  description   = "Production stage of harborline-customer-api."

  xray_tracing_enabled = true

  # Metadata only; request and response bodies are never logged. requestId can
  # be set by the client, so the API Gateway generated extendedRequestId is
  # logged too.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.harborline_customer_api_access_logs.arn
    format = jsonencode({
      requestId         = "$context.requestId"
      extendedRequestId = "$context.extendedRequestId"
      callerArn         = "$context.identity.userArn"
      sourceIp          = "$context.identity.sourceIp"
      requestTime       = "$context.requestTime"
      httpMethod        = "$context.httpMethod"
      resourcePath      = "$context.resourcePath"
      status            = "$context.status"
    })
  }

  # The account-level CloudWatch Logs role must be set before access logging.
  depends_on = [aws_api_gateway_account.harborline]
}

resource "aws_api_gateway_method_settings" "harborline_summarize_post" {
  #checkov:skip=CKV_AWS_225:Caching is off on purpose; see the CKV_AWS_120 skip on the prod stage.
  # Execution logging is off: access logs record every request, and execution
  # logs would go to an API Gateway named log group with no retention set.
  rest_api_id = aws_api_gateway_rest_api.harborline_customer_api.id
  stage_name  = aws_api_gateway_stage.harborline_customer_api_prod.stage_name
  method_path = "${trimprefix(aws_api_gateway_resource.harborline_summarize.path, "/")}/${aws_api_gateway_method.harborline_summarize_post.http_method}"

  settings {
    # Cost guard.
    throttling_rate_limit  = 1
    throttling_burst_limit = 2

    metrics_enabled      = true
    logging_level        = "OFF"
    data_trace_enabled   = false
    caching_enabled      = false
    cache_data_encrypted = true
  }
}

# --- Account-level CloudWatch Logs role for API Gateway ------------------------

# ACCOUNT-WIDE SETTING: API Gateway uses one CloudWatch Logs role per account
# and region for every API. Setting it here replaces any role already set.
data "aws_iam_policy_document" "harborline_apigateway_cloudwatch_assume_role" {
  statement {
    sid     = "ApiGatewayServiceOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "harborline_apigateway_cloudwatch" {
  name               = "harborline-apigateway-cloudwatch-role"
  description        = "Account-level role API Gateway uses to write logs to CloudWatch Logs."
  assume_role_policy = data.aws_iam_policy_document.harborline_apigateway_cloudwatch_assume_role.json
}

resource "aws_iam_role_policy_attachment" "harborline_apigateway_cloudwatch" {
  role       = aws_iam_role.harborline_apigateway_cloudwatch.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "harborline" {
  cloudwatch_role_arn = aws_iam_role.harborline_apigateway_cloudwatch.arn

  depends_on = [aws_iam_role_policy_attachment.harborline_apigateway_cloudwatch]
}
