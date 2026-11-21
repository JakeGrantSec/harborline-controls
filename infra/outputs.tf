output "api_invoke_url" {
  description = "Full URL of the POST /summarize endpoint (IAM SigV4 signing required)."
  value       = "${aws_api_gateway_stage.harborline_customer_api_prod.invoke_url}${aws_api_gateway_resource.harborline_summarize.path}"
}
