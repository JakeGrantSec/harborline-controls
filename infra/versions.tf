terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # Bucket and region are supplied at init time, for example:
  #   terraform init -backend-config="bucket=<state bucket>" -backend-config="region=<region>"
  backend "s3" {
    key          = "harborline/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

# Region is intentionally not set here; it comes from the environment
# (AWS_REGION / AWS_DEFAULT_REGION or the active AWS profile).
provider "aws" {
  default_tags {
    tags = {
      scope   = "harborline"
      project = "harborline-controls"
    }
  }
}

data "aws_caller_identity" "current" {}
