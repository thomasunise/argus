terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Configure remote state before using this in a team:
  # backend "s3" {
  #   bucket         = "my-tfstate"
  #   key            = "sentinel/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "my-tfstate-lock"
  #   encrypt        = true
  # }
}

# Credentials come from the ambient AWS chain (env, profile, SSO, instance role). Nothing is
# embedded here.
provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}
