terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # State lives in S3 (created by bootstrap/): encrypted with its own KMS key,
  # versioned, locked with S3 native lockfiles. The bucket name carries the
  # account id; change it if this stack is ever deployed to another account.
  backend "s3" {
    bucket       = "sentinelpay-tfstate-723799951407"
    key          = "sentinelpay/terraform.tfstate"
    region       = "eu-west-2"
    encrypt      = true
    kms_key_id   = "alias/sentinelpay-tfstate"
    use_lockfile = true
  }
}
