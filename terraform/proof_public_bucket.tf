# THROWAWAY: proves the Checkov gate fails. Never applied; this PR is closed unmerged.
resource "aws_s3_bucket" "proof_public" {
  bucket = "sentinelpay-proof-public-bucket"
}

resource "aws_s3_bucket_acl" "proof_public" {
  bucket = aws_s3_bucket.proof_public.id
  acl    = "public-read"
}
