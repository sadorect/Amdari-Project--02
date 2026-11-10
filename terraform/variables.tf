variable "region" {
  description = "AWS region. Pick an enabled-by-default region; opt-in regions (e.g. af-south-1) must be enabled on the account first."
  type        = string
  default     = "eu-west-2"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "github_oidc_subject_prefix" {
  description = "Prefix of the GitHub OIDC `sub` claim for this repo. Repos with immutable subject claims enabled use numeric IDs: `gh api repos/OWNER/REPO/actions/oidc/customization/sub` returns the exact sub_claim_prefix. Otherwise it is repo:OWNER/REPO."
  type        = string
  default     = "repo:sadorect@24244892/Amdari-Project--02@1447932521"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "nat_gateway_per_az" {
  description = "One NAT gateway per AZ (prod posture) or a single shared one (cheaper for dev)."
  type        = bool
  default     = false
}

variable "db_multi_az" {
  type    = bool
  default = false
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "alert_email" {
  description = "Email subscribed to the security-findings SNS topic. Empty skips the subscription."
  type        = string
  default     = ""
}

variable "desired_count" {
  type    = number
  default = 1
}

variable "certificate_arn" {
  description = "ACM certificate for the ALB HTTPS listener. Empty falls back to HTTP only, which is NOT acceptable beyond a throwaway dev stack."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Image tag deployed to ECS. CI pushes :latest today; pin to a digest once the Week 3 pipeline lands."
  type        = string
  default     = "latest"
}

variable "deletion_protection" {
  description = "Protects RDS and the ALB from deletion, keeps a final RDS snapshot and a 30-day Secrets Manager recovery window. Set to false (and apply) BEFORE terraform destroy."
  type        = bool
  default     = true
}

variable "db_backup_retention_days" {
  description = "RDS automated backup retention. The AWS Free plan caps this at 1; use 14 on a paid plan."
  type        = number
  default     = 14
}

variable "service_db_roles" {
  description = "false: app tasks use the RDS master secret (first-apply bootstrap, before db_admin.sh roles has run). true: each service uses its own least-privilege Postgres role from sentinelpay-<env>/db/<service>. Flip to true only after scripts/db_admin.sh roles has populated those secrets."
  type        = bool
  default     = true
}
