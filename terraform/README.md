# SentinelPay infrastructure (Week 2)

Single-environment Terraform for the target state in
`docs/ARCHITECTURE_NOTES.md`. Nothing here has been applied yet; it is
validated (`terraform validate`) and scanned (`trivy config`) offline.

| File | Covers |
|------|--------|
| `network.tf` | VPC, public / private / isolated tiers, VPC endpoints, flow logs (V-CLD-08) |
| `data.tf` | Private encrypted RDS (V-CLD-01), Redis with TLS + AUTH |
| `s3.tf` | KYC bucket SSE-KMS, no ACLs, public access blocked (V-CLD-02, V-CLD-03); Object Lock trail bucket |
| `detection.tf` | CloudTrail with validation + KMS (V-CLD-06), GuardDuty (V-CLD-07), Security Hub FSBP + CIS, high-severity alerts |
| `iam.tf` | Per-service task roles, GitHub OIDC build + deploy roles (V-CLD-05, V-PIP-03, V-CLD-04) |
| `ecs.tf`, `ecr.tf` | ALB, Fargate services, repositories |

## Applying

1. Configure credentials (`AWS_PROFILE`); default region `eu-west-2` (opt-in
   regions such as `af-south-1` must be enabled on the account first). The
   account must be on a paid AWS plan: the Free plan blocks RDS backups above
   1 day, GuardDuty, Security Hub and ElastiCache.
2. **State backend (once):** `cd bootstrap && terraform init && terraform apply`
   creates the encrypted, versioned state bucket (its own KMS key; S3 native
   locking, no DynamoDB). Bootstrap keeps a tiny local state file that holds no
   secrets and is git-ignored. Then `terraform init` here uses the S3 backend.
3. `terraform plan -out=x.tfplan`, review, `terraform apply x.tfplan`.
4. Populate the JWT secrets out of band (never through Terraform state):
   generate an RSA key pair and `aws secretsmanager put-secret-value` the
   base64 of each into `sentinelpay-dev/jwt-private-key-b64` and
   `sentinelpay-dev/jwt-public-key-b64`.
5. Apply the schema (tables only, never the demo data) with
   `scripts/db_admin.sh schema`, then create the first admin deliberately.
6. Per-service database roles (two-phase): on a fresh account apply with
   `-var service_db_roles=false`, run `scripts/db_admin.sh roles`, set
   `service_db_roles = true` (the default), apply, redeploy. The services image must already
   contain the `ensure_audit_table` fix.

## Known gaps

- **TLS.** Set `certificate_arn` once a domain exists; without it the ALB serves
  HTTP only.
- **Image tags.** ECR tags are mutable until the deploy job registers task
  definitions by commit SHA (Week 3).
- **Honeytoken.** Its access key is in Terraform state (now encrypted in S3).
  EventBridge only sees this region plus global events, so a call to another
  region's endpoint would not fire the rule.
- **Cost.** The stack bills continuously; destroy when finished (below).

## Tearing down

Deletion protection is a variable, not an edit to the resources:

```
terraform apply -var deletion_protection=false     # lifts RDS + ALB protection, drops final snapshot, zero-day secret recovery
terraform destroy -var deletion_protection=false
```

The CloudTrail bucket has Object Lock (Governance, 365 days), so `destroy`
cannot empty it while the retention runs. Remove it from state
(`terraform state rm aws_s3_bucket.cloudtrail ...`) or empty it with
`s3:BypassGovernanceRetention` before destroying.
