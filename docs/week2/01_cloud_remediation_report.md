# SentinelPay — Week 2 Cloud Security Report

**Engagement:** SentinelPay security assessment (Amdari programme, Week 2)
**Scope:** Design and build of the AWS deployment in Terraform, remediation of
the cloud findings `V-CLD-01` to `V-CLD-08`, and the infrastructure half of
`V-PIP-03` (OIDC deploy roles)
**Status:** 162 resources are deployed in `eu-west-2` and match the Terraform
(`terraform plan` reports no changes); state is in an encrypted, versioned S3
bucket. Both services run healthy behind the load balancer, built and shipped
by a green pipeline. A second tranche of hardening (PR #45) is applied: AWS
Config, the honeytoken, the response Lambda and the database-role plumbing are
live, and the **per-service database roles are now in force**: both services
connect as their own least-privilege Postgres role (cutover done after PR #45
merged and CI redeployed). The S3 state backend and bootstrap stack landed in a
follow-up PR, so `main` briefly lagged the account.

---

## 1. Executive summary

Week 1 fixed the application. Week 2 gave it somewhere safe to run. The repo
shipped no infrastructure code, so the whole AWS estate was designed from the
target state in `docs/ARCHITECTURE_NOTES.md` and written as 12 Terraform files
(about 1,600 lines, a further four files are in PR #45): a three-tier VPC across two AZs, encrypted private data
stores, three customer-managed KMS keys, Fargate services behind an ALB,
CloudTrail with log-file validation into an Object Lock bucket, GuardDuty,
Security Hub, VPC flow logs, and GitHub-to-AWS OIDC with no stored keys.

Each of the eight cloud findings has a concrete control, and every live control
was checked against AWS itself, not only against the plan: RDS reports
`PubliclyAccessible=False` and `StorageEncrypted=True`, Redis reports in-transit
and at-rest encryption, a GuardDuty detector exists, the trail is logging, and
the ALB returns 401 to unauthenticated calls and 404 for the unrouted admin
path. A real login through the load balancer returns 200 with an admin token and
401 for a wrong password.

The deployment did not go smoothly, and that is part of the result. The first
`apply` partly failed on nine errors with three causes: an AWS Free plan
restriction and two defects in my Terraform (a KMS key policy and an ALB
log-bucket policy). Once the plan was upgraded, a tenth error surfaced, an
invalid Security Hub ARN. After the apply, the first CI run on `main` failed because the repo uses
GitHub's immutable OIDC subject claim, which my trust policy could not match.
Each is recorded in §4.9 with its cause and fix. The CI test job had also been
masking failures since the start of the engagement (§4.10).

**What remains open:**
- The ALB serves HTTP only. An ACM certificate needs a domain with DNS
  validation, and none exists.
- ECR tags are mutable until the deploy job registers task definitions by
  commit SHA (Week 3 pipeline work).

---

## 2. Methodology

1. **Design from the target state, not from the finding list.** The
   architecture notes describe the intended estate; each cloud finding is the
   absence of one of its controls, so building the target state closes the
   findings as a side effect, and the table in §3 maps them back.
2. **Plan before apply, always.** Every change was reviewed as a plan with a
   count of adds, changes and destroys. Applies that touch IAM trust policies
   or create new infrastructure were held for explicit owner approval.
3. **Scan the plan, not just the source.** `trivy config` runs on the Terraform
   and on the rendered plan JSON. Seven rule IDs are ignored in
   `terraform/.trivyignore`, each with a written reason; six are false
   positives or intentional and one (a customer-managed-key rule) I reasoned
   through but did not confirm.
4. **Verify against the real account.** After each apply, state was checked
   with the AWS CLI and the running system was probed through the ALB.
5. **Secrets never pass through chat, state or logs where avoidable.** The JWT
   key pair and the initial admin password were generated locally, checked,
   and written straight to Secrets Manager. The per-service database passwords
   are generated inside the VPC by the task that sets them.
6. **Test the privilege model, not just the code.** The restricted database
   roles were validated by running both full test suites as those roles.

---

## 3. Findings overview

| ID | Finding | Control | Status |
|----|---------|---------|--------|
| V-CLD-01 | Public RDS instance | Isolated subnets, no internet route, `publicly_accessible=false`, SG only from the app SG, NACL, forced SSL | Live, verified |
| V-CLD-02 | Unencrypted KYC bucket | SSE-KMS (customer key), bucket key, TLS-only and deny-unencrypted-upload policy, versioning | Live, verified |
| V-CLD-03 | Public ACL on demo bucket | ACLs disabled (`BucketOwnerEnforced`), all four public-access-block flags on every bucket | Live, verified |
| V-CLD-04 | Hardcoded AWS keys | No static keys anywhere; Secrets Manager (KMS), task roles, OIDC | Live, verified |
| V-CLD-05 | Overbroad IAM role | One task role per service; only `kyc-api` can reach S3, only the KYC bucket; scoped deploy and build roles | Live, verified |
| V-CLD-06 | CloudTrail integrity | Multi-region trail, log-file validation, KMS, S3 object events on the KYC bucket, Object Lock (Governance, 365 days) | Live, verified |
| V-CLD-07 | GuardDuty disabled | Detector on with S3, malware, RDS login, Lambda and runtime features; Security Hub FSBP and CIS; AWS Config now recording | Live; Security Hub still `INCOMPLETE` minutes after Config started, re-check pending |
| V-CLD-08 | No flow logs | VPC flow logs to S3 and to an encrypted CloudWatch log group | Live, verified |
| V-PIP-03 | Pipeline has admin | GitHub OIDC build role (ECR push, any branch) and deploy role (ECS redeploy, `main` only) | Live; pipeline green end to end |
| (target state) | Config, per-service DB roles, honeytoken, automated response | See §4.11 to §4.14 | Config, honeytoken and Lambda **live**; DB roles plumbed, **cutover pending** (PR #45 unmerged) |

---

## 4. Findings in detail

### 4.1 V-CLD-01 — Public RDS instance

RDS PostgreSQL 15 sits in two isolated subnets whose route table has no route
beyond the VPC, behind a NACL that only admits the VPC CIDR on 5432. The
security group accepts 5432 only from the application security group. Storage
is encrypted with a customer-managed key, `rds.force_ssl=1` is set (a static
parameter, applied on reboot), backups are kept 14 days, and the master
password is owned by RDS in Secrets Manager (`manage_master_user_password`),
so it appears in neither code nor Terraform state.
**Evidence:** `describe-db-instances` returned `available / PubliclyAccessible
False / StorageEncrypted True / BackupRetention 14`.

### 4.2 V-CLD-02 and V-CLD-03 — KYC bucket encryption and public ACL

Three buckets (KYC, logs, CloudTrail) are created with the same hardening via
`for_each`: public access fully blocked, ACLs disabled, versioning, and a
TLS-only policy. The KYC bucket additionally denies any `PutObject` that is not
SSE-KMS. **The logs bucket uses SSE-S3 on purpose:** S3 server-access logs and
ALB access logs cannot be delivered to a KMS-encrypted bucket. Trivy flags this
(and the `for_each` public-access blocks it cannot resolve statically); each
is recorded in `.trivyignore` with that reason, and the scan of the rendered
plan JSON came back clean.

### 4.3 V-CLD-04 — Hardcoded AWS keys

Week 1 removed the repo-visible secrets. Week 2 removes the need for them:
the services use task roles (boto3 falls back to the role when no static keys
are set), and credentials live in Secrets Manager under a KMS key. The RDS
master secret is injected by ECS from its JSON keys, never composed into a URL
in Terraform. The Redis AUTH token is generated by Terraform and stored the
same way. Git history still contains the fake training secrets (Week 1 §4.13,
unchanged).

### 4.4 V-CLD-05 — Overbroad IAM

There is no `*:*` anywhere. A shared execution role can pull the two images,
write its own log groups, and read only the secrets it injects. Each service
has its own task role: `payments-api` has none, `kyc-api` has `s3:PutObject`
and `GetObject` on the KYC bucket plus the data key. The CI roles are separate:
the build role pushes to the two ECR repositories; the deploy role can only
`UpdateService` on the two ECS services and is trusted from `main` alone.

### 4.5 V-CLD-06 — CloudTrail integrity

A multi-region trail with log-file validation, KMS encryption, global service
events, and S3 object-level events on the KYC bucket (who read which document)
delivers to a bucket with Object Lock in Governance mode, 365-day default
retention, and to a KMS-encrypted CloudWatch log group. **Trade-off:** Object
Lock means `terraform destroy` cannot empty that bucket while retention runs;
the README documents the workaround.

### 4.6 V-CLD-07 — GuardDuty and Security Hub

GuardDuty is enabled with S3 data events, EBS malware protection, RDS login
events, Lambda network logs and runtime monitoring. Security Hub is on with the
AWS Foundational Security Best Practices and CIS 1.4.0 standards. High-severity
GuardDuty findings (severity ≥ 7) are routed to an encrypted SNS topic.
**Open:** both standards showed `INCOMPLETE` while AWS Config was not
recording. Config is now recording (§4.11), but a query made minutes after the
recorder started still returned `INCOMPLETE` with reason
`NO_AVAILABLE_CONFIGURATION_RECORDER`. Security Hub refreshes this on its own
schedule, so this is unconfirmed either way; re-check it, and if it persists
treat it as a defect in the Config setup.

### 4.7 V-CLD-08 — VPC flow logs

All traffic is logged to S3 (long retention, lifecycle to Glacier at 90 days,
expiry at 400) and to an encrypted CloudWatch log group (90 days).

### 4.8 V-PIP-03 — Pipeline identity

The two GitHub OIDC roles replace the long-lived admin keys. The first
pipeline run on `main` after merge was green end to end: tests, two image
builds, cosign signing, SBOM attach and signing, signature verification, and
the deploy job. **Verified:** both images exist in ECR with `.sig` and `.sbom`
companions next to the `latest` tag.

### 4.9 Deployment issues and their fixes

These are listed because each one is a lesson that the plan and the scanner
could not have caught.

| # | Symptom | Cause | Fix |
|---|---------|-------|-----|
| 1 | RDS, ElastiCache, GuardDuty and Security Hub refused (`FreeTierRestriction`, `SubscriptionRequiredException`) | The account was on the AWS **Free plan**, which blocks those services and caps RDS backup retention | Owner upgraded the plan; backup retention became a variable |
| 2 | Four CloudWatch log groups failed (`KMS key does not exist or is not allowed`) | The log-service statement in the key policy omitted `Encrypt*` and `ReEncrypt*` | Added the full action set; re-applied |
| 3 | ALB attribute update failed (`Access Denied for bucket`) | `eu-west-2` writes ALB logs as a regional ELB account, not the newer service principal | Granted `aws_elb_service_account` in the bucket policy |
| 4 | CIS standard rejected (`Invalid StandardsSubscriptionRequest`) | v1.4.0 uses a regional `standards/` ARN; I used the legacy `ruleset/` form | Corrected the ARN |
| 5 | Every plan showed a diff after apply | GuardDuty auto-enables sub-features my config did not declare; `rds.force_ssl` is static but defaulted to `immediate` | `ignore_changes` on the sub-feature block; `apply_method = pending-reboot` |
| 6 | First CI run on `main` failed at the AWS login | GitHub's immutable OIDC subject claim carries numeric IDs; my trust policy matched `repo:owner/name`. Separately the build job assumed the main-only deploy role, and `cosign verify` ran against private ECR with no login | Subject prefix is now a variable; build job uses the build role; ECR login added to verify steps |
| 7 | ECS tasks failed to start (`unable to retrieve secret`) | The JWT secrets existed but were empty | Populated them, forced a new deployment |
| 8 | `POST /v1/auth/login` returned 500 | The database had no tables: `seed/init.sql` only ran under docker-compose | Split schema from demo data (PR #44); applied the schema only, with a one-off in-VPC task |

Two further changes came from the owner's decisions: the region moved from
`af-south-1` to `eu-west-2` (an opt-in region adds setup and cost and nothing
in the project depends on it), and `deletion_protection` became a single
variable so teardown is one flag, not edits to resources.

### 4.10 CI test gate (PR #40)

The test step had `continue-on-error: true`, and removing it exposed that the
step had never run: `pytest` was only in `requirements-dev.txt` (so it was
"command not found"), the `app` package was not importable, and no database
existed. CI now installs the dev requirements, has a `pytest.ini`, and starts
Postgres 15 and Redis 7 as service containers loaded from the schema and demo
data. A failing test now blocks the build.

### 4.11 AWS Config (PR #45, applied)

A configuration recorder, delivery channel and role, delivering to the logs
bucket under `config/`. Security Hub's controls evaluate against Config, so
this is what moves FSBP and CIS from `INCOMPLETE` to scored.
**Verified:** `describe-configuration-recorder-status` reports the recorder
recording with a last status of `SUCCESS`.

### 4.12 Per-service database roles (PR #45, in force)

Both services connect as their own role, not the RDS master user. The change adds
`payments_app` (SELECT/INSERT/UPDATE on users and accounts, SELECT/INSERT on
transactions, webhooks and the audit log) and `kyc_app` (SELECT on
`kyc_records` only). A dedicated `db-admin` task is the **only** one allowed to
read the master credential; it generates each role password inside the VPC and
writes it straight to Secrets Manager, so the password appears in no state file,
command line or log. Rollout was two-phase behind `service_db_roles` (now defaulting to `true`).
**Found during cutover:** the first `db_admin.sh roles` run reported failure
although both roles and secrets were written: GuardDuty runtime monitoring
injects an agent sidecar, and the db-admin execution role could not pull it
(403 on the AWS-owned repo). The role now has that pull permission.
**Found by testing:** a least-privilege role cannot run the application's
startup `CREATE TABLE IF NOT EXISTS audit_log` even when the table exists
(`permission denied for schema public`); the startup check now looks the table
up first, with a regression test that fails without the fix.
**Verified:** payments-api 46 and kyc-api 19 tests pass running as the
restricted roles; role creation is idempotent. **Applied:** the two secret
containers, the `db-admin` task definition and its scoped roles exist in AWS.
**Not done:** the roles themselves and the switch to them (§6).

### 4.13 Honeytoken (PR #45, applied)

A decoy IAM user (`svc-backup-sync`) with an explicit deny-all policy and an
access key stored in an unremarkable secret that nothing reads. The user and
the secret exist in AWS; the alarm path has not been fired end to end. Any API call
made with it fires an EventBridge rule to the security topic and the response
function. **Limits:** its secret is in Terraform state, and EventBridge only
sees this region plus global events, so a call to another region's endpoint
would not fire the rule.

### 4.14 Automated response (PR #45, applied)

A Lambda, triggered by GuardDuty findings ≥ 7 and honeytoken use, that
contains and never deletes: it deactivates a compromised IAM access key and
attaches a deny-all policy, and stops a flagged ECS task so the service starts
a clean one. It will not touch protected users (default `cloudproject`, the
human admin), enforced twice: in code and by an explicit IAM deny. A
`response_dry_run` variable logs without acting. **Verified:** six unit tests,
including that the protected admin is never touched, and the deployed function
reports `Active` with `PROTECTED_USERS=cloudproject`. It has not yet been
triggered by a real or synthetic event in AWS.

---

## 5. Testing and verification summary

| Check | Result |
|-------|--------|
| `terraform validate` | Pass |
| `trivy config` on source and on the rendered plan JSON | 0 HIGH or CRITICAL after the documented ignores |
| `terraform plan` after the final apply | No changes |
| payments-api tests (as master / as `payments_app`) | 47 pass / 46 pass (the audit probe needs superuser) |
| kyc-api tests (as master / as `kyc_app`) | 19 / 19 |
| Response Lambda unit tests | 6 pass |
| CI on `main` after PR #43 | All jobs green, including deploy |
| Live: RDS | Available, private, encrypted, 14-day backups |
| Live: Redis | Available, TLS and at-rest encryption |
| Live: through the ALB | Login 200 (admin) and 401 (wrong password); unauthenticated calls 401; `/v1/admin` 404 (unrouted) |
| Live: ECS | Both services 1/1, rollout `COMPLETED`; both target groups healthy |
| Live: AWS Config | Recorder recording, last status `SUCCESS` |
| Live: response Lambda and honeytoken | Function `Active`, protected user set; decoy user exists (alarm path not yet fired) |
| Terraform state | Remote object is KMS-encrypted; 133 resources readable through the backend at migration (162 after the apply); the plan against it matched the approved plan exactly |

No test was weakened, skipped or masked to obtain a pass; the one deselected
test is deselected only in the restricted-role run because it creates a role.

---

## 6. Residual risk and recommendations

1. **Database-role cutover is done**; the master credential is now used only
   by the `db-admin` task. Smoke test: both services stable on task definition
   revision 2, an unauthenticated login returns 401 through the ALB, and logs
   show no permission errors. A full authenticated flow (login, transfer) was
   not re-run after cutover.
2. **No HTTPS.** The ALB listens on HTTP. Set `certificate_arn` once a domain
   exists; the listener then redirects 80 to 443.
3. **State now lives in S3** (own KMS key, versioning, S3 native locking), and
   the local copies were shredded after the migration was verified. The state
   still holds secrets (the Redis token, the honeytoken key), so access to the
   bucket and its key is access to those. Bootstrap keeps a small local state
   file for the bucket itself, which holds no secrets.
4. **ECR tags are mutable** because CI pushes `:latest`. The deploy job should
   register a task definition per commit SHA, then the repositories can be set
   immutable. Week 3 pipeline scope.
5. **The initial admin password** is a generated secret
   (`sentinelpay-dev/initial-admin`), and the app has no change-password or
   reset route (the only password-adjacent route is `/otp`). Rotate it by
   another one-off task, and add the route.
6. **Cost.** The stack bills continuously (NAT gateway, five interface
   endpoints across two AZs, RDS, ElastiCache, ALB, Fargate, GuardDuty,
   Security Hub). My estimate of $120 to $200 a month in London is not checked
   against AWS pricing. Teardown is `terraform apply -var
   deletion_protection=false` then `terraform destroy -var
   deletion_protection=false`; the Object Lock bucket needs the extra step in
   `terraform/README.md`.
7. **Week 3 carries forward:** multi-stage pipeline gates, IaC scanning in CI,
   and the purple-team simulation against this deployment.

---

## 7. Appendix — PR reference

| PR | Change | Status |
|----|--------|--------|
| #40 | CI test job is a real gate (pytest, `pytest.ini`, Postgres and Redis services) | Merged |
| #41 | Terraform for the AWS target state, `eu-west-2`, deletion-protection switch, apply fixes | Merged |
| #42 | App builds DB and Redis URLs from ECS-injected parts | Merged |
| #43 | OIDC subject claim, build role, ECR login for signature verification | Merged |
| #44 | Split `init.sql` into `schema.sql` and `seed_data.sql` | Merged |
| #45 | AWS Config, per-service DB roles, honeytoken, response Lambda, S3 state backend, report and deck | Open; applied from the branch |
