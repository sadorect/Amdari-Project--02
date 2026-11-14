# SentinelPay — Week 3 DevSecOps & Purple Team Report

**Engagement:** SentinelPay security assessment (Amdari programme, Week 3)
**Scope:** Immutable, signature-verified deploys; a multi-stage security
pipeline (SAST, secrets, dependency, IaC, container and DAST scanning);
repository governance (required checks, CODEOWNERS, Dependabot); and a
live purple-team exercise against the Week 2 AWS deployment and this
pipeline.
**Status:** **Week 3 complete.** All five phases closed; `main`'s branch
protection requires 12 checks; both services are live on digest-pinned
task definitions; the purple-team exercise found and fixed a real pipeline
gap.

---

## 1. Executive summary

Week 2 gave the app somewhere safe to run. Week 3 made sure what runs
there is provably the thing CI built, kept it that way under every push,
and then attacked the result to find out whether any of that actually
holds.

Deploys now pin a signed, SHA-tagged image digest instead of redeploying
a mutable `:latest` tag (Phase 1). A second workflow, independent of the
one that builds and deploys, runs seven scanners on every push — secrets,
SAST, dependency, IaC, container image and DAST — and all of them gate the
merge (Phase 2). `main` enforces 12 required checks, has CODEOWNERS on
every path with the security-sensitive ones called out, and Dependabot
watches pip, Docker, Actions and Terraform weekly (Phase 3). A throwaway
PR deliberately planting a secret, a vulnerable dependency, unsafe code
and a public S3 bucket was blocked from merging by exactly those checks,
then closed (Phase 3 proof).

The purple-team exercise (Phase 4) ran live against this account's own
`dev` environment: AWS-side detection (GuardDuty, a honeytoken) both
detected and auto-contained in seconds with no human in the loop;
app-layer attacks (SQL injection, IDOR, mass assignment, SSRF, insecure
deserialisation, credential brute force) against the deployed services all
held. The exercise also found a real gap — the pipeline's own
signature-verification check didn't pin the repository it trusted, only a
workflow filename — which is now fixed, tested, and merged. It surfaced
two things that aren't vulnerabilities but are worth acting on: the
automated response Lambda isn't resilient to synthetic GuardDuty findings,
and there is no alerting on the application's own logs, only on AWS
control-plane activity.

Nothing here was weakened to get a pass. Where a gate couldn't reasonably
be closed in a dev account (ALB over plain HTTP, no domain yet; several
cost-driven Checkov controls), it's accepted explicitly with a reason in
`.checkov.yaml`, not silently skipped.

## 2. Methodology

Each phase shipped as its own branch and PR, held to the same CI it was
adding to (`test`, then as each phase landed, its own new checks).
Scanners were run locally first to triage before trusting CI's read — the
Trivy/Checkov/Semgrep/pip-audit output quoted in §4 below is local output
confirmed against the live CI run, not CI output taken on faith. The
purple-team exercise (§5) was run live, by hand, from this machine against
the deployed AWS account and ALB — not a tabletop exercise and not a
re-run of the unit test suite's exploit tests. Every live claim below was
checked against AWS or GitHub itself at the time this report was written,
not only against a PR diff.

## 3. Findings overview

| ID | Area | Status |
|----|------|--------|
| V-PIP-05 (new) | Deploys trusted a mutable tag, not a signed digest | Fixed — Phase 1 |
| V-PIP-06 (new) | No SAST/secrets/dependency/IaC/container/DAST gate in CI | Fixed — Phase 2 |
| V-PIP-07 (new) | No required checks, CODEOWNERS or dependency bot on `main` | Fixed — Phase 3 |
| V-PIP-08 (new, found in testing) | cosign identity-regexp didn't pin the repository | Fixed — Phase 4 |
| — | App-layer attacks against the live deployment | Held — Phase 4 |
| — | AWS-side detection (GuardDuty, honeytoken) | Held — Phase 4 |
| (observation) | Response Lambda not resilient to synthetic findings | Open — see §6 |
| (observation) | No alerting on application log groups | Open — see §6 |

IDs continue from Week 1/2's `V-APP-*`/`V-CLD-*`/`V-PIP-01..04` numbering;
`V-PIP-05..08` are this week's own findings, not in the original inherited
index.

## 4. Findings in detail

### 4.1 V-PIP-05 — Mutable-tag deploys (Phase 1, PR #50, #51)

Deploy previously redeployed whatever `:latest` currently resolved to in
ECR. Fix: CI tags every build with the commit SHA; `scripts/deploy_ecs.sh`
resolves that tag to its digest, verifies the digest's cosign signature,
then registers a new task definition revision with the image pinned
`@sha256:...` — no tag indirection at the point of deploy. The ECR
repositories themselves were also switched to `IMMUTABLE` (Security Hub
ECR.2), and the lifecycle policy raised from 30 to 100 kept images so an
in-service digest can't expire out of the repository.

**First attempt failed, fixed, re-verified.** The first live deploy on
this change failed: `aws ecs register-task-definition --cli-input-json
file:///dev/stdin` returned `Invalid JSON received` on the runner — not a
logic bug, an environment one. Fixed by writing the document to a temp
file instead (PR #51). Re-run: both services deployed, task definition
revision 3, digest-pinned image, rollout `COMPLETED`.

### 4.2 V-PIP-06 — No security pipeline (Phase 2, PR #52)

A new `.github/workflows/security.yml`, deliberately separate from
`ci.yml` so a scanner change can never touch the deploy path:

| Job | Tool | Gate |
|---|---|---|
| `secrets` | Gitleaks, full history | exit 1 on a finding |
| `sast` | Semgrep (python, flask, owasp-top-ten, secrets) | `--error` |
| `dependencies` | pip-audit + Trivy fs, per service | HIGH/CRITICAL, fixed only |
| `iac` | Checkov (Terraform) + Hadolint (both Dockerfiles) | baseline in `.checkov.yaml` |
| `image` | Trivy, local build, per service | HIGH/CRITICAL, fixed only |
| `dast` | OWASP ZAP baseline against docker-compose | PRs only (needs the stack up) |

Getting these green surfaced and fixed real issues, not just pipeline
plumbing:

- **payments-api returned 500 for every unknown route or wrong HTTP
  method.** The catch-all `Exception` handler also caught Werkzeug's own
  `HTTPException` (404s, 405s), so ZAP's baseline crawl saw every 500 as
  an error-disclosure finding. Fixed to pass `HTTPException`s through with
  their real status code; regression tests added.
- **Neither service set a Content-Security-Policy or Permissions-Policy
  header.** ZAP flagged both as missing on every response. Both services
  now set CSP (`default-src 'none'`, with explicit `form-action` and
  `base-uri` since neither falls back to `default-src`),
  Permissions-Policy, `X-Content-Type-Options: nosniff` and
  `Cache-Control: no-store` on every response, with a regression test.
- **The base image carried two fixable HIGH CVEs** (zlib) and one whose
  origin Trivy never resolved (`setuptools` 70.3.0, CVE-2025-47273). zlib
  is upgraded in both Dockerfiles; `setuptools`/`wheel` and their vendored
  tree are removed after install (the app needs neither at runtime); the
  unresolved one is accepted in `.trivyignore` with a reason — it's an
  install-time-only flaw (package-index download), not reachable by the
  running service.
- **Checkov: 47 findings across ~27 checks.** Each is in `.checkov.yaml`
  as an explicit skip-with-reason (cost/scope for a single-AZ dev account,
  or a documented false positive) except six: the ALB serving plain HTTP
  (CKV_AWS_2/103/378, CKV2_AWS_20/28, CKV_AWS_260). There's no domain or
  ACM certificate yet, so these are carried as accepted risk — see §6.

### 4.3 V-PIP-07 — No governance on `main` (Phase 3, PR #53 + branch protection)

`.github/CODEOWNERS` requires owner review on every path, with
`terraform/`, `.github/`, `scripts/`, the two `auth.py` files and both
Dockerfiles called out explicitly. `.github/dependabot.yml` watches pip
(both services), Docker (both Dockerfiles), GitHub Actions and Terraform
weekly, grouping minor/patch pip bumps.

`main`'s branch protection now requires 12 status checks (previously 2:
just the two `test` jobs), applied directly via the GitHub API after
PR #53 merged: `test` ×2, `secrets`, `sast`, `dependencies` ×2, `iac`,
`image` ×2, `dast`, `verify-signature` ×2. Required reviews were not
added — `enforce_admins` is on and there is one contributor, so a
required-approval rule would simply block every merge until a second
reviewer exists.

**Proof the gates actually block a merge (PR #54, closed unmerged):** a
throwaway PR planted a random fake API key, a pinned vulnerable dependency
(`pyyaml==5.3`), unsafe Python (`subprocess(..., shell=True)` and
`eval()` on request input) and a public S3 bucket. Five of the twelve
required checks failed — Gitleaks (`generic-api-key`), pip-audit and
Trivy image (PyYAML PYSEC-2020-96 / CVE-2020-14343, critical), Semgrep
(subprocess injection, dangerous eval) and Checkov (the public bucket) —
and the PR's merge state read `BLOCKED`. Closed unmerged; branch deleted.

### 4.4 V-PIP-08 — cosign identity-regexp didn't pin the repository (Phase 4, PR #55)

Found during the purple-team pipeline test, not a planned fix. See §5.4.

## 5. Purple team exercise (Phase 4, PR #56)

Full detail and command-level evidence:
`docs/week3/02_purple_team_exercise.md`. Summary:

### 5.1 AWS-side detection

- **GuardDuty:** `aws guardduty create-sample-findings` generated 7
  findings across 5 types. The `severity >= 7` EventBridge rule fired for
  the one at severity 8; CloudWatch confirms the rule invocation and one
  SNS message published to the security-findings topic in the same
  5-minute window as finding creation.
- **Honeytoken:** real prior evidence (2026-11-10) already showed
  `GetCallerIdentity` → quarantined in 5 seconds. Re-triggered live for
  this exercise's own record: `GetCallerIdentity` at 05:44:06.401Z,
  quarantined at 05:44:06.948Z — under a second from CloudTrail delivery
  to containment, auto-contained twice now, no human in the loop.

### 5.2 App-layer attacks (live ALB)

A freshly registered test account attacked the deployed services directly
— no seed or production data touched. SQL injection (UNION payload):
`200 []`, parameterised, no leak. IDOR (cross-account account read):
`404`, ownership folded into the lookup so existence isn't leaked either.
Mass assignment: `400`, explicit field allowlist. SSRF to the instance
metadata address: `400`, blocked by the SSRF guard. Insecure
deserialisation (pickle payload at the admin restore endpoint): `404` —
blocked at *two* independent layers, since the ALB's own listener rules
don't route `/v1/admin/*` at all, on top of the app-level JSON-not-pickle
fix. Credential brute force: `401` ×5 then `429` for the rest. The wallet
race-condition test was not run live (needs a funded wallet this exercise
had no credentials for); it's covered in CI by
`test_vulnerabilities.py`'s concurrent-debit test.

### 5.3 Pipeline attack simulation

`scripts/verify_image_signature.sh` against a real, unsigned public image:
failed closed (`no signatures found`, exit 10), as designed.

### 5.4 Cross-repo signature acceptance — found and fixed (PR #55)

While constructing the test above, the identity check itself was
examined: `--certificate-identity-regexp
"^https://github.com/.+/\.github/workflows/ci\.yml@.+$"`. The `.+`
immediately after `github.com/` matches **any** org/repo — the pattern
pinned the workflow's *filename*, not who owns it. Verified live: a real
cosign signature on a real image in this account's ECR, checked against a
constructed cross-repo identity string, matched the old pattern. Fixed by
anchoring to `sadorect/Amdari-Project--02`; any branch of this repo still
matches (the `verify-signature` job runs on every push, not just `main`).
Re-verified both directions after the fix, with a regression test that
checks the literal pattern, not just that a flag exists.

## 6. Residual risk and accepted items

**Carried forward from Week 2, still open**
1. **No HTTPS on the ALB.** Six Checkov checks (CKV_AWS_2/103/378,
   CKV2_AWS_20/28, CKV_AWS_260) are skipped in `.checkov.yaml` with this
   reason. Needs a domain and an ACM certificate; once those exist, add an
   HTTPS listener, redirect 80→443, and drop the six skips.
2. **Root MFA, account security contact, console MFA on `cloudproject`.**
   Unchanged from Week 2 — console/root steps, not expressible in code.

**New this week, accepted with a reason**
3. **`setuptools` 70.3.0 (CVE-2025-47273)** survives removal of
   `setuptools`/`wheel` and their vendored tree in both Dockerfiles; Trivy
   reports it with no resolvable file path. Accepted in `.trivyignore` —
   the flaw is in package-index downloads, which never run in the running
   service. Revisit on the next `python:3.11-slim` base bump.
4. **Flask's own dev server still runs in both containers**
   (`python -m app.main`), which is why ZAP flags the `Server: Werkzeug`
   header (ignored in `.zap/rules.tsv`). `gunicorn` is already a
   dependency; moving `CMD` to it would close this and is a clean
   follow-up, not done this week since it's outside the pipeline/purple-team
   scope.

**New this week, not yet actioned**
5. **No alerting on application logs.** CloudWatch has 12 CIS alarms for
   AWS control-plane activity, and zero metric filters on
   `/sentinelpay-dev/payments-api` or `/sentinelpay-dev/kyc-api`. Every
   app-layer attack in §5.2 is visible in those logs as a plain
   gunicorn/Werkzeug access-log line, but nothing alerts on it — a real
   SQLi or brute-force campaign today is as visible as this exercise's
   simulated one: to someone who goes and reads the logs, not to anyone
   on the existing alert topic. Recommended: metric filters for 401/403
   bursts, 429 density and SQLi-shaped query strings, alarming into the
   existing `sentinelpay-dev-security-findings` SNS topic.
6. **Response Lambda isn't resilient to synthetic GuardDuty findings.**
   `create-sample-findings` references a fictitious principal
   (`GeneratedFindingUserName`); the Lambda's `quarantine_user()` throws
   `NoSuchEntityException` trying to disable it, visible as a crashed
   invocation in its CloudWatch logs. Not a security hole — a real
   compromised principal does exist and is handled correctly (§5.1) — but
   worth a small fix: catch `NoSuchEntityException`/`NoSuchUser` and
   log-and-continue instead of raising, so future sample-finding testing
   (or a real finding referencing an already-deleted principal) doesn't
   read as a broken response pipeline.

## 7. Testing and verification summary

| Check | Result |
|---|---|
| `security.yml` on `main` after PR #52/#53/#55/#56 | All jobs green |
| CI (`test`, `build-and-push`, `verify-signature`, `deploy`) on `main` | Green, both services |
| Branch protection, required checks | 12 (was 2) |
| Throwaway gate-proof PR #54 | Blocked (5 of 12 checks failed), closed unmerged |
| Live: ECS after latest `main` merge | Both services, task def rev 6, rollout `COMPLETED`, 1/1 running |
| Live: digest pinning | Both task defs' container image is `@sha256:...`, not a tag |
| Live: ALB login (wrong password) | `401` |
| Live: ALB `/v1/admin/*` | `404` (unrouted at the ALB, independent of the app-level fix) |
| Live: ALB unauthenticated account access | `401` |
| Live: GuardDuty sample findings → SNS | 1 message, same 5-min window |
| Live: honeytoken trigger → quarantine | <1s from CloudTrail delivery, confirmed twice |
| Live: unsigned image → `verify_image_signature.sh` | Exit 10, fails closed |
| Live: cross-repo identity, pre-fix | Matched (bug confirmed) |
| Live: cross-repo identity, post-fix | Did not match (fix confirmed) |

## 8. Appendix — PR reference

| PR | Change | Status |
|----|--------|--------|
| #50 | Deploy by commit SHA and digest; immutable ECR tags | Merged |
| #51 | Fix first main deploy: task definition via temp file | Merged |
| #52 | Security pipeline: secrets, SAST, dependency, IaC, image, DAST | Merged |
| #53 | CODEOWNERS and Dependabot | Merged |
| #54 | Throwaway: prove the gates fail | Closed, unmerged, branch deleted |
| #55 | Pipeline fix: cosign identity-regexp didn't pin the repo | Merged |
| #56 | Purple team exercise report | Merged |
| (branch protection) | 12 required checks on `main` | Applied via API, not a PR |
