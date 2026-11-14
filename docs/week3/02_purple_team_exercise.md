# Week 3 — Purple Team Exercise

Authorized testing against SentinelPay's own `dev` AWS account
(723799951407, eu-west-2), built for this engagement. No destructive
actions were taken; app-layer attacks used freshly-registered test
accounts; AWS-side tests used the account's own decoy credentials and
AWS's official sample-finding API. Run 2026-11-14.

## Summary

| # | Scenario | MITRE ATT&CK | Result | Time-to-detect / respond |
|---|---|---|---|---|
| 1 | GuardDuty sample findings (7 types) | T1078.004, T1526, TA0006 | Detected | ≤ 5 min (EventBridge → SNS, same metric bucket) |
| 2 | Honeytoken credential use | T1078.004, T1526 | Detected + auto-contained | ~7s (API call → quarantine), confirmed twice |
| 3 | SQL injection (UNION) | T1190 | Blocked (parameterised query) | N/A — never reached the DB |
| 4 | IDOR (cross-account account read) | T1190 | Blocked (ownership check) | N/A |
| 5 | Mass assignment (profile update) | T1190 | Blocked (field allowlist) | N/A |
| 6 | SSRF to instance metadata | T1552.005 | Blocked (SSRF guard) | N/A |
| 7 | Insecure deserialisation (pickle) | T1190 | Blocked — twice over | N/A |
| 8 | Credential brute force | T1110.001 | Blocked after 5 attempts (429) | N/A |
| 9 | Wallet race condition | T1190 | Not run live (needs funded wallet) — covered by `test_vulnerabilities.py` | — |
| 10 | Unsigned image deploy | T1195.002 | Blocked (cosign fails closed) | N/A |
| 11 | Cross-repo signature acceptance | T1195.002 | **Found, fixed** (PR #55) | — |

**Headline finding:** app-layer and pipeline controls held under live
testing. One real gap was found and fixed (#11, below). The exercise also
surfaced a detection gap that isn't a vulnerability but is worth acting on
(see "Detection gap" below).

---

## 1–2. AWS-side: GuardDuty sample findings & honeytoken

**GuardDuty.** Ran `aws guardduty create-sample-findings` for 7 finding
types (Recon:IAMUser/TorIPCaller, Recon:IAMUser/MaliciousIPCaller.Custom,
UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS ×1 at
severity 8, CredentialAccess:IAMUser/AnomalousBehavior,
Policy:IAMUser/RootCredentialUsage ×3). The `sentinelpay-dev-guardduty-high`
EventBridge rule (severity ≥ 7) fired for the severity-8 finding;
CloudWatch confirms 2 rule invocations and 1 SNS message published to the
security-findings topic (sadorect@gmail.com) within the same 5-minute
metric window as finding creation.

**Side-effect found:** the same rule also targets the response Lambda
(not just SNS), and the Lambda crashed on these synthetic findings —
`NoSuchEntityException: The user with name GeneratedFindingUserName cannot
be found`, because sample findings reference a fictitious principal that
the Lambda's `quarantine_user()` then tries to disable. This is a
robustness gap in the auto-response code (no guard for "finding references
a resource that doesn't exist"), not a security hole — a real compromised
user does exist and quarantine_user works correctly against one (see
below). Worth a follow-up: catch `NoSuchEntityException`/`NoSuchUser` in
the Lambda and log-and-continue instead of raising.

**Honeytoken.** The decoy user `svc-backup-sync` already carried evidence
of a real prior trigger (2026-11-10T07:29:27Z, `GetCallerIdentity` then
`ListBuckets`, quarantined by 07:29:32 — 5 seconds). For a dated record in
this exercise, the key was reactivated, used once (`GetCallerIdentity`, a
deny-all-policy account so nothing beyond this is reachable), and
re-quarantined automatically:

```
05:44:06.401Z  WARNING  HONEYTOKEN USED: user=svc-backup-sync event=GetCallerIdentity source_ip=90.204.82.163
05:44:06.948Z  INFO     quarantined user=svc-backup-sync key=AKIA...IQKOU
```

Call-to-quarantine: well under 1 second once CloudTrail delivers the
event; end-to-end from the API call itself, ~7 seconds. This is the
fastest and most reliable control tested — full detect-and-contain with no
human in the loop.

## 3–8. App-layer attacks (live ALB)

Target: `sentinelpay-dev-242486288.eu-west-2.elb.amazonaws.com`. A fresh
account was registered and used as the attacker identity; no seeded/real
account data was touched.

- **SQLi** (`transactions/search?q=x' UNION SELECT ... FROM users--`):
  `200 []` — parameterised query, no injection, no error leak (V-APP-01
  holds).
- **IDOR** (`GET /v1/accounts/1` as a different user): `404`. The
  ownership check is folded into the lookup itself rather than returning a
  distinguishing 403, so existence isn't leaked either (V-APP-03 holds).
- **Mass assignment** (`PUT /v1/accounts/1/profile` with `user_id` in the
  body): `400 {"error": "fields not updatable via this endpoint: ...
  user_id"}` — explicit field allowlist (V-APP-07 holds).
- **SSRF** (webhook callback pointed at `169.254.169.254` instance
  metadata): `400 {"error": "callback_url must be a public http(s)
  URL"}` (V-APP-04 holds).
- **Insecure deserialisation** (pickle payload at
  `/v1/admin/session/restore`): `404`. This endpoint is blocked at *two*
  independent layers — the ALB listener rules deliberately don't route
  `/v1/admin/*` at all (defense-in-depth beyond V-APP-10's JSON-not-pickle
  fix), so the attack never reached the application layer to exercise the
  app-level fix directly.
- **Credential brute force** (15 rapid bad logins, same account): `401`
  ×5, then `429` for the rest (V-APP-08 holds).
- **Wallet race condition:** not run against live data — doing so needs a
  funded wallet, and the only funded accounts are seed data I don't have
  credentials for. This is already covered by
  `services/payments-api/tests/test_vulnerabilities.py`'s concurrent
  `debit_wallet` test, which runs in CI against a disposable database.

### Detection gap (not a vulnerability, a visibility gap)

All six attempts above reached payments-api and are visible in
`/sentinelpay-dev/payments-api` CloudWatch Logs (plain gunicorn/Werkzeug
access-log lines — status codes, paths, query strings). But:

```
$ aws logs describe-metric-filters --log-group-name /sentinelpay-dev/payments-api
(none)
$ aws cloudwatch describe-alarms --query 'MetricAlarms[].AlarmName'
sentinelpay-dev-cis-*   (12 CIS control-plane alarms only)
```

There are no metric filters or alarms on either service's log group. The
CIS alarms watch AWS control-plane activity (console sign-in failures,
IAM/NACL/route-table/SG changes, root usage) — exactly what fired for the
GuardDuty/honeytoken tests above — but nothing watches the application
logs themselves. A real SQLi/IDOR/brute-force campaign against the app
today would be visible only to someone manually reading logs, not to an
alarm. **Recommendation:** add CloudWatch metric filters on
`/sentinelpay-dev/payments-api` and `/sentinelpay-dev/kyc-api` for 401/403
bursts, `429` density, and SQL-injection-shaped query strings, with alarms
into the existing `sentinelpay-dev-security-findings` SNS topic.

## 10–11. Pipeline attack simulation

**Unsigned image (fail-closed check):** ran
`scripts/verify_image_signature.sh` against a public, unsigned image
(`docker.io/library/alpine:3.20`). Failed closed as designed:

```
Error: no signatures found
exit code: 10
```

**Cross-repo signature acceptance (real finding, fixed):** while
constructing the test above, the certificate-identity check used to
verify a cosign signature was examined directly:

```
--certificate-identity-regexp "^https://github.com/.+/\.github/workflows/ci\.yml@.+$"
```

The `.+` immediately after `github.com/` matches *any* org/repo path — it
pins the workflow **filename** (`ci.yml`), not who owns it. Verified live
against a real signed image in this account's own ECR (digest
`sha256:b1fe...e4a5`, signed by this repo's own workflow): the script
accepted it correctly, and a second run substituting a constructed
cross-repo identity string
(`.../some-other-org/totally-unrelated-repo/.github/workflows/ci.yml@...`)
against the *same real signature* **also matched** the old pattern.

Impact: a cosign-signed image from any unrelated GitHub repository that
also happens to name its workflow `ci.yml` would pass this check. Fixed in
PR #55 by anchoring the regexp to this repository
(`sadorect/Amdari-Project--02`) instead of a wildcard; any branch of this
repo still matches (needed by the `verify-signature` job, which runs on
every push). Re-verified: own-repo signature still passes, constructed
cross-repo identity now fails the pattern. A regression test checks the
literal pattern against both cases, not just that the flag is present.

## Scope notes

- No production/customer data exists in this `dev` account; the app-layer
  tests used a freshly registered test account only.
- The honeytoken's deny-all IAM policy meant the one live credential-use
  test could reach nothing beyond `GetCallerIdentity`/`ListBuckets`
  (`ListBuckets` returned `AccessDenied` both on 11-10 and would again
  now).
- Cloud config / recon probes beyond GuardDuty's own sample-finding
  mechanism were not run as separate live AWS API calls — GuardDuty's
  sample findings already exercise the detection path for recon- and
  credential-shaped activity without generating real suspicious API
  traffic against the account.
