"""Automated first response for high-severity findings.

Triggered by EventBridge for (a) GuardDuty findings with severity >= 7 and
(b) any CloudTrail activity by the honeytoken user. It only contains the
damage, it never deletes anything:

  - IAM access key finding  -> deactivate that key, attach a deny-all inline
                               policy to the user
  - ECS task finding        -> stop the task (the service starts a clean one)
  - honeytoken use          -> deactivate the key and deny-all the user

Principals in PROTECTED_USERS are never touched, so a finding against the
human admin cannot lock the account owner out. DRY_RUN=true logs the action
without taking it.
"""
import json
import logging
import os
import time

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DENY_ALL = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
)


def _protected():
    return {u.strip() for u in os.environ.get("PROTECTED_USERS", "").split(",") if u.strip()}


def _dry_run():
    return os.environ.get("DRY_RUN", "false").lower() == "true"


def quarantine_user(iam, user_name, access_key_id=None):
    if user_name in _protected():
        logger.warning("skip protected user %s", user_name)
        return "skipped-protected"
    if _dry_run():
        logger.info("DRY_RUN: would quarantine user=%s key=%s", user_name, access_key_id)
        return "dry-run"
    if access_key_id:
        iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Inactive")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=f"quarantine-{int(time.time())}",
        PolicyDocument=DENY_ALL,
    )
    logger.info("quarantined user=%s key=%s", user_name, access_key_id)
    return "quarantined"


def stop_task(ecs, cluster, task_arn):
    if _dry_run():
        logger.info("DRY_RUN: would stop task=%s", task_arn)
        return "dry-run"
    ecs.stop_task(cluster=cluster, task=task_arn, reason="Stopped by automated security response")
    logger.info("stopped task=%s", task_arn)
    return "stopped"


def handle_guardduty(detail, iam, ecs):
    resource = detail.get("resource", {})
    results = []
    key = resource.get("accessKeyDetails") or {}
    if key.get("userType") == "IAMUser" and key.get("userName"):
        results.append(quarantine_user(iam, key["userName"], key.get("accessKeyId")))
    cluster = resource.get("ecsClusterDetails") or {}
    tasks = cluster.get("taskDetails") or []
    for task in [tasks] if isinstance(tasks, dict) else tasks:
        if task.get("arn") and cluster.get("name"):
            results.append(stop_task(ecs, cluster["name"], task["arn"]))
    return results


def handle_honeytoken(detail, iam):
    identity = detail.get("userIdentity", {})
    user = identity.get("userName")
    if not user:
        return ["no-user"]
    logger.warning("HONEYTOKEN USED: user=%s event=%s source_ip=%s", user, detail.get("eventName"), detail.get("sourceIPAddress"))
    return [quarantine_user(iam, user, identity.get("accessKeyId"))]


def handler(event, context):
    iam = boto3.client("iam")
    ecs = boto3.client("ecs")
    detail = event.get("detail", {})
    if event.get("source") == "aws.guardduty":
        results = handle_guardduty(detail, iam, ecs)
    elif detail.get("userIdentity", {}).get("userName"):
        results = handle_honeytoken(detail, iam)
    else:
        results = ["ignored"]
    logger.info("result=%s", results)
    return {"actions": results}
