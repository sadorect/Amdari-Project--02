import importlib.util
import pathlib
import sys
import types
from unittest import mock

import pytest

# boto3 is provided by the Lambda runtime; stub it so the test needs nothing installed.
sys.modules.setdefault("boto3", types.SimpleNamespace(client=lambda *_a, **_k: None))
_spec = importlib.util.spec_from_file_location(
    "response", pathlib.Path(__file__).resolve().parents[2] / "terraform/lambda/response.py")
response = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(response)


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("PROTECTED_USERS", "cloudproject")
    monkeypatch.setenv("DRY_RUN", "false")


def gd_key_event(user, key="AKIAEXAMPLE"):
    return {"source": "aws.guardduty", "detail": {"severity": 8, "resource": {
        "accessKeyDetails": {"userType": "IAMUser", "userName": user, "accessKeyId": key}}}}


def test_guardduty_access_key_is_deactivated_and_user_denied():
    iam, ecs = mock.Mock(), mock.Mock()
    with mock.patch.object(response.boto3, "client", side_effect=[iam, ecs]):
        out = response.handler(gd_key_event("svc-deploy"), None)
    iam.update_access_key.assert_called_once_with(UserName="svc-deploy", AccessKeyId="AKIAEXAMPLE", Status="Inactive")
    assert iam.put_user_policy.call_args.kwargs["UserName"] == "svc-deploy"
    assert '"Effect": "Deny"' in iam.put_user_policy.call_args.kwargs["PolicyDocument"]
    assert out == {"actions": ["quarantined"]}


def test_protected_admin_is_never_touched():
    iam, ecs = mock.Mock(), mock.Mock()
    with mock.patch.object(response.boto3, "client", side_effect=[iam, ecs]):
        out = response.handler(gd_key_event("cloudproject"), None)
    iam.update_access_key.assert_not_called()
    iam.put_user_policy.assert_not_called()
    assert out == {"actions": ["skipped-protected"]}


def test_guardduty_ecs_task_is_stopped():
    iam, ecs = mock.Mock(), mock.Mock()
    event = {"source": "aws.guardduty", "detail": {"resource": {"ecsClusterDetails": {
        "name": "sentinelpay", "taskDetails": [{"arn": "arn:aws:ecs:eu-west-2:1:task/sentinelpay/abc"}]}}}}
    with mock.patch.object(response.boto3, "client", side_effect=[iam, ecs]):
        out = response.handler(event, None)
    ecs.stop_task.assert_called_once()
    assert ecs.stop_task.call_args.kwargs["cluster"] == "sentinelpay"
    assert out == {"actions": ["stopped"]}


def test_honeytoken_use_quarantines_the_key():
    iam, ecs = mock.Mock(), mock.Mock()
    event = {"source": "aws.iam", "detail": {"eventName": "GetCallerIdentity", "sourceIPAddress": "203.0.113.9",
             "userIdentity": {"userName": "svc-backup-sync", "accessKeyId": "AKIAHONEY"}}}
    with mock.patch.object(response.boto3, "client", side_effect=[iam, ecs]):
        out = response.handler(event, None)
    iam.update_access_key.assert_called_once_with(UserName="svc-backup-sync", AccessKeyId="AKIAHONEY", Status="Inactive")
    assert out == {"actions": ["quarantined"]}


def test_dry_run_takes_no_action(monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    iam, ecs = mock.Mock(), mock.Mock()
    with mock.patch.object(response.boto3, "client", side_effect=[iam, ecs]):
        out = response.handler(gd_key_event("svc-deploy"), None)
    iam.update_access_key.assert_not_called()
    iam.put_user_policy.assert_not_called()
    assert out == {"actions": ["dry-run"]}


def test_unrelated_event_is_ignored():
    iam, ecs = mock.Mock(), mock.Mock()
    with mock.patch.object(response.boto3, "client", side_effect=[iam, ecs]):
        assert response.handler({"detail": {}}, None) == {"actions": ["ignored"]}
