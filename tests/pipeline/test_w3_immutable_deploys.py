"""Week 3 — immutable image tags and SHA/digest deploys (Security Hub ECR.2).

Static checks against ci.yml, scripts/deploy_ecs.sh and terraform/ecr.tf.
Run from the repo root:

    python3 -m pytest tests/pipeline/test_w3_immutable_deploys.py -v
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
CI = (ROOT / ".github/workflows/ci.yml").read_text()
DEPLOY = (ROOT / "scripts/deploy_ecs.sh").read_text()
ECR = (ROOT / "terraform/ecr.tf").read_text()


def _code(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_ci_never_uses_the_latest_tag():
    assert ":latest" not in _code(CI)


def test_ci_tags_images_by_commit_sha():
    assert "${{ github.sha }}" in CI


def test_ecr_repositories_are_immutable():
    assert re.search(r'image_tag_mutability\s*=\s*"IMMUTABLE"', ECR)


def test_deploy_registers_a_task_definition_instead_of_forcing_redeploy():
    assert "--force-new-deployment" not in _code(CI)
    assert "register-task-definition" in DEPLOY


def test_deploy_pins_image_by_digest_and_verifies_signature_first():
    code = _code(DEPLOY)
    assert "@${DIGEST}" in code
    assert code.index("verify_image_signature.sh") < code.index("register-task-definition")
