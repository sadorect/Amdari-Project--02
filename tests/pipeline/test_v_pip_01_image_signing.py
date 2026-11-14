"""V-PIP-01 — unsigned container images.

Static check against .github/workflows/ci.yml (not a live CI run, since
this sandbox has no AWS/ECR/GitHub Actions to execute against). Run from
the repo root:

    python3 -m pytest tests/pipeline/test_v_pip_01_image_signing.py -v

or directly:

    python3 tests/pipeline/test_v_pip_01_image_signing.py

Fails against the inherited ci.yml (no cosign step at all); passes once
the fix branch's build-and-push job signs the pushed image and a
verify-signature (or deploy) job verifies it.
"""
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_image_signature.sh"


def _non_comment_text() -> str:
    """Strips full-line and trailing '#' comments so a step merely
    mentioning a tool's name in passing (e.g. documenting that it's
    missing) doesn't satisfy these checks."""
    lines = []
    for line in CI_YML.read_text().splitlines():
        stripped = line.split("#", 1)[0]
        lines.append(stripped)
    return "\n".join(lines)


def test_build_and_push_signs_the_image_with_cosign():
    text = _non_comment_text()
    assert "sigstore/cosign-installer" in text, "expected cosign to be installed in the pipeline"
    assert "cosign sign" in text, "expected an image to actually be signed, not just cosign installed"


def test_build_and_push_requests_an_oidc_token_for_keyless_signing():
    text = _non_comment_text()
    assert "id-token: write" in text, (
        "keyless cosign signing requires requesting the job's OIDC identity token"
    )


def test_a_verification_step_fails_closed_before_deploy():
    text = _non_comment_text()
    assert "verify_image_signature.sh" in text, (
        "expected a signature verification step gating the pipeline (ideally before deploy)"
    )
    assert VERIFY_SCRIPT.exists(), "verify_image_signature.sh referenced by ci.yml must exist"
    assert VERIFY_SCRIPT.stat().st_mode & 0o111, "verify_image_signature.sh must be executable"


def test_verify_script_pins_the_identity_to_this_repo_not_just_the_workflow_filename():
    """Found by Week 3 purple-team testing: the --certificate-identity-regexp
    pinned the workflow filename (ci.yml) but left the org/repo as a `.+`
    wildcard, so a cosign-signed image from ANY GitHub repo whose workflow
    also happened to be named ci.yml would verify. Checks the regexp
    literal itself (not just that one is present), so this would have
    caught the original bug."""
    import re

    text = VERIFY_SCRIPT.read_text()
    m = re.search(r'--certificate-identity-regexp\s+"([^"]+)"', text)
    assert m, "expected a --certificate-identity-regexp flag in verify_image_signature.sh"
    pattern = m.group(1)

    own_repo_identity = "https://github.com/sadorect/Amdari-Project--02/.github/workflows/ci.yml@refs/heads/main"
    other_repo_identity = "https://github.com/some-other-org/totally-unrelated-repo/.github/workflows/ci.yml@refs/heads/main"

    assert re.fullmatch(pattern, own_repo_identity), "the pattern must still accept this repo's own workflow"
    assert not re.fullmatch(pattern, other_repo_identity), (
        "the pattern must reject a differently-owned repo's workflow of the same filename"
    )


def test_verify_script_fails_closed_on_an_actually_unsigned_image():
    """Without a real cosign binary + registry in this sandbox, this
    exercises the one thing we CAN check here: the script's own
    `set -e`/explicit exit-on-failure behaviour, by running it with no
    arguments (its own usage-error path) and confirming it exits non-zero
    rather than silently succeeding."""
    result = subprocess.run(["bash", str(VERIFY_SCRIPT)], capture_output=True, text=True)
    assert result.returncode != 0, "verify_image_signature.sh must fail closed, not exit 0, on error"


if __name__ == "__main__":
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS: {name}")
            except AssertionError as e:
                print(f"FAIL: {name}: {e}")
                failures += 1
    sys.exit(1 if failures else 0)
