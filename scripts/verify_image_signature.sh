#!/bin/bash
# Fix for V-PIP-01: verifies the given image's cosign (keyless) signature
# and fails closed — a non-zero exit here must block whatever called this
# script (the verify-signature CI job, and the deploy job before it force-
# deploys to ECS) from trusting the image.
#
# Usage: scripts/verify_image_signature.sh <image-ref>
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <image-ref>" >&2
    exit 1
fi

IMAGE_REF="$1"

# Keyless verification trusts the signature only if it was issued by this
# repository's own GitHub Actions workflow (the OIDC identity cosign sign
# used in build-and-push), not any Sigstore-signed image from anywhere.
#
# Found by Week 3 purple-team testing: the regexp previously pinned only the
# workflow filename (`ci.yml`), not the repository — `.+` after
# github.com/ matches any org/repo, so a cosign-signed image from a
# completely unrelated GitHub repo whose workflow also happened to be named
# ci.yml would also verify. The repo is now a literal, not a wildcard; any
# branch of *this* repo still matches, which both the verify-signature job
# (every branch) and the deploy job (main only, gated separately by the
# workflow's own `if`) need.
cosign verify \
    --certificate-identity-regexp "^https://github.com/sadorect/Amdari-Project--02/\.github/workflows/ci\.yml@.+$" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "$IMAGE_REF"
