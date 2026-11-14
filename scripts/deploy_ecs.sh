#!/bin/bash
# Deploys one service by registering a new ECS task definition revision that
# pins the image by digest, then pointing the service at it. ECR tags are
# immutable (commit SHA), and the digest removes any tag indirection at all.
#
# Usage: scripts/deploy_ecs.sh <cluster> <service> <ecr-repo-url> <commit-sha>
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <cluster> <service> <ecr-repo-url> <commit-sha>" >&2
    exit 1
fi

CLUSTER="$1"
SERVICE="$2"
REPO_URL="$3"
SHA="$4"
REPO_NAME="${REPO_URL#*/}"

DIGEST=$(aws ecr describe-images --repository-name "$REPO_NAME" \
    --image-ids imageTag="$SHA" --query 'imageDetails[0].imageDigest' --output text)
IMAGE="${REPO_URL}@${DIGEST}"

# Fail closed: only a digest signed by this repo's workflow may be deployed.
"$(dirname "$0")/verify_image_signature.sh" "$IMAGE"

CURRENT_TD=$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
    --query 'services[0].taskDefinition' --output text)

TD_FILE=$(mktemp)
trap 'rm -f "$TD_FILE"' EXIT

aws ecs describe-task-definition --task-definition "$CURRENT_TD" \
    --query taskDefinition --output json |
    jq --arg image "$IMAGE" '
        .containerDefinitions[0].image = $image
        | {family, taskRoleArn, executionRoleArn, networkMode, containerDefinitions,
           volumes, placementConstraints, requiresCompatibilities, cpu, memory,
           runtimePlatform}
        | with_entries(select(.value != null))' > "$TD_FILE"

NEW_TD=$(aws ecs register-task-definition --cli-input-json "file://${TD_FILE}" \
    --query 'taskDefinition.taskDefinitionArn' --output text)

echo "Registered ${NEW_TD} -> ${IMAGE}"

aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
    --task-definition "$NEW_TD" > /dev/null
aws ecs wait services-stable --cluster "$CLUSTER" --services "$SERVICE"
echo "${SERVICE} stable on ${NEW_TD}"
