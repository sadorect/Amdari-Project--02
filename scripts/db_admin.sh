#!/bin/bash
# Run a one-off database administration task inside the VPC, as the RDS
# master user, via the db-admin ECS task definition. RDS is in isolated
# subnets, so this is the only way in.
#
#   scripts/db_admin.sh schema   apply seed/schema.sql (tables only, idempotent)
#   scripts/db_admin.sh roles    create per-service Postgres roles; passwords go
#                                straight to Secrets Manager (re-run rotates them)
#
# Needs AWS credentials for the account (AWS_PROFILE) and the terraform stack
# applied. Prints only the task's own summary lines, never credentials.
set -euo pipefail

cd "$(dirname "$0")/.."
ACTION="${1:-}"
CLUSTER=sentinelpay
FAMILY=sentinelpay-dev-db-admin

case "$ACTION" in
  schema)
    SCRIPT='import base64,os,psycopg2
from app.config import database_url
c=psycopg2.connect(database_url());k=c.cursor()
k.execute(base64.b64decode(os.environ["PAYLOAD_B64"]).decode());c.commit()
k.execute("select count(*) from information_schema.tables where table_schema=%s",("public",))
print("schema applied, tables=%s"%k.fetchone()[0])'
    PAYLOAD=$(base64 -w0 seed/schema.sql) ;;
  roles)
    SCRIPT='import base64,os;exec(base64.b64decode(os.environ["PAYLOAD_B64"]))'
    PAYLOAD=$(base64 -w0 scripts/db_roles.py) ;;
  *) echo "usage: $0 schema|roles" >&2; exit 1 ;;
esac

SUBNETS=$(aws ec2 describe-subnets --filters Name=tag:Tier,Values=private Name=tag:Project,Values=sentinelpay \
  --query 'Subnets[].SubnetId' --output text | tr '\t' ',')
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values='sentinelpay-dev-app-*' \
  --query 'SecurityGroups[0].GroupId' --output text)

OVERRIDES=$(python3 -c "
import json,sys
print(json.dumps({'containerOverrides':[{'name':'db-admin','command':['python','-c',sys.argv[1]],
  'environment':[{'name':'PAYLOAD_B64','value':sys.argv[2]}]}]}))" "$SCRIPT" "$PAYLOAD")

TASK=$(aws ecs run-task --cluster "$CLUSTER" --task-definition "$FAMILY" --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG],assignPublicIp=DISABLED}" \
  --overrides "$OVERRIDES" --started-by "db-admin-$ACTION" --query 'tasks[0].taskArn' --output text)
TASK_ID=${TASK##*/}
echo "started $ACTION task $TASK_ID"

until [ "$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ID" --query 'tasks[0].lastStatus' --output text)" = STOPPED ]; do sleep 8; done
CODE=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ID" --query 'tasks[0].containers[0].exitCode' --output text)
sleep 5
aws logs tail /sentinelpay-dev/db-admin --since 15m --log-stream-name-prefix "db-admin/db-admin/$TASK_ID" \
  | sed -E 's/^[^ ]+ [^ ]+ //' | grep -v '^$' || true
[ "$CODE" = 0 ] || { echo "task failed (exit $CODE)" >&2; exit 1; }
