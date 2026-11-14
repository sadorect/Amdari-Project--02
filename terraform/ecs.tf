resource "aws_ecs_cluster" "this" {
  name = "sentinelpay"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_cloudwatch_log_group" "service" {
  for_each = local.services

  name              = "/${local.name}/${each.key}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.this["logs"].arn
}

# --- Secrets the app needs. Values for the JWT keys are set out of band
# (scripts/generate_dev_jwt_keys.sh for dev), never through Terraform state.

resource "aws_secretsmanager_secret" "jwt_public" {
  name                    = "${local.name}/jwt-public-key-b64"
  kms_key_id              = aws_kms_key.this["secrets"].arn
  recovery_window_in_days = var.deletion_protection ? 30 : 0
}

resource "aws_secretsmanager_secret" "jwt_private" {
  name                    = "${local.name}/jwt-private-key-b64"
  kms_key_id              = aws_kms_key.this["secrets"].arn
  recovery_window_in_days = var.deletion_protection ? 30 : 0
}

# --- Load balancer ------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name_prefix = "${local.name}-alb-"
  description = "Public ALB"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr  public API entry point
  }

  ingress {
    description = "HTTP (redirected to HTTPS when a certificate is configured)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-ingress-sgr
  }

  lifecycle { create_before_destroy = true }
}

# Egress rules as separate resources so they can reference the app SG
# without a dependency cycle.
resource "aws_security_group_rule" "alb_to_app" {
  for_each = local.service_ports

  type                     = "egress"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.app.id
  protocol                 = "tcp"
  from_port                = each.value
  to_port                  = each.value
  description              = "ALB to ${each.key}"
}

resource "aws_security_group_rule" "app_from_alb" {
  for_each = local.service_ports

  type                     = "ingress"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.alb.id
  protocol                 = "tcp"
  from_port                = each.value
  to_port                  = each.value
  description              = "${each.key} from ALB"
}

resource "aws_security_group_rule" "app_to_db" {
  type                     = "egress"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.db.id
  protocol                 = "tcp"
  from_port                = 5432
  to_port                  = 5432
  description              = "Postgres"
}

resource "aws_security_group_rule" "app_to_redis" {
  type                     = "egress"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.redis.id
  protocol                 = "tcp"
  from_port                = 6379
  to_port                  = 6379
  description              = "Redis"
}

resource "aws_security_group_rule" "app_to_endpoints" {
  type                     = "egress"
  security_group_id        = aws_security_group.app.id
  source_security_group_id = aws_security_group.endpoints.id
  protocol                 = "tcp"
  from_port                = 443
  to_port                  = 443
  description              = "Interface VPC endpoints"
}

# S3 is reached through the gateway endpoint, which is addressed by prefix list.
resource "aws_security_group_rule" "app_to_s3" {
  type              = "egress"
  security_group_id = aws_security_group.app.id
  prefix_list_ids   = [aws_vpc_endpoint.s3.prefix_list_id]
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "S3 gateway endpoint"
}

# kyc-api's outbound BVN lookups and webhook delivery need internet egress
# over 443 via NAT. Kept explicit so it shows up in review.
resource "aws_security_group_rule" "app_to_internet_https" {
  type              = "egress"
  security_group_id = aws_security_group.app.id
  cidr_blocks       = ["0.0.0.0/0"] # tfsec:ignore:aws-ec2-no-public-egress-sgr  BVN provider, webhooks
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS egress via NAT"
}

resource "aws_lb" "this" {
  name                       = local.name
  load_balancer_type         = "application"
  internal                   = false #tfsec:ignore:aws-elb-alb-not-public  public API
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

resource "aws_lb_target_group" "this" {
  for_each = local.service_ports

  name_prefix = substr(replace(each.key, "-api", ""), 0, 6)
  port        = each.value
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.this.id

  health_check {
    path    = "/health"
    matcher = "200"
  }

  lifecycle { create_before_destroy = true }
}

locals {
  https = var.certificate_arn != ""
}

resource "aws_lb_listener" "https" {
  count = local.https ? 1 : 0

  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\":\"not found\"}"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  dynamic "default_action" {
    for_each = local.https ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = local.https ? [] : [1]
    content {
      type = "fixed-response"
      fixed_response {
        content_type = "application/json"
        message_body = "{\"error\":\"not found\"}"
        status_code  = "404"
      }
    }
  }
}

locals {
  # Whichever listener is serving traffic carries the path rules.
  listener_arn = local.https ? aws_lb_listener.https[0].arn : aws_lb_listener.http.arn
  # /v1/admin is deliberately not routed: the admin API is not reachable
  # from the internet through the ALB.
  path_patterns = {
    "payments-api" = ["/v1/auth/*", "/v1/accounts/*", "/v1/transactions/*", "/v1/wallets/*", "/v1/webhooks/*"]
    "kyc-api"      = ["/v1/verify/*", "/v1/documents/*"]
  }
}

resource "aws_lb_listener_rule" "this" {
  for_each = local.service_ports

  listener_arn = local.listener_arn
  priority     = each.key == "payments-api" ? 10 : 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[each.key].arn
  }
  condition {
    path_pattern { values = local.path_patterns[each.key] }
  }
}

# --- Tasks and services -----------------------------------------------------------------------

resource "aws_ecs_task_definition" "this" {
  for_each = local.services

  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task[each.key].arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name      = each.key
    image     = "${aws_ecr_repository.this[each.key].repository_url}:${var.image_tag}"
    essential = true

    portMappings           = [{ containerPort = local.service_ports[each.key], protocol = "tcp" }]
    readonlyRootFilesystem = true
    user                   = "app"

    environment = concat([
      { name = "ENVIRONMENT", value = var.environment },
      { name = "AWS_REGION", value = var.region },
      { name = "DB_HOST", value = aws_db_instance.this.address },
      { name = "DB_NAME", value = "sentinelpay" },
      { name = "DB_SSLMODE", value = "require" },
      { name = "REDIS_HOST", value = aws_elasticache_replication_group.this.primary_endpoint_address },
    ], each.key == "kyc-api" ? [{ name = "KYC_BUCKET", value = aws_s3_bucket.kyc.id }] : [])

    secrets = concat([
      { name = "DB_USER", valueFrom = "${local.db_secret_arn[each.key]}:username::" },
      { name = "DB_PASSWORD", valueFrom = "${local.db_secret_arn[each.key]}:password::" },
      { name = "REDIS_AUTH_TOKEN", valueFrom = aws_secretsmanager_secret.redis_auth.arn },
      { name = "JWT_PUBLIC_KEY_B64", valueFrom = aws_secretsmanager_secret.jwt_public.arn },
    ], each.key == "payments-api" ? [{ name = "JWT_PRIVATE_KEY_B64", valueFrom = aws_secretsmanager_secret.jwt_private.arn }] : [])

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.service[each.key].name
        awslogs-region        = var.region
        awslogs-stream-prefix = each.key
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  for_each = local.services

  name            = each.key
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this[each.key].arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  # ECS Exec (shell into a task) stays off: break-glass only, per the
  # target-state notes.
  enable_execute_command = false

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this[each.key].arn
    container_name   = each.key
    container_port   = local.service_ports[each.key]
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # CI registers a task definition revision per commit and points the service
  # at it; Terraform should not fight it.
  lifecycle { ignore_changes = [desired_count, task_definition] }

  depends_on = [aws_lb_listener_rule.this]
}
