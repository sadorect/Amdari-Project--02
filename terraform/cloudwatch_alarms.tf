# CIS AWS Foundations 1.4 section 4 (Security Hub CloudWatch.1, .4 to .14):
# a metric filter on the CloudTrail log group and an alarm per event class,
# all routed to the security SNS topic.

locals {
  iam_changes = join(" || ", [for e in [
    "DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy", "PutRolePolicy",
    "PutUserPolicy", "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion",
    "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy",
    "AttachGroupPolicy", "DetachGroupPolicy",
  ] : "($.eventName = ${e})"])

  event_names = { for k, v in {
    cloudtrail  = ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"]
    config      = ["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"]
    s3_policy   = ["PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle", "PutBucketReplication", "DeleteBucketPolicy", "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication"]
    sg          = ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"]
    nacl        = ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"]
    gateway     = ["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"]
    route_table = ["CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"]
    vpc         = ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection", "AttachClassicLinkVpc", "DetachClassicLinkVpc", "DisableVpcClassicLink", "EnableVpcClassicLink"]
  } : k => join(" || ", [for e in v : "($.eventName = ${e})"]) }

  cis_monitors = {
    root_usage   = { control = "CloudWatch.1", pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }" }
    iam_changes  = { control = "CloudWatch.4", pattern = "{ ${local.iam_changes} }" }
    cloudtrail   = { control = "CloudWatch.5", pattern = "{ ${local.event_names.cloudtrail} }" }
    console_fail = { control = "CloudWatch.6", pattern = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }" }
    cmk_disable  = { control = "CloudWatch.7", pattern = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }" }
    s3_policy    = { control = "CloudWatch.8", pattern = "{ ($.eventSource = s3.amazonaws.com) && (${local.event_names.s3_policy}) }" }
    config       = { control = "CloudWatch.9", pattern = "{ ($.eventSource = config.amazonaws.com) && (${local.event_names.config}) }" }
    sg           = { control = "CloudWatch.10", pattern = "{ ${local.event_names.sg} }" }
    nacl         = { control = "CloudWatch.11", pattern = "{ ${local.event_names.nacl} }" }
    gateway      = { control = "CloudWatch.12", pattern = "{ ${local.event_names.gateway} }" }
    route_table  = { control = "CloudWatch.13", pattern = "{ ${local.event_names.route_table} }" }
    vpc          = { control = "CloudWatch.14", pattern = "{ ${local.event_names.vpc} }" }
  }
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each = local.cis_monitors

  name           = "${local.name}-cis-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = "${local.name}-${each.key}"
    namespace = "SentinelPay/CIS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each = local.cis_monitors

  alarm_name          = "${local.name}-cis-${each.key}"
  alarm_description   = "Security Hub ${each.value.control}: ${each.key}"
  namespace           = "SentinelPay/CIS"
  metric_name         = "${local.name}-${each.key}"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.cis]
}
