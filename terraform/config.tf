# AWS Config records resource configuration. Security Hub's FSBP and CIS
# controls evaluate against it and report INCOMPLETE until it runs.
# The standards must be subscribed after the recorder is running.

# Security Hub control Config.1 requires the service-linked role. It delivers
# to the logs bucket through the Config statements in that bucket's policy.
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "this" {
  name     = local.name
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

}

resource "aws_config_delivery_channel" "this" {
  name           = local.name
  s3_bucket_name = aws_s3_bucket.logs.id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.this, aws_s3_bucket_policy.logs]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}
