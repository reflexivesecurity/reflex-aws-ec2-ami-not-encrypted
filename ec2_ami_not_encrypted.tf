module "ec2_ami_not_encrypted" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.6.0"
  rule_name        = "Ec2AmiNotEncrypted"
  rule_description = "A Reflex rule for detecting the creation of unencrypted EC2 AMIs."

  event_pattern = <<PATTERN
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "source": [
    "aws.ec2"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "CreateImage"
    ]
  }
}
PATTERN

  function_name            = "Ec2AmiNotEncrypted"
  source_code_dir          = "${path.module}/source"
  handler                  = "ec2_ami_not_encrypted.lambda_handler"
  lambda_runtime           = "python3.7"
  environment_variable_map = { SNS_TOPIC = var.sns_topic_arn }
  custom_lambda_policy     = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

  queue_name    = "Ec2AmiNotEncrypted"
  delay_seconds = 60
  target_id     = "Ec2AmiNotEncrypted"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
