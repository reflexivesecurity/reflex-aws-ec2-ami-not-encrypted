module "detect_ec2_ami_not_encrypted" {
  source           = "git@github.com:cloudmitigator/reflex.git//modules/cwe_lambda"
  rule_name        = "DetectEc2AmiNotEncrypted"
  rule_description = "Rule to enforce S3 bucket encryption"

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
  environment_variable_map = { SNS_TOPIC = module.detect_ec2_ami_not_encrypted.arn }
  custom_lambda_policy     = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetEncryptionConfiguration",
        "s3:PutEncryptionConfiguration"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

  queue_name    = "DetectEc2AmiNotEncrypted"
  delay_seconds = 60
  target_id = "DetectEc2AmiNotEncrypted"
  topic_name = "DetectEc2AmiNotEncrypted"
  email      = var.email
}