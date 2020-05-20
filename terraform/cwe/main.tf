module "cwe" {
  source      = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe?ref=v0.6.0"
  name        = "Ec2AmiNotEncrypted"
  description = "A Reflex rule for detecting the creation of unencrypted EC2 AMIs."

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
}
