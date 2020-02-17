""" Module for enforcing PublicAccessBlockRule """

import json
from reflex_core import AWSRule
from reflex_core.notifiers import sns_notifier


class Ec2AmiNotEncrypted(AWSRule):
    """ AWS rule for ensuring S3 bucket encryption """

    def __init__(self, event):
        super().__init__(event)
        self.is_compliant = False
        self.raw_event = None
        self.ami_block_device_mapping = None

    def extract_event_data(self, event):
        """ To be implemented by every rule """
        self.raw_event = event
        self.ami_block_device_mapping = (
            self.raw_event["detail"]
            ["requestParameters"]
            ["blockDeviceMapping"]
            ["items"])

    def resource_compliant(self):
        """ True if all blocks are set to True."""
        self.is_compliant = self.all_block_devices_encrypted()
        return self.is_compliant

    def all_block_devices_encrypted(self):
        """Iterates over blocks and checks if True."""
        for block_device in self.ami_block_device_mapping:
            if block_device["ebs"]["encrypted"] is False:
                return False
        return True

    def get_remediation_message(self):
        if self.is_compliant is True:
            return "All AMI EC2 block devices are currently encrypted"
        else:
            return f"EC2 AMI block devices are not" \
                   f" currently encrypted, {self.raw_event}"

    def remediate(self):
        self.resource_compliant()


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    ami_not_encrypted = Ec2AmiNotEncrypted(
        json.loads(event["Records"][0]["body"]))
    ami_not_encrypted.run_compliance_rule()
