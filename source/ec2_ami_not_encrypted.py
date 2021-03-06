""" Module for enforcing PublicAccessBlockRule """

import json
from reflex_core import AWSRule, subscription_confirmation
from reflex_core.notifiers import sns_notifier


class Ec2AmiNotEncrypted(AWSRule):
    """
    A Reflex rule for detecting the creation of unencrypted EC2 AMIs
    """

    def __init__(self, event):
        self.raw_event = None
        self.ami_block_device_mapping = None
        super().__init__(event)

    def extract_event_data(self, event):
        """ To be implemented by every rule """
        self.raw_event = event
        self.ami_block_device_mapping = self.raw_event["detail"]["requestParameters"][
            "blockDeviceMapping"
        ]["items"]

    def resource_compliant(self):
        """ True if all blocks are set to True."""
        return self.all_block_devices_encrypted()

    def all_block_devices_encrypted(self):
        """Iterates over blocks and checks if True."""
        for block_device in self.ami_block_device_mapping:
            if block_device["ebs"]["encrypted"] is False:
                return False
        return True

    def get_remediation_message(self):
        return (
            f"EC2 AMI block devices are not" f" currently encrypted, {self.raw_event}"
        )


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    ami_not_encrypted = Ec2AmiNotEncrypted(event_payload)
    ami_not_encrypted.run_compliance_rule()
