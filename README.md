# reflex-aws-detect-ec2-ami-not-encrypted
A Reflex rule for detecting the creation of unencrypted EC2 AMIs.

## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
version: 0.1

providers:
  - aws

measures:
  - reflex-aws-detect-ec2-ami-not-encrypted:
      email: "example@example.com"
```

or add it directly to your Terraform:  
```
...

module "detect-ec2-ami-not-encrypted" {
  source           = "github.com/cloudmitigator/reflex-aws-detect-ec2-ami-not-encrypted"
  email            = "example@example.com"
}

...
```

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-detect-ec2-ami-not-encrypted/blob/master/LICENSE) 
