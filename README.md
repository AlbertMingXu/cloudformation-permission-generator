# cloudformation-permission-generator
A tool for automatically reading AWS CloudFormation templates and generating the necessary IAM permissions required for deploying the resources defined in the template. 

# Install dependencies

`pip3 install -r requirements.txt`

# Simple Example

```
$ python3 analyze_cloudformation.py
Enter the CloudFormation deployment region (default: us-east-1): **us-east-1**
Enter the CloudFormation AWS Account ID (Required): **123456789012**
Enter the CloudFormation stack name (Required): **ThreeSubnets**
Enter the template uri of CloudFormation (Required): **./ThreeSubnets.template.json**

...
The policy file has been saved to the ./output/da33dc61-5d22-415b-b140-3d07870888f7 directory.
```