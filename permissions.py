from models import PolicyStatement


class PermissionRegistry:
    def __init__(self):
        # Initializes an empty dictionary to store resource type to permissions mapping.
        self._permission_map = {}

    def register(self, resource_type: str, permissions: list[PolicyStatement]) -> None:
        """
        Registers a resource type with its associated permissions list.

        Args:
            resource_type (str): The type of the resource (e.g., 'AWS::S3::Bucket').
            permissions (list): List of permissions associated with the resource type.

        Raises:
            ValueError: If the resource type is already registered.
        """
        if resource_type in self._permission_map:
            raise ValueError(f"Resource '{resource_type}' is already registered.")
        self._permission_map[resource_type] = permissions

    def get(
        self,
        resource_type: str,
        default: list[PolicyStatement] | None = None,
    ) -> list[PolicyStatement] | None:
        """
        Retrieves the permissions associated with a resource type, or returns a default value if not found.

        Args:
            resource_type (str): The type of the resource to retrieve permissions for.
            default (list[PolicyStatement] | None): The default value to return if resource is not found.

        Returns:
            PolicyStatement | None (list): Permissions list or the default value.
        """
        return (
            default
            if resource_type not in self._permission_map
            else self._permission_map[resource_type]
        )

    def __getitem__(self, resource_type: str) -> list[PolicyStatement]:
        """Dictionary-like access to retrieve permissions for a resource type."""
        if resource_type not in self._permission_map:
            raise KeyError(f"Resource '{resource_type}' is not registered.")
        return self._permission_map[resource_type]

    def __setitem__(
        self, resource_type: str, permissions: list[PolicyStatement]
    ) -> None:
        """Dictionary-like setting to register a resource type and its permissions_register."""
        self.register(resource_type, permissions)

    def __delitem__(self, resource_type: str, default=None) -> None:
        """Dictionary-like deletion of a resource type and its permissions_register."""
        return self._permission_map.pop(resource_type, default)

    def __contains__(self, resource_type: str) -> bool:
        """Allows using 'in' to check if a resource type exists."""
        return resource_type in self._permission_map

    def __repr__(self) -> str:
        """
        Returns a string representation of the PermissionRegistry.

        Returns:
            str: A string representation of the resource types in the registry.
        """
        return f"PermissionRegistry({list(self._permission_map.keys())})"


permissions_register = PermissionRegistry()

permissions_register.register(
    resource_type="AWS::EC2::VPC",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:CreateVpc",
                "ec2:DeleteVpc",
                "ec2:DescribeVpcs",
                "ec2:ModifyVpcAttribute",
                "ec2:DescribeTags",
                "ec2:CreateTags",
                "ec2:DeleteTags",
                "ec2:CreateNetworkInterface",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
            ],
            resource=["*"],
        )
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::InternetGateway",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:CreateInternetGateway",
                "ec2:DeleteInternetGateway",
                "ec2:AttachInternetGateway",
                "ec2:DetachInternetGateway",
                "ec2:DescribeInternetGateways",
            ],
            resource=["*"],
        )
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::Route",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:CreateRoute",
                "ec2:DeleteRoute",
                "ec2:DescribeRouteTables",
            ],
            resource=["*"],
        )
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::RouteTable",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:CreateRouteTable",
                "ec2:DeleteRouteTable",
                "ec2:DescribeRouteTables",
            ],
            resource=["*"],
        )
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::SecurityGroup",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:CreateSecurityGroup",
                "ec2:DeleteSecurityGroup",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupEgress",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::SecurityGroupIngress",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DescribeSecurityGroups",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::EIP",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:AllocateAddress",
                "ec2:ReleaseAddress",
            ],
            resource=[
                "arn:{aws_partition}:ec2:{aws_region}:{aws_account_id}:elastic-ip/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::Subnet",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:CreateSubnet",
                "ec2:DeleteSubnet",
                "ec2:DescribeSubnets",
                "ec2:DescribeAddresses",
                "ec2:DescribeAvailabilityZones",
                "ec2:ModifySubnetAttribute",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::SubnetRouteTableAssociation",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:AssociateRouteTable",
                "ec2:DisassociateRouteTable",
                "ec2:DescribeRouteTables",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::VPCGatewayAttachment",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:AttachInternetGateway",
                "ec2:DetachInternetGateway",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::EC2::NatGateway",
    permissions=[
        PolicyStatement(
            action=[
                "ec2:AssociateRouteTable",
                "ec2:DescribeNatGateways",
                "ec2:AssociateNatGatewayAddress",
                "ec2:CreateNatGateway",
                "ec2:DeleteNatGateway",
                "ec2:DisassociateNatGatewayAddress",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::IAM::Role",
    permissions=[
        PolicyStatement(
            action=[
                "iam:*",
                # "iam:GetRole",
                # "iam:CreateRole",
                # "iam:PutRolePolicy",
                # "iam:AttachRolePolicy",
                # "iam:DeleteRole",
                # "iam:DetachRolePolicy",
                # "iam:GetRolePolicy",
            ],
            resource=["arn:{aws_partition}:iam::{aws_account_id}:role/{stack_name}-*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::S3::Bucket",
    permissions=[
        PolicyStatement(
            action=[
                "s3:*",
                # "s3:CreateBucket",
                # "s3:PutBucketPolicy",
                # "s3:DeleteBucket",
                # "s3:ListBucket",
                # "s3:PutBucketOwnershipControls",
                # "s3:PutBucketAcl",
            ],
            resource=["arn:aws:s3:::{stack_name}*"],
            lower=True,
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::DynamoDB::Table",
    permissions=[
        PolicyStatement(
            action=[
                "dynamodb:*",
                # "dynamodb:CreateTable",
                # "dynamodb:DeleteTable",
                # "dynamodb:DescribeTable",
                # "dynamodb:UpdateTable",
                # "dynamodb:Scan",
                # "dynamodb:Query",
                # "dynamodb:GetItem",
                # "dynamodb:PutItem",
                # "dynamodb:DeleteItem",
            ],
            resource=[
                "arn:{aws_partition}:dynamodb:{aws_region}:{aws_account_id}:table/{stack_name}-*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::SNS::Topic",
    permissions=[
        PolicyStatement(
            action=[
                "sns:*",
                # "sns:CreateTopic",
                # "sns:DeleteTopic",
                # "sns:Subscribe",
                # "sns:Unsubscribe",
                # "sns:Publish",
                # "sns:GetTopicAttributes",
                # "sns:SetTopicAttributes",
            ],
            resource=[
                "arn:{aws_partition}:sns:{aws_region}:{aws_account_id}:{stack_name}-*",
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::CloudFront::OriginAccessControl",
    permissions=[
        PolicyStatement(
            action=[
                "cloudfront:*",
                # "cloudfront:CreateOriginAccessControl",
                # "cloudfront:UpdateOriginAccessControl",
                # "cloudfront:DeleteOriginAccessControl",
                # "cloudfront:GetOriginAccessControl",
                # "cloudfront:ListOriginAccessControls",
            ],
            resource=[
                "arn:{aws_partition}:cloudfront::{aws_account_id}:origin-access-control/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::SQS::Queue",
    permissions=[
        PolicyStatement(
            action=[
                "sqs:*",
                # "sqs:CreateQueue",
                # "sqs:DeleteQueue",
                # "sqs:SendMessage",
                # "sqs:ReceiveMessage",
                # "sqs:DeleteMessage",
                # "sqs:GetQueueAttributes",
                # "sqs:SetQueueAttributes",
            ],
            resource=[
                "arn:{aws_partition}:sqs:{aws_region}:{aws_account_id}:{stack_name}-*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::ApiGateway::RestApi",
    permissions=[
        PolicyStatement(
            action=["apigateway:*"],
            resource=["arn:{aws_partition}:apigateway:{aws_region}::/restapis*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::ApiGateway::Account",
    permissions=[
        PolicyStatement(
            action=["apigateway:*"],
            resource=["arn:{aws_partition}:apigateway:{aws_region}::/account*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Lambda::LayerVersion",
    permissions=[
        PolicyStatement(
            action=[
                "lambda:*",
                # "lambda:ListLayers",
                # "lambda:ListLayerVersions",
                # "lambda:GetLayerVersion",
                # "lambda:DeleteLayerVersion",
                # "lambda:PublishLayerVersion",
            ],
            resource=[
                "arn:{aws_partition}:lambda:{aws_region}:{aws_account_id}:layer:{resource_name}*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::SecretsManager::Secret",
    permissions=[
        PolicyStatement(
            action=[
                "secretsmanager:GetRandomPassword",
                "secretsmanager:CreateSecret",
                "secretsmanager:GetSecretValue",
                "secretsmanager:DeleteSecret",
                "secretsmanager:PutSecretValue",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::CloudFront::CloudFrontOriginAccessIdentity",
    permissions=[
        PolicyStatement(
            action=[
                "cloudfront:*",
                # "cloudfront:CreateCloudFrontOriginAccessIdentity",
                # "cloudfront:GetCloudFrontOriginAccessIdentity",
                # "cloudfront:UpdateCloudFrontOriginAccessIdentity",
                # "cloudfront:DeleteCloudFrontOriginAccessIdentity",
                # "cloudfront:ListCloudFrontOriginAccessIdentities",
            ],
            resource=[
                "arn:{aws_partition}:cloudfront::{aws_account_id}:origin-access-identity/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::CloudFront::Distribution",
    permissions=[
        PolicyStatement(
            action=["cloudfront:*"],
            resource=[
                "arn:{aws_partition}:cloudfront::{aws_account_id}:distribution/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Cognito::UserPool",
    permissions=[
        PolicyStatement(
            action=[
                "cognito-idp:*",
                # "cognito-idp:CreateUserPool",
                # "cognito-idp:DeleteUserPool",
            ],
            resource=[
                "arn:{aws_partition}:cognito-idp:{aws_region}:{aws_account_id}:userpool/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Cognito::UserPoolDomain",
    permissions=[
        PolicyStatement(
            action=[
                "cognito-idp:*",
                # "cognito-idp:CreateUserPoolDomain",
            ],
            resource=[
                "arn:{aws_partition}:cognito-idp:{aws_region}:{aws_account_id}:userpool/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Cognito::UserPoolUser",
    permissions=[
        PolicyStatement(
            action=[
                "cognito-idp:*",
                # "cognito-idp:AdminGetUser",
            ],
            resource=[
                "arn:{aws_partition}:cognito-idp:{aws_region}:{aws_account_id}:userpool/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Lambda::Function",
    permissions=[
        PolicyStatement(
            action=[
                "lambda:*",
                # "lambda:CreateFunction",
                # "lambda:DeleteFunction",
                # "lambda:UpdateFunctionCode",
                # "lambda:InvokeFunction",
                # "lambda:GetFunction",
            ],
            resource=[
                "arn:{aws_partition}:lambda:{aws_region}:{aws_account_id}:function:{stack_name}-*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Lambda::EventSourceMapping",
    permissions=[
        PolicyStatement(
            action=["lambda:*"],
            resource=[
                "arn:{aws_partition}:lambda:{aws_region}:{aws_account_id}:event-source-mapping:*"
            ],
        ),
        PolicyStatement(
            action=[
                "lambda:GetEventSourceMapping",
                "lambda:CreateEventSourceMapping",
                "lambda:UpdateEventSourceMapping",
                "lambda:DeleteEventSourceMapping",
                "lambda:ListEventSourceMappings",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::RDS::DBSubnetGroup",
    permissions=[
        PolicyStatement(
            action=[
                "rds:*",
                # "rds:CreateDBSubnetGroup",
                # "rds:DeleteDBSubnetGroup",
                # "rds:DescribeDBSubnetGroups",
            ],
            resource=[
                "arn:{aws_partition}:rds:{aws_region}:{aws_account_id}:subgrp:{stack_name}-*"
            ],
            lower=True,
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::RDS::DBCluster",
    permissions=[
        PolicyStatement(
            action=["rds:*"],
            resource=[
                "arn:{aws_partition}:rds:{aws_region}:{aws_account_id}:cluster:{stack_name}-*",
                "arn:{aws_partition}:rds:{aws_region}:{aws_account_id}:cluster-*:*",
            ],
            lower=True,
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::RDS::DBInstance",
    permissions=[
        PolicyStatement(
            action=[
                "rds:*",
                # "rds:CreateDBInstance",
                # "rds:DeleteDBInstance",
                # "rds:DescribeDBInstances",
                # "rds:ModifyDBInstance",
            ],
            resource=[
                "arn:{aws_partition}:rds:{aws_region}:{aws_account_id}:cluster:{stack_name}-*",
                "arn:{aws_partition}:rds:{aws_region}:{aws_account_id}:db:{stack_name}-*",
            ],
            lower=True,
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::RDS::DBProxy",
    permissions=[
        PolicyStatement(
            action=["rds:*"],
            resource=[
                "arn:{aws_partition}:rds:{aws_region}:{aws_account_id}:db-proxy:*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::RDS::DBProxyTargetGroup",
    permissions=[
        PolicyStatement(
            action=["rds:*"],
            resource=[
                "arn:{aws_partition}:rds:{aws_region}:{aws_account_id}:target-group:*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::IAM::Policy",
    permissions=[
        PolicyStatement(
            action=[
                "iam:*",
                # "iam:CreatePolicy",
                # "iam:DeletePolicy",
                # "iam:AttachRolePolicy",
                # "iam:DetachRolePolicy",
                # "iam:ListPolicies",
            ],
            resource=[
                "arn:{aws_partition}:iam::{aws_account_id}:policy/{stack_name}-*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::CloudFront::CachePolicy",
    permissions=[
        PolicyStatement(
            action=[
                "cloudfront:*",
                # "cloudfront:CreateCachePolicy",
                # "cloudfront:UpdateCachePolicy",
                # "cloudfront:DeleteCachePolicy",
                # "cloudfront:GetCachePolicy",
                # "cloudfront:ListCachePolicies",
            ],
            resource=[
                "arn:{aws_partition}:cloudfront::{aws_account_id}:cache-policy/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::IoT::TopicRule",
    permissions=[
        PolicyStatement(
            action=[
                "iot:*",
                # "iot:CreateTopicRule",
                # "iot:DeleteTopicRule",
                # "iot:GetTopicRule",
                # "iot:ListTopicRules",
                # "iot:GetTopicRuleDestination",
                # "iot:ConfirmTopicRuleDestination",
                # "iot:CreateTopicRuleDestination",
                # "iot:DeleteTopicRuleDestination",
                # "iot:ReplaceTopicRule",
                # "iot:UpdateTopicRuleDestination",
            ],
            resource=[
                "arn:{aws_partition}:iot:{aws_region}:{aws_account_id}:rule/{resource_name}*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::KMS::Key",
    permissions=[
        PolicyStatement(
            action=[
                "kms:CreateKey",
                "kms:DisableKey",
                "kms:CreateGrant",
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:EnableKeyRotation",
                "kms:Encrypt",
                "kms:GenerateDataKey*",
                "kms:Get*",
                "kms:List*",
                "kms:PutKeyPolicy",
                "kms:ScheduleKeyDeletion",
                "kms:TagResource",
            ],
            resource=["*"],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::KMS::Alias",
    permissions=[
        PolicyStatement(
            action=[
                "kms:ListAliases",
                "kms:CreateAlias",
                "kms:DeleteAlias",
                "kms:UpdateAlias",
            ],
            resource=[
                "arn:{aws_partition}:kms:{aws_region}:{aws_account_id}:key/*",
                "arn:{aws_partition}:kms:{aws_region}:{aws_account_id}:alias/*",
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Athena::WorkGroup",
    permissions=[
        PolicyStatement(
            action=["athena:*"],
            resource=[
                "arn:{aws_partition}:athena:{aws_region}:{aws_account_id}:workgroup/*",
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::IoT::Authorizer",
    permissions=[
        PolicyStatement(
            action=["iot:*"],
            resource=[
                "arn:{aws_partition}:iot:{aws_region}:{aws_account_id}:authorizer/*",
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::IoT::DomainConfiguration",
    permissions=[
        PolicyStatement(
            action=["iot:*"],
            resource=[
                "arn:{aws_partition}:iot:{aws_region}:{aws_account_id}:domainconfiguration/*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::StepFunctions::StateMachine",
    permissions=[
        PolicyStatement(
            action=["states:*"],
            resource=[
                "arn:{aws_partition}:states:{aws_region}:{aws_account_id}:stateMachine:{resource_name}*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::KinesisFirehose::DeliveryStream",
    permissions=[
        PolicyStatement(
            action=["firehose:*"],
            resource=[
                "arn:{aws_partition}:firehose:{aws_region}:{aws_account_id}:deliverystream/{stack_name}*"
            ],
        ),
    ],
)
permissions_register.register(
    resource_type="AWS::Logs::SubscriptionFilter",
    permissions=[
        PolicyStatement(
            action=["logs:*"],
            resource=[
                "arn:{aws_partition}:logs:{aws_region}:{aws_account_id}:log-group:*"
            ],
        ),
    ],
)
# resource_permission_repository.register(
#     resource_type="AWS::SSM::Parameter::Value<String>",
#     policy_statement=PolicyStatementDefinition(
#         action={"ssm:*"},
#         resource={"arn:{aws_partition}:ssm:{aws_region}:{aws_account_id}:parameter/*"},
#     ),
# )
