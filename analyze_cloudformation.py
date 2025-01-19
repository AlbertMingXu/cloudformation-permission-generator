import os
import uuid
import yaml
import json
import boto3
import requests
from typing import Dict
from itertools import zip_longest
from models import PolicyDocument, PolicyStatement
from permissions import permissions_register


AWS_PARTITION = "aws"
AWS_ACCOUNT_ID = ""
AWS_REGION = "us-west-1"
STACK_NAME = ""
TASK_ID = ""
WORK_PATH = ""


class CloudFormationLoader(yaml.SafeLoader):
    pass


def cloudformation_loader(stream):
    CloudFormationLoader.add_constructor(
        "!Ref", lambda loader, node: f"Ref({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!Sub", lambda loader, node: f"Sub({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!GetAtt", lambda loader, node: f"GetAtt({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!Join", lambda loader, node: f"Join({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!FindInMap", lambda loader, node: f"FindInMap({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!If", lambda loader, node: f"If({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!Equals", lambda loader, node: f"Equals({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!And", lambda loader, node: f"And({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!Or", lambda loader, node: f"Or({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!Not", lambda loader, node: f"Not({node.value})"
    )
    CloudFormationLoader.add_constructor(
        "!Base64", lambda loader, node: f"Base64({node.value})"
    )
    return yaml.load(stream, Loader=CloudFormationLoader)


def load_cfn_template(uri: str) -> dict:
    """
    Load a CloudFormation template from a URI.
    """
    if uri.startswith(("http://", "https://")):
        template = requests.get(url=uri).text
    elif os.path.isfile(path=uri):
        template = open(uri, "r").read()
    else:
        raise ValueError(
            f"Invalid URI: {uri}, Only local files or HTTP URLs are supported."
        )

    try:
        return cloudformation_loader(template)
    except yaml.YAMLError:
        return json.loads(template)


def merge_permissions(
    permissions_1: Dict[str, list[PolicyStatement]],
    permissions_2: Dict[str, list[PolicyStatement]],
) -> Dict[str, list[PolicyStatement]]:
    """
    Merge two dictionaries of PolicyStatement objects, combining 'action' and 'resource' for matching resource types.
    """
    for resource_type, policy_statements in permissions_2.items():
        if resource_type in permissions_1:
            # Merge the resource lists by taking the union of the two
            permissions_1[resource_type] = [
                PolicyStatement(
                    action=x.action,
                    resource=list(set(x.resource) | set(y.resource)),
                )
                for x, y in zip(
                    permissions_1[resource_type],
                    policy_statements,
                )
            ]
        else:
            permissions_1[resource_type] = policy_statements
    return permissions_1


def format_policy_statement(
    resource_name: str,
    policy_statement: PolicyStatement,
    aws_partition: str,
    aws_region: str,
    aws_account_id: str,
    stack_name: str,
) -> PolicyStatement:
    new_policy_statement = policy_statement.model_copy(deep=True)
    new_policy_statement.resource = [
        x.format(
            aws_partition=aws_partition,
            aws_region=aws_region,
            aws_account_id=aws_account_id,
            stack_name=(
                stack_name.lower() if new_policy_statement.lower is True else stack_name
            ),
            resource_name=(
                resource_name[:28].lower()
                if new_policy_statement.lower is True
                else resource_name[:28]
            ),
        )
        for x in new_policy_statement.resource
    ]
    return new_policy_statement


def analyze_cfn_template(
    template: dict,
) -> tuple[Dict[str, list[PolicyStatement]], set]:
    permissions = {}
    missing_resource_type = set()

    for name, attributes in template["Resources"].items():
        resource_type = attributes["Type"]

        if resource_type == "AWS::CloudFormation::Stack":
            sub_permissions, sub_missing_resource_type = analyze_cfn_template(
                template=load_cfn_template(uri=attributes["Properties"]["TemplateURL"])
            )
            permissions = merge_permissions(permissions, sub_permissions)
            missing_resource_type.update(sub_missing_resource_type)
            continue

        if resource_type in permissions_register:
            permissions[resource_type] = [
                (
                    PolicyStatement(
                        action=x.action,
                        resource=list(
                            set(x.resource)
                            | set(
                                format_policy_statement(
                                    resource_name=name,
                                    policy_statement=y,
                                    aws_partition=AWS_PARTITION,
                                    aws_region=AWS_REGION,
                                    aws_account_id=AWS_ACCOUNT_ID,
                                    stack_name=STACK_NAME,
                                ).resource
                            )
                        ),
                    )
                    if x is not None
                    else PolicyStatement(
                        action=y.action,
                        resource=format_policy_statement(
                            resource_name=name,
                            policy_statement=y,
                            aws_partition=AWS_PARTITION,
                            aws_region=AWS_REGION,
                            aws_account_id=AWS_ACCOUNT_ID,
                            stack_name=STACK_NAME,
                        ).resource,
                    )
                )
                for x, y in zip_longest(
                    permissions.get(resource_type, []),
                    permissions_register[resource_type],
                )
            ]
        else:
            missing_resource_type.add(resource_type)

    for name, attributes in template["Parameters"].items():
        if attributes["Type"] == "AWS::SSM::Parameter::Value<String>":
            permissions["AWS::SSM::Parameter::Value<String>"] = [
                PolicyStatement(
                    action=["ssm:*"],
                    resource=[
                        "arn:{aws_partition}:ssm:{aws_region}:{aws_account_id}:parameter/*".format(
                            aws_partition=AWS_PARTITION,
                            aws_region=AWS_REGION,
                            aws_account_id=AWS_ACCOUNT_ID,
                        )
                    ],
                )
            ]

    return permissions, missing_resource_type


def ask_for_input(prompt: str, default: str | None = None) -> str:
    if default is not None:
        # If default is provided, prompt the user with a default value
        user_input = input(f"{prompt} (default: {default}): ")
        return user_input if user_input else default
    else:
        # If no default, make input required (user cannot skip)
        user_input = input(f"{prompt} (Required): ")
        while not user_input:
            print("This field is required. Please enter a value.")
            user_input = input(f"{prompt} (Required): ")
        return user_input


def write_policy_file(path: str, policy_document: PolicyDocument):
    with open(path, "w") as f:
        f.write(
            policy_document.model_dump_json(exclude_none=True, by_alias=True, indent=4)
        )


if __name__ == "__main__":
    AWS_REGION = ask_for_input(
        "Enter the CloudFormation deployment region", "us-east-1"
    )
    AWS_ACCOUNT_ID = ask_for_input("Enter the CloudFormation AWS Account ID")
    STACK_NAME = ask_for_input("Enter the CloudFormation stack name")
    TEMPLATE_URI = ask_for_input("Enter the template uri of CloudFormation")

    AWS_PARTITION = boto3.Session().get_partition_for_region(region_name=AWS_REGION)

    print(
        f"Region: {AWS_REGION}, Account ID: {AWS_ACCOUNT_ID}, Stack Name: {STACK_NAME}"
    )

    CURRENT_PATH = os.path.dirname(__file__)
    TASK_ID = str(uuid.uuid4())
    WORK_PATH = f"{CURRENT_PATH}/output/{TASK_ID}"
    os.makedirs(WORK_PATH)

    write_policy_file(
        path=f"{WORK_PATH}/cdk-bootstrap-policy.json",
        policy_document=PolicyDocument(
            statement=[
                PolicyStatement(
                    action=["cloudformation:*"],
                    resource=["*"],
                ),
                PolicyStatement(
                    action=["s3:GetObject"],
                    resource=["arn:aws:s3:::*"],
                ),
                PolicyStatement(
                    action=["s3:*"],
                    resource=[
                        "arn:aws:s3:::cdk-hnb659fds-*",
                        "arn:aws:s3:::cf-templates-*",
                    ],
                ),
                PolicyStatement(
                    action=[
                        "iam:UpdateAssumeRolePolicy",
                        "iam:DeleteRole",
                        "iam:GetRole",
                        "iam:CreateRole",
                        "iam:getRolePolicy",
                        "iam:DeleteRolePolicy",
                        "iam:DetachRolePolicy",
                        "iam:AttachRolePolicy",
                        "iam:PutRolePolicy",
                        "iam:TagRole",
                        "iam:PassRole",
                    ],
                    resource=[
                        "arn:aws:iam::942636716027:role/cdk-hnb659fds-*",
                    ],
                ),
                PolicyStatement(
                    action=[
                        "ecr:CreateRepository",
                        "ecr:PutLifecyclePolicy",
                        "ecr:DeleteRepository",
                        "ecr:SetRepositoryPolicy",
                        "ecr:DescribeRepositories",
                    ],
                    resource=[
                        "arn:aws:ecr:us-west-1:942636716027:repository/cdk-hnb659fds-*",
                    ],
                ),
                PolicyStatement(
                    action=[
                        "ssm:PutParameter",
                        "ssm:DeleteParameter",
                        "ssm:GetParameter",
                        "ssm:GetParameters",
                        "ssm:DeleteParameters",
                    ],
                    resource=[
                        "arn:aws:ssm:us-west-1:942636716027:parameter/cdk-bootstrap/hnb659fds/version",
                    ],
                ),
                PolicyStatement(
                    action=["sns:ListTopics", "iam:ListRoles"],
                    resource=[
                        "*",
                    ],
                ),
                PolicyStatement(
                    action=["sns:ListTopics", "iam:ListRoles"],
                    resource=[
                        "*",
                    ],
                ),
            ]
        ),
    )

    permissions, missing_resource_type = analyze_cfn_template(
        template=load_cfn_template(uri=TEMPLATE_URI)
    )

    policy_document = PolicyDocument()
    for policy_statements in permissions.values():
        policy_document.statement.extend(policy_statements)

        if len(policy_document.model_dump_json()) >= 6144:
            policy_document.statement = policy_document.statement[
                : -len(policy_statements)
            ]
            write_policy_file(
                path=f"{WORK_PATH}/policy-{str(uuid.uuid4()).split("-")[0]}.json",
                policy_document=policy_document,
            )
            policy_document = PolicyDocument(statement=policy_statements)

    if policy_document.statement:
        write_policy_file(
            path=f"{WORK_PATH}/policy-{str(uuid.uuid4()).split("-")[0]}.json",
            policy_document=policy_document,
        )
    print(sorted(missing_resource_type))
    print(f"The policy file has been saved to the {WORK_PATH} directory.")
