from typing import Literal, Any
from pydantic import BaseModel, Field


class PolicyStatement(BaseModel):
    effect: Literal["Allow", "Deny"] = Field("Allow", alias="Effect")
    action: list[str] = Field(..., alias="Action")
    resource: list[str] = Field(..., alias="Resource")
    lower: bool | None = None

    def __init__(
        self,
        effect: Literal["Allow", "Deny"] = "Allow",
        action: list[str] = [],
        resource: list[str] = [],
        lower: bool | None = None,
        **data: Any,
    ):
        data["Effect"] = data["Effect"] if "Effect" in data else effect
        data["Action"] = data["Action"] if "Action" in data else action
        data["Resource"] = data["Resource"] if "Resource" in data else resource
        data["lower"] = lower
        super().__init__(**data)


class PolicyDocument(BaseModel):
    version: str = Field("2012-10-17", alias="Version")
    statement: list[PolicyStatement] = Field(..., alias="Statement")

    def __init__(
        self,
        version: str = "2012-10-17",
        statement: list[PolicyStatement] = [],
        **data: Any,
    ):
        data["Version"] = data["Version"] if "Version" in data else version
        data["Statement"] = data["Statement"] if "Statement" in data else statement
        super().__init__(**data)
