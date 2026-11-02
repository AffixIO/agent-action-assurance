"""Version 0.2 uses integer minor units and explicit host-owned policy."""

import re
from dataclasses import asdict, dataclass, field

from .crypto import canonical, digest


def identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise ValueError("Invalid identifier")


def resource(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value):
        raise ValueError("Resource must contain literal path segments, without encoding or traversal")


def within(value, scope):
    return value == scope or value.startswith(scope + "/")


def integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 2**53 - 1:
        raise ValueError("Expected bounded non-negative integer")


@dataclass(frozen=True)
class ActionRequest:
    operation_id: str
    agent_id: str
    tool: str
    resource: str
    audience: str
    amount_minor: int = 0
    currency: str = "GBP"
    arguments: dict = field(default_factory=dict)

    def __post_init__(self):
        for value in (self.operation_id, self.agent_id, self.tool, self.audience):
            identifier(value)
        resource(self.resource)
        integer(self.amount_minor)
        if not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("Currency must be a three-letter code")
        if type(self.arguments) is not dict:
            raise ValueError("Arguments must be an object")
        canonical(asdict(self))

    @property
    def fingerprint(self):
        return digest(asdict(self))


@dataclass(frozen=True)
class Mandate:
    mandate_id: str
    principal: str
    agent_id: str
    tool: str
    resource_scope: str
    audience: str
    max_amount_minor: int
    total_budget_minor: int
    max_calls: int
    not_before: int
    expires_at: int
    currency: str = "GBP"
    parent_mandate: str | None = None
    can_delegate: bool = False

    def __post_init__(self):
        for value in (self.mandate_id, self.principal, self.agent_id, self.tool, self.audience):
            identifier(value)
        resource(self.resource_scope)
        if self.parent_mandate is not None:
            identifier(self.parent_mandate)
        for value in (self.max_amount_minor, self.total_budget_minor, self.not_before, self.expires_at):
            integer(value)
        integer(self.max_calls, 1)
        if self.expires_at <= self.not_before or self.max_amount_minor > self.total_budget_minor:
            raise ValueError("Invalid validity window or budget")
        if type(self.can_delegate) is not bool or not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("Invalid delegation flag or currency")

    def signed(self, authority):
        return authority.sign("mandate", asdict(self))


@dataclass(frozen=True)
class ToolPolicy:
    tool: str
    version: str
    review_above_minor: int | None = None
    always_review: bool = False
    argument_keys: tuple[str, ...] = ()

    def __post_init__(self):
        identifier(self.tool)
        identifier(self.version)
        if self.review_above_minor is not None:
            integer(self.review_above_minor)
        if type(self.always_review) is not bool:
            raise ValueError("Invalid review policy")
        if len(set(self.argument_keys)) != len(self.argument_keys):
            raise ValueError("Duplicate argument key")
        for key in self.argument_keys:
            identifier(key)

    @property
    def fingerprint(self):
        return digest({**asdict(self), "argument_keys": list(self.argument_keys)})


def approve(request, mandate, policy, reviewer, *, approval_id, not_before, expires_at):
    """Call only after a trusted reviewer has seen the exact action."""
    identifier(approval_id)
    integer(not_before)
    integer(expires_at)
    if not_before >= expires_at:
        raise ValueError("Invalid approval window")
    return reviewer.sign(
        "approval",
        {
            "approval_id": approval_id,
            "request_digest": request.fingerprint,
            "mandate_digest": digest(asdict(mandate)),
            "policy_digest": policy.fingerprint,
            "audience": request.audience,
            "not_before": not_before,
            "expires_at": expires_at,
        },
    )


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    evidence_digest: str
    sequence: int
    receipt: dict


@dataclass(frozen=True)
class Execution:
    decision: Decision
    state: str
    value: object = None
