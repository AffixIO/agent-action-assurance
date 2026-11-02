from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json

def digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

@dataclass(frozen=True)
class Mandate:
    mandate_id: str
    principal: str
    agent_id: str
    tool: str
    resource_prefix: str
    max_value: float | None
    expires_at: int
    one_use: bool = True
    parent_mandate: str | None = None
    mandate_digest: str = ""

    @classmethod
    def issue(cls, mandate_id: str, principal: str, agent_id: str, tool: str, resource_prefix: str, max_value: float | None, expires_at: int, one_use: bool = True, parent_mandate: str | None = None):
        body = {"mandate_id": mandate_id, "principal": principal, "agent_id": agent_id, "tool": tool, "resource_prefix": resource_prefix, "max_value": max_value, "expires_at": expires_at, "one_use": one_use, "parent_mandate": parent_mandate}
        return cls(**body, mandate_digest=digest(body))

@dataclass(frozen=True)
class ActionRequest:
    operation_id: str
    agent_id: str
    tool: str
    resource: str
    value: float | None = None
    requires_review: bool = False

@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    evidence_digest: str
    sequence: int

class PolicyGate:
    """A local, fail-closed policy point. No external action is executed here."""
    def __init__(self):
        self.mandates: dict[str, Mandate] = {}
        self.used_operations: set[str] = set()
        self.revoked_mandates: set[str] = set()
        self.audit: list[dict] = []

    def add(self, mandate: Mandate) -> None: self.mandates[mandate.mandate_id] = mandate
    def revoke(self, mandate_id: str) -> None: self.revoked_mandates.add(mandate_id)

    def check(self, request: ActionRequest, mandate_id: str, now: int) -> Decision:
        mandate = self.mandates.get(mandate_id)
        reason = "allowed"
        outcome = "ALLOW"
        if not mandate: outcome, reason = "DENY", "unknown-mandate"
        elif mandate.mandate_id in self.revoked_mandates: outcome, reason = "DENY", "revoked"
        elif now >= mandate.expires_at: outcome, reason = "DENY", "expired"
        elif request.operation_id in self.used_operations: outcome, reason = "DENY", "replay"
        elif request.agent_id != mandate.agent_id or request.tool != mandate.tool: outcome, reason = "DENY", "identity-or-tool-mismatch"
        elif not request.resource.startswith(mandate.resource_prefix): outcome, reason = "DENY", "resource-out-of-scope"
        elif mandate.max_value is not None and (request.value is None or request.value > mandate.max_value): outcome, reason = "DENY", "value-out-of-scope"
        elif request.requires_review: outcome, reason = "REVIEW", "human-review-required"
        evidence = {"request": request.__dict__, "mandate": mandate.mandate_digest if mandate else None, "outcome": outcome, "reason": reason, "now": now}
        chain = {"sequence": len(self.audit) + 1, "previous": self.audit[-1]["chain_digest"] if self.audit else "GENESIS", "evidence": digest(evidence)}
        chain_digest = digest(chain)
        self.audit.append({**chain, "chain_digest": chain_digest})
        if outcome == "ALLOW" and mandate and mandate.one_use: self.used_operations.add(request.operation_id)
        return Decision(outcome, reason, chain_digest, len(self.audit))

    def verify_audit(self) -> bool:
        previous = "GENESIS"
        for index, event in enumerate(self.audit, 1):
            if event["sequence"] != index or event["previous"] != previous: return False
            if event["chain_digest"] != digest({"sequence": event["sequence"], "previous": event["previous"], "evidence": event["evidence"]}): return False
            previous = event["chain_digest"]
        return True
