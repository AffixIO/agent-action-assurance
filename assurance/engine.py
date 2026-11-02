"""Trusted host gate with durable reservations and simulated tool examples."""

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict
from itertools import pairwise
from uuid import uuid4

from .crypto import canonical, digest, verify
from .models import ActionRequest, Decision, Execution, Mandate, ToolPolicy, identifier, integer, within


class EnforcementUnavailable(RuntimeError):
    """No execution is permitted when enforcement storage is unavailable."""


class PolicyGate:
    def __init__(self, database, *, audience, authorities, reviewers, audit_signer, clock=None):
        self.database = str(database)
        if self.database == ":memory:":
            raise ValueError("Use a filesystem database for durable replay state")
        if not authorities:
            raise ValueError("At least one pinned authority is required")
        self.audience = audience
        self.authorities = dict(authorities)
        self.reviewers = dict(reviewers)
        self.audit_signer = audit_signer
        self.clock = clock or (lambda: int(time.time()))
        self._tools = {}
        with self._transaction() as db:
            for statement in (
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS mandates (id TEXT PRIMARY KEY, envelope TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS revoked (kind TEXT, id TEXT, PRIMARY KEY(kind,id))",
                "CREATE TABLE IF NOT EXISTS usage (id TEXT PRIMARY KEY, calls INTEGER NOT NULL, amount INTEGER NOT NULL)",
                "CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY)",
                "CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, envelope TEXT NOT NULL)",
            ):
                db.execute(statement)
            identity = {
                "audience": audience,
                "audit_key": audit_signer.public_key,
                "audit_key_id": audit_signer.key_id,
                "schema": "assurance.store.v2",
            }
            old = db.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
            if old and json.loads(old[0]) != identity:
                raise ValueError("Database belongs to a different audience or audit signer")
            db.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('identity',?)", (canonical(identity).decode(),)
            )
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('ledger_id',?)", (str(uuid4()),))
            self.ledger_id = db.execute("SELECT value FROM metadata WHERE key='ledger_id'").fetchone()[0]

    @contextmanager
    def _transaction(self):
        db = None
        try:
            db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except sqlite3.Error as exc:
            if db:
                db.rollback()
            raise EnforcementUnavailable("Enforcement storage unavailable; no automatic retry") from exc
        except BaseException:
            if db:
                db.rollback()
            raise
        finally:
            if db:
                db.close()

    def register_tool(self, policy: ToolPolicy, handler):
        """Trusted startup configuration, never agent-accessible."""
        if not callable(handler):
            raise TypeError("Tool handler must be callable")
        self._tools[policy.tool] = (policy, handler)

    def _event(self, db, kind, details):
        row = db.execute("SELECT seq,envelope FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq = row[0] + 1 if row else 1
        event = {
            "ledger_id": self.ledger_id,
            "sequence": seq,
            "at": self.clock(),
            "kind": kind,
            "details": details,
            "previous": digest(json.loads(row[1])) if row else "GENESIS",
        }
        envelope = self.audit_signer.sign("audit-event", event)
        db.execute("INSERT INTO audit VALUES (?,?)", (seq, canonical(envelope).decode()))
        return envelope

    def _chain(self, db, mandate_id, now):
        chain, visited = [], set()
        while mandate_id:
            if mandate_id in visited or len(visited) >= 5:
                raise ValueError("invalid-delegation-depth")
            visited.add(mandate_id)
            row = db.execute("SELECT envelope FROM mandates WHERE id=?", (mandate_id,)).fetchone()
            if not row:
                raise ValueError("unknown-mandate")
            envelope = json.loads(row[0])
            if self._revoked(db, "key", envelope["key_id"]) or self._revoked(db, "mandate", mandate_id):
                raise ValueError("revoked")
            mandate = Mandate(**verify(envelope, self.authorities, "mandate"))
            if mandate.mandate_id != mandate_id or mandate.audience != self.audience:
                raise ValueError("mandate-binding-mismatch")
            if not mandate.not_before <= now < mandate.expires_at:
                raise ValueError("expired-or-not-yet-valid")
            chain.append(mandate)
            mandate_id = mandate.parent_mandate
        for child, parent in pairwise(chain):
            self._attenuated(child, parent)
        return chain

    @staticmethod
    def _attenuated(child, parent):
        if (
            not parent.can_delegate
            or child.principal != parent.principal
            or child.tool != parent.tool
            or child.audience != parent.audience
            or child.currency != parent.currency
            or not within(child.resource_scope, parent.resource_scope)
            or child.max_amount_minor > parent.max_amount_minor
            or child.total_budget_minor > parent.total_budget_minor
            or child.max_calls > parent.max_calls
            or child.not_before < parent.not_before
            or child.expires_at > parent.expires_at
        ):
            raise ValueError("delegation-broadens-authority")

    def add(self, signed_mandate):
        mandate = Mandate(**verify(signed_mandate, self.authorities, "mandate"))
        with self._transaction() as db:
            old = db.execute("SELECT envelope FROM mandates WHERE id=?", (mandate.mandate_id,)).fetchone()
            if old:
                if json.loads(old[0]) != signed_mandate:
                    raise ValueError("Mandate IDs are immutable")
                return
            db.execute(
                "INSERT INTO mandates VALUES (?,?)", (mandate.mandate_id, canonical(signed_mandate).decode())
            )
            self._chain(db, mandate.mandate_id, self.clock())
            db.execute("INSERT INTO usage VALUES (?,0,0)", (mandate.mandate_id,))
            self._event(db, "mandate-added", {"mandate_digest": digest(asdict(mandate))})

    @staticmethod
    def _revoked(db, kind, identity):
        return (
            db.execute("SELECT 1 FROM revoked WHERE kind=? AND id=?", (kind, identity)).fetchone() is not None
        )

    def revoke(self, identity, *, kind="mandate"):
        """Trusted administration only. Revoking a parent invalidates its descendants."""
        if kind not in {"mandate", "key", "approval"}:
            raise ValueError("Unknown revocation type")
        with self._transaction() as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?,?)", (kind, identity))
            self._event(db, "revoked", {"type": kind, "id_digest": digest(identity)})

    def _evaluate(self, db, request, mandate_id, actor, approval):
        now = self.clock()
        integer(now)
        if request.agent_id != actor:
            return "DENY", "authenticated-actor-mismatch", [], None
        if request.audience != self.audience:
            return "DENY", "wrong-audience", [], None
        if request.tool not in self._tools:
            return "DENY", "unknown-tool", [], None
        policy = self._tools[request.tool][0]
        if set(request.arguments) != set(policy.argument_keys):
            return "DENY", "argument-schema-mismatch", [], None
        try:
            chain = self._chain(db, mandate_id, now)
        except (ValueError, TypeError) as exc:
            return "DENY", str(exc), [], None
        if not chain:
            return "DENY", "unknown-mandate", [], None
        mandate = chain[0]
        if mandate.agent_id != actor or mandate.tool != request.tool:
            return "DENY", "identity-or-tool-mismatch", chain, None
        if not within(request.resource, mandate.resource_scope):
            return "DENY", "resource-out-of-scope", chain, None
        if request.currency != mandate.currency or request.amount_minor > mandate.max_amount_minor:
            return "DENY", "value-out-of-scope", chain, None
        if db.execute("SELECT 1 FROM operations WHERE id=?", (request.operation_id,)).fetchone():
            return "DENY", "replay", chain, None
        for ancestor in chain:
            calls, amount = db.execute(
                "SELECT calls,amount FROM usage WHERE id=?", (ancestor.mandate_id,)
            ).fetchone()
            if calls >= ancestor.max_calls:
                return "DENY", "call-limit", chain, None
            if amount + request.amount_minor > ancestor.total_budget_minor:
                return "DENY", "budget-exhausted", chain, None
        review = policy.always_review or (
            policy.review_above_minor is not None and request.amount_minor > policy.review_above_minor
        )
        if review and approval is None:
            return "REVIEW", "human-review-required", chain, None
        approval_id = None
        if approval is not None:
            try:
                approved = verify(approval, self.reviewers, "approval")
                required = {
                    "approval_id",
                    "request_digest",
                    "mandate_digest",
                    "policy_digest",
                    "audience",
                    "not_before",
                    "expires_at",
                }
                if set(approved) != required:
                    raise ValueError("approval-schema-mismatch")
                integer(approved["not_before"])
                integer(approved["expires_at"])
                if (
                    approved["request_digest"] != request.fingerprint
                    or approved["mandate_digest"] != digest(asdict(mandate))
                    or approved["policy_digest"] != policy.fingerprint
                    or approved["audience"] != self.audience
                ):
                    raise ValueError("approval-binding-mismatch")
                if not approved["not_before"] <= now < approved["expires_at"]:
                    raise ValueError("approval-expired-or-not-yet-valid")
                approval_id = approved["approval_id"]
                identifier(approval_id)
                if self._revoked(db, "key", approval["key_id"]) or self._revoked(db, "approval", approval_id):
                    raise ValueError("approval-revoked")
                if db.execute("SELECT 1 FROM approvals WHERE id=?", (approval_id,)).fetchone():
                    raise ValueError("approval-replay")
            except (ValueError, TypeError, KeyError) as exc:
                return "DENY", str(exc), chain, None
        return "ALLOW", "allowed", chain, approval_id

    def _decide(self, db, request, mandate_id, actor, approval, reserve):
        outcome, reason, chain, approval_id = self._evaluate(db, request, mandate_id, actor, approval)
        policy = self._tools.get(request.tool, (None,))[0]
        if outcome == "ALLOW" and reserve:
            db.execute(
                "INSERT INTO operations VALUES (?,?, 'RESERVED')", (request.operation_id, request.fingerprint)
            )
            for mandate in chain:
                db.execute(
                    "UPDATE usage SET calls=calls+1, amount=amount+? WHERE id=?",
                    (request.amount_minor, mandate.mandate_id),
                )
            if approval_id:
                db.execute("INSERT INTO approvals VALUES (?)", (approval_id,))
        envelope = self._event(
            db,
            "decision",
            {
                "operation_id": request.operation_id,
                "request_digest": request.fingerprint,
                "policy_digest": policy.fingerprint if policy else None,
                "mandate_chain": [digest(asdict(m)) for m in chain],
                "outcome": outcome,
                "reason": reason,
                "reserved": reserve and outcome == "ALLOW",
            },
        )
        return Decision(outcome, reason, digest(envelope), envelope["payload"]["sequence"], envelope)

    def check(self, request, mandate_id, *, authenticated_agent, approval=None):
        """A preview, not an executable authorisation. execute() rechecks everything."""
        request = ActionRequest(**json.loads(canonical(asdict(request))))
        with self._transaction() as db:
            return self._decide(db, request, mandate_id, authenticated_agent, approval, False)

    def execute(self, request, mandate_id, *, authenticated_agent, approval=None):
        request = ActionRequest(**json.loads(canonical(asdict(request))))
        request_digest = request.fingerprint
        with self._transaction() as db:
            decision = self._decide(db, request, mandate_id, authenticated_agent, approval, True)
            handler = self._tools.get(request.tool, (None, None))[1]
        if decision.outcome != "ALLOW":
            return Execution(decision, "BLOCKED")
        # Commit reservation BEFORE dispatch. Lost responses remain uncertain.
        try:
            result = handler(request)
            result_digest = digest(result)
            state = "COMPLETED"
        except Exception:  # noqa: BLE001 - all tool failures leave the reservation consumed
            result, result_digest, state = None, None, "UNCERTAIN"
        with self._transaction() as db:
            db.execute("UPDATE operations SET state=? WHERE id=?", (state, request.operation_id))
            self._event(
                db,
                "execution",
                {
                    "operation_id": request.operation_id,
                    "request_digest": request_digest,
                    "state": state,
                    "result_digest": result_digest,
                },
            )
        return Execution(decision, state, result)

    def operation_state(self, operation_id):
        with self._transaction() as db:
            row = db.execute("SELECT state FROM operations WHERE id=?", (operation_id,)).fetchone()
            return row[0] if row else None

    def export_audit(self):
        with self._transaction() as db:
            events = [json.loads(row[0]) for row in db.execute("SELECT envelope FROM audit ORDER BY seq")]
            checkpoint = self.audit_signer.sign(
                "checkpoint",
                {
                    "ledger_id": self.ledger_id,
                    "count": len(events),
                    "head": digest(events[-1]) if events else "GENESIS",
                    "at": self.clock(),
                },
            )
            return {"schema": "assurance.audit.v1", "events": events, "checkpoint": checkpoint}


def verify_audit(bundle, *, trusted_keys, expected_ledger_id, expected_checkpoint):
    """Require an independently retained checkpoint and pinned public key."""
    try:
        checkpoint = verify(expected_checkpoint, trusted_keys, "checkpoint")
        if bundle["schema"] != "assurance.audit.v1" or bundle["checkpoint"] != expected_checkpoint:
            return False
        if checkpoint["ledger_id"] != expected_ledger_id or len(bundle["events"]) != checkpoint["count"]:
            return False
        previous = "GENESIS"
        for index, envelope in enumerate(bundle["events"], 1):
            event = verify(envelope, trusted_keys, "audit-event")
            if (
                event["sequence"] != index
                or event["previous"] != previous
                or event["ledger_id"] != expected_ledger_id
            ):
                return False
            previous = digest(envelope)
        return previous == checkpoint["head"]
    except (ValueError, TypeError, KeyError):
        return False
