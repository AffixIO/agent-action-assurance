"""Pinned Ed25519 signatures over a deliberately restricted JSON profile."""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value):
    def validate(item, depth=0):
        if depth > 20:
            raise ValueError("JSON nesting limit")
        if item is None or type(item) is bool:
            return
        if type(item) is int and abs(item) <= 2**53 - 1:
            return
        if type(item) is str:
            item.encode("utf-8")
            return
        if type(item) is list:
            for child in item:
                validate(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for key, child in item.items():
                validate(key, depth + 1)
                validate(child, depth + 1)
            return
        raise ValueError("Use JSON strings, booleans, null and safe integers; no floats")

    validate(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(raw) > 65536:
        raise ValueError("JSON size limit")
    return raw


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_loads(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    if len(raw) > 65536:
        raise ValueError("JSON size limit")
    value = json.loads(raw, object_pairs_hook=unique)
    canonical(value)
    return value


class SigningKey:
    """The host owns these keys; never hand them to an agent."""

    def __init__(self, key_id, private_key=None):
        self.key_id = key_id
        self._key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self):
        return self._key.public_key().public_bytes_raw().hex()

    def sign(self, kind, payload):
        protected = {
            "schema": "assurance.signature.v1",
            "algorithm": "Ed25519",
            "kind": kind,
            "key_id": self.key_id,
            "payload": payload,
        }
        signature = self._key.sign(canonical(protected))
        return {**protected, "signature": base64.b64encode(signature).decode()}


def verify(envelope, pins, kind):
    try:
        if set(envelope) != {"schema", "algorithm", "kind", "key_id", "payload", "signature"}:
            raise ValueError("Invalid envelope")
        if (envelope["schema"], envelope["algorithm"], envelope["kind"]) != (
            "assurance.signature.v1",
            "Ed25519",
            kind,
        ):
            raise ValueError("Wrong signature context")
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pins[envelope["key_id"]]))
        protected = {k: v for k, v in envelope.items() if k != "signature"}
        key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(protected))
        return json.loads(canonical(envelope["payload"]))
    except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid signature or untrusted signer") from exc
