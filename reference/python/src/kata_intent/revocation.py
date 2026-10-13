# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Revocation distribution for this version.

Three channels, all checked by the evaluator when the caller supplies them:

- A pull list with a short cache. The default lifetime is five minutes.
- A signed push notification (webhook) wrapping a principal revocation.
- An append-only transparency log of agreements and revocations. The log is
  hash-chained, summarized by a Merkle root, and the tree head is signed.

Nothing here opens a socket. A deployment passes the fetcher, the webhook
body, and the log it already holds.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Sequence

from kata_intent.canonical import canonical_bytes
from kata_intent.document import revocation_document
from kata_intent.errors import KataError
from kata_intent.jws import same_bytes, sign_jws, verify_jws
from kata_intent.keys import PrivateKey, PublicKey
from kata_intent.values import as_time, hash_document, prefixed_hash

PUSH_TYP = "kata-revocation-push+jws"
TREE_HEAD_TYP = "kata-tree-head+jws"
DEFAULT_CACHE_SECONDS = 300


class RevocationCache:
    """Pull-based revocation list. Repeated reads inside ``ttl_seconds`` do not call ``fetcher``."""

    def __init__(self, fetcher: Callable[[], Sequence[Mapping[str, Any]]], ttl_seconds: int = DEFAULT_CACHE_SECONDS):
        if ttl_seconds < 0:
            raise KataError("revocation cache lifetime cannot be negative")
        self.fetcher = fetcher
        self.ttl_seconds = ttl_seconds
        self._cached: list[dict[str, Any]] = []
        self._fetched_at: datetime | None = None
        self.fetches = 0

    def get(self, now: datetime) -> list[dict[str, Any]]:
        if self._fetched_at is not None and now - self._fetched_at < timedelta(seconds=self.ttl_seconds):
            return list(self._cached)
        self.fetches += 1
        self._cached = [dict(item) for item in self.fetcher()]
        self._fetched_at = now
        return list(self._cached)


def sign_revocation_push(revocation: Mapping[str, Any], notifier_key: PrivateKey, at: str | datetime) -> dict[str, Any]:
    """Sign a webhook body that carries a principal revocation."""

    inner = _push_revocation(revocation)
    document = {"at": as_time(at), "kata_revocation_push": "1", "revocation": inner}
    notice = dict(document)
    notice["signature"] = sign_jws(document, notifier_key, typ=PUSH_TYP)
    return notice


def verify_revocation_push(notice: Mapping[str, Any], notifier_key: PublicKey) -> dict[str, Any] | None:
    """Return the inner revocation when ``notifier_key`` signed the webhook. Otherwise ``None``."""

    if not isinstance(notice, Mapping) or "signature" not in notice:
        return None
    check = verify_jws(notice.get("signature") or {}, notifier_key, typ=PUSH_TYP)
    if not check.ok or check.payload_bytes is None:
        return None
    document = {
        "at": notice.get("at"),
        "kata_revocation_push": "1",
        "revocation": _push_revocation(notice.get("revocation") or {}),
    }
    if not same_bytes(check.payload_bytes, canonical_bytes(document)):
        return None
    inner = document["revocation"]
    if not isinstance(inner, dict) or "signature" not in inner:
        return None
    return inner


def _push_revocation(revocation: Mapping[str, Any]) -> dict[str, Any]:
    kept = revocation_document(dict(revocation))
    if revocation.get("signature"):
        kept["signature"] = revocation["signature"]
    if revocation.get("mandate_hashes"):
        kept["mandate_hashes"] = list(revocation["mandate_hashes"])
    return kept


class TransparencyLog:
    """Append-only log. Each entry names the previous entry hash. The root is a Merkle root."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, kind: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if kind not in {"agreement", "revocation"}:
            raise KataError("transparency log entries are agreements or revocations")
        sequence = len(self.entries) + 1
        record: dict[str, Any] = {"body": dict(body), "kind": kind, "sequence": sequence}
        if self.entries:
            record["prev_entry_hash"] = self.entries[-1]["entry_hash"]
        record["entry_hash"] = hash_document({key: value for key, value in record.items() if key != "entry_hash"})
        self.entries.append(record)
        return record

    def leaves(self) -> list[str]:
        return [entry["entry_hash"] for entry in self.entries]

    def root(self) -> str:
        return merkle_root(self.leaves())

    def sign_tree_head(self, private_key: PrivateKey, at: str | datetime) -> dict[str, Any]:
        document = {
            "algorithm": private_key.algorithm,
            "at": as_time(at),
            "kata_tree_head": "1",
            "root": self.root(),
            "tree_size": len(self.entries),
        }
        signed = dict(document)
        signed["signature"] = sign_jws(document, private_key, typ=TREE_HEAD_TYP)
        return signed

    def inclusion_proof(self, sequence: int) -> list[dict[str, str]]:
        if sequence < 1 or sequence > len(self.entries):
            raise KataError("transparency log sequence is outside the tree")
        return merkle_proof(self.leaves(), sequence - 1)

    def verify_chain(self) -> bool:
        previous: str | None = None
        for index, entry in enumerate(self.entries, start=1):
            if entry.get("sequence") != index:
                return False
            if index == 1 and "prev_entry_hash" in entry:
                return False
            if index > 1 and entry.get("prev_entry_hash") != previous:
                return False
            body = {key: value for key, value in entry.items() if key != "entry_hash"}
            if entry.get("entry_hash") != hash_document(body):
                return False
            previous = entry["entry_hash"]
        return True

    def revocations(self) -> list[dict[str, Any]]:
        found = []
        for entry in self.entries:
            if entry["kind"] == "revocation" and isinstance(entry.get("body"), dict):
                found.append(entry["body"])
        return found


def verify_tree_head(head: Mapping[str, Any], public_key: PublicKey, log: TransparencyLog) -> bool:
    """True when ``head`` is a signature by ``public_key`` over ``log``'s current root and size."""

    if not isinstance(head, Mapping) or "signature" not in head:
        return False
    if head.get("algorithm") != public_key.algorithm:
        return False
    check = verify_jws(head.get("signature") or {}, public_key, typ=TREE_HEAD_TYP)
    if not check.ok or check.payload_bytes is None:
        return False
    document = {
        "algorithm": head.get("algorithm"),
        "at": head.get("at"),
        "kata_tree_head": "1",
        "root": head.get("root"),
        "tree_size": head.get("tree_size"),
    }
    if not same_bytes(check.payload_bytes, canonical_bytes(document)):
        return False
    return head.get("tree_size") == len(log.entries) and head.get("root") == log.root()


def merkle_root(leaves: Sequence[str]) -> str:
    """Binary Merkle root. An odd trailing node is duplicated. An empty log hashes the empty string."""

    return _levels(list(leaves))[-1][0]


def merkle_proof(leaves: Sequence[str], index: int) -> list[dict[str, str]]:
    """Sibling hashes from the leaf toward the root. ``side`` is where the sibling sits."""

    levels = _levels(list(leaves))
    proof: list[dict[str, str]] = []
    cursor = index
    for level in levels[:-1]:
        padded = level if len(level) % 2 == 0 else level + [level[-1]]
        if cursor % 2 == 0:
            proof.append({"hash": padded[cursor + 1], "side": "right"})
        else:
            proof.append({"hash": padded[cursor - 1], "side": "left"})
        cursor //= 2
    return proof


def verify_inclusion(leaf_hash: str, index: int, proof: Sequence[Mapping[str, str]], root: str) -> bool:
    """True when ``leaf_hash`` at ``index`` is inside the tree with ``root``."""

    current = leaf_hash
    cursor = index
    for step in proof:
        sibling = step.get("hash")
        side = step.get("side")
        if not isinstance(sibling, str) or side not in {"left", "right"}:
            return False
        if side == "right":
            current = prefixed_hash(canonical_bytes({"left": current, "right": sibling}))
        else:
            current = prefixed_hash(canonical_bytes({"left": sibling, "right": current}))
        cursor //= 2
    return current == root


def _levels(leaves: list[str]) -> list[list[str]]:
    if not leaves:
        return [[prefixed_hash(b"")]]
    level = list(leaves)
    levels = [level]
    while len(level) > 1:
        padded = level if len(level) % 2 == 0 else level + [level[-1]]
        nxt = []
        for index in range(0, len(padded), 2):
            nxt.append(prefixed_hash(canonical_bytes({"left": padded[index], "right": padded[index + 1]})))
        levels.append(nxt)
        level = nxt
    return levels
