# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""The reference objects validate against the published schemas."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from conftest import activate, propose

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas"


def _validator(name: str) -> Draft202012Validator:
    resources = []
    for schema_name in ("intent.json", "intent-mandate.json", "agreement.json"):
        contents = json.loads((SCHEMAS / schema_name).read_text())
        resources.append((contents["$id"], Resource.from_contents(contents)))
    schema = json.loads((SCHEMAS / name).read_text())
    return Draft202012Validator(schema, registry=Registry().with_resources(resources))


def test_active_amended_and_revoked_agreements_match_the_schema(principal_key, agent_key, merchant_key):
    agreement = activate(principal_key, agent_key)
    agreement.acknowledge(
        role="merchant",
        party_id="mer_techstore",
        private_key=merchant_key,
        at="2026-10-04T13:59:00Z",
    )
    agreement.amend(principal_key, "2026-10-04T16:00:00Z", intent={"maximum_amount": 1200})
    validator = _validator("agreement.json")
    validator.validate(json.loads(agreement.to_json()))

    revoked = activate(principal_key, agent_key, agreement_id="agr_revoke")
    revoked.revoke(principal_key, "2026-10-04T18:00:00Z", reason="changed my mind")
    validator.validate(json.loads(revoked.to_json()))


def test_unsigned_draft_matches_the_schema(principal_key, agent_key):
    agreement = propose(principal_key, agent_key)
    _validator("agreement.json").validate(json.loads(agreement.to_json()))


def test_mandate_schema_accepts_the_signed_mandate(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    mandate = json.loads(agreement.to_json())["mandate"]
    _validator("intent-mandate.json").validate(mandate)
