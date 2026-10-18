# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Store rejects an agreement whose mandate signature does not verify.

SYNTHETIC TEST DATA.
"""

from __future__ import annotations

import json

from tests.test_bureau import _agreement, _auth, _client, _key, _org, _register
from tests.test_postgres_path import _database_url, _reset


def _post(client, operator_key: str, document: dict):
    return client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=json.dumps(document),
    )


def _assert_store(client) -> None:
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    document = json.loads(_agreement().to_json())

    tampered_signature = json.loads(json.dumps(document))
    signature = tampered_signature["mandates"][0]["signature"]["signature"]
    replacement = "A" if signature[:1] != "A" else "B"
    tampered_signature["mandates"][0]["signature"]["signature"] = replacement + signature[1:]
    bad_signature = _post(client, operator_key, tampered_signature)
    assert bad_signature.status_code == 400, bad_signature.text
    assert bad_signature.json() == {"error": "agreement signature is not valid"}

    tampered_body = json.loads(json.dumps(document))
    tampered_body["mandates"][0]["intent"]["maximum_amount"] = 1
    bad_body = _post(client, operator_key, tampered_body)
    assert bad_body.status_code == 400, bad_body.text
    assert bad_body.json() == {"error": "agreement signature does not match the document"}

    missing = client.get("/v1/agents/shopper-01/intents", headers=_auth(operator_key))
    assert missing.status_code == 200, missing.text
    assert missing.json() == []

    valid = _post(client, operator_key, document)
    assert valid.status_code == 200, valid.text
    assert valid.json()["agreement_id"] == "agr_test"
    assert valid.json()["intents"][0]["maximum_amount"] == 1500


def test_store_rejects_a_tampered_signature_and_a_tampered_body():
    _assert_store(_client())


def test_store_rejects_a_tampered_signature_and_a_tampered_body_on_postgres():
    url = _database_url()
    _reset(url)
    _assert_store(_client(database_url=url, schema_url=url))
