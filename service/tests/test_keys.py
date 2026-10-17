# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Key custody. SYNTHETIC TEST DATA only. No production keys."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kata_service.keys import (
    ENV_PROVIDER_NOTICE,
    AwsKmsEnvelopeProvider,
    EnvKeyProvider,
    KeyCustodyError,
    dek_encryption_context,
    hmac_encryption_context,
    parse_hmac_token,
    provider_from_env,
)
from kata_service.settings import settings_from_env

# 32-byte labels. SYNTHETIC TEST DATA. Not a credential for any host.
_HMAC_KEY = b"SYNTHETIC TEST DATA key-00000000"
_HMAC_KEY_OLD = b"SYNTHETIC TEST DATA key-old!!!!!"
_KEK = b"SYNTHETIC TEST DATA local-kek!!!"
_KMS_KEK = b"SYNTHETIC TEST DATA kms-kek!!!!!"
_EMAIL = "synthetic-test-data@example.com"
_MASTER = "alias/gab-synthetic-test"

assert len(_HMAC_KEY) == len(_HMAC_KEY_OLD) == len(_KEK) == len(_KMS_KEK) == 32


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _ring() -> dict[str, dict[str, object]]:
    return {
        "email-old": {"secret": _HMAC_KEY_OLD, "purposes": ["identifier"], "active": False},
        "email-new": {"secret": _HMAC_KEY, "purposes": ["identifier"], "active": True},
        "ip-1": {"secret": _HMAC_KEY, "purposes": ["rate"], "active": True},
        "local-kek": {"secret": _KEK, "purposes": ["kek"], "active": True},
    }


def _env_json() -> str:
    return json.dumps(
        {
            "email-old": {"secret": _b64(_HMAC_KEY_OLD), "purposes": ["identifier"]},
            "email-new": {"secret": _b64(_HMAC_KEY), "purposes": ["identifier"], "active": True},
            "local-kek": {"secret": _b64(_KEK), "purposes": ["kek"], "active": True},
        }
    )


class FakeKms:
    """In-memory stand-in for AWS KMS. SYNTHETIC TEST DATA. Not a second production provider."""

    def __init__(self) -> None:
        self.kek = _KMS_KEK
        self.calls: list[str] = []

    def generate_data_key(self, *, key_id: str, encryption_context: dict[str, str]) -> tuple[bytes, bytes]:
        self.calls.append("generate_data_key")
        assert key_id == _MASTER
        dek = os.urandom(32)
        return dek, self.encrypt(key_id=key_id, plaintext=dek, encryption_context=encryption_context)

    def encrypt(self, *, key_id: str, plaintext: bytes, encryption_context: dict[str, str]) -> bytes:
        self.calls.append("encrypt")
        assert key_id == _MASTER
        nonce = os.urandom(12)
        aad = json.dumps(encryption_context, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return nonce + AESGCM(self.kek).encrypt(nonce, plaintext, aad)

    def decrypt(self, *, key_id: str, ciphertext: bytes, encryption_context: dict[str, str]) -> bytes:
        self.calls.append("decrypt")
        assert key_id == _MASTER
        nonce, body = ciphertext[:12], ciphertext[12:]
        aad = json.dumps(encryption_context, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return AESGCM(self.kek).decrypt(nonce, body, aad)


def _independent_hmac(key: bytes, purpose: str, value: str) -> str:
    message = b"gab-hmac-v1\x00" + purpose.encode("utf-8") + b"\x00" + value.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def test_hmac_matches_an_independent_vector():
    provider = EnvKeyProvider(_ring())
    token = provider.hmac(_EMAIL, purpose="identifier")
    assert token.encode() == "v1:email-new:" + _independent_hmac(_HMAC_KEY, "identifier", _EMAIL)
    assert token.kid == "email-new"
    assert parse_hmac_token(token.encode()) == token


def test_rotation_keeps_old_kid_verifiable_and_writes_the_active_kid():
    provider = EnvKeyProvider(_ring())
    old = "v1:email-old:" + _independent_hmac(_HMAC_KEY_OLD, "identifier", _EMAIL)
    assert provider.verify(old, _EMAIL, purpose="identifier") is True
    fresh = provider.hmac(_EMAIL, purpose="identifier")
    assert fresh.kid == "email-new"
    assert provider.verify(fresh.encode(), _EMAIL, purpose="identifier") is True
    assert provider.verify(fresh.encode(), "other@example.com", purpose="identifier") is False
    tokens = provider.hmac_tokens(_EMAIL, purpose="identifier")
    assert [item.kid for item in tokens] == ["email-new", "email-old"]


def test_verify_uses_compare_digest(monkeypatch):
    provider = EnvKeyProvider(_ring())
    token = provider.hmac(_EMAIL, purpose="identifier").encode()
    seen: list[bool] = []
    real = hmac.compare_digest

    def spy(left, right):
        seen.append(True)
        return real(left, right)

    monkeypatch.setattr("kata_service.keys.hmac.compare_digest", spy)
    assert provider.verify(token, _EMAIL, purpose="identifier") is True
    assert seen


def test_env_provider_is_marked_non_production_and_hides_secrets():
    provider = EnvKeyProvider(_ring())
    assert provider.production_custody is False
    assert provider.custody == "non-production-env"
    assert "NON-PRODUCTION" in provider.notice()
    assert "NON-PRODUCTION" in repr(provider)
    rendered = repr(provider) + provider.notice() + json.dumps(provider.info().purposes)
    assert _HMAC_KEY.decode() not in rendered
    assert _b64(_HMAC_KEY) not in rendered
    sealed = provider.seal(b"SYNTHETIC TEST DATA mailbox", subject_id="prn_synthetic")
    assert provider.unseal(sealed, subject_id="prn_synthetic") == b"SYNTHETIC TEST DATA mailbox"
    with pytest.raises(KeyCustodyError):
        provider.unseal(sealed, subject_id="prn_other")


def test_env_provider_refused_on_production_without_the_allow_flag():
    blocked = settings_from_env(
        {"GAB_ENV": "production", "GAB_KEY_PROVIDER": "env", "GAB_HMAC_KEYS": _env_json()}
    )
    assert blocked.key_provider is None
    assert blocked.config_error is not None
    assert "GAB_ALLOW_ENV_KEYS" in blocked.config_error
    assert _HMAC_KEY.decode() not in blocked.config_error

    allowed = settings_from_env(
        {
            "GAB_ENV": "production",
            "GAB_KEY_PROVIDER": "env",
            "GAB_ALLOW_ENV_KEYS": "1",
            "GAB_HMAC_KEYS": _env_json(),
        }
    )
    assert allowed.config_error is None
    assert allowed.key_provider is not None
    assert allowed.key_provider.production_custody is False
    assert ENV_PROVIDER_NOTICE.split(".", 1)[0] in allowed.key_provider.notice()


def test_unset_provider_keeps_settings_unchanged():
    settings = settings_from_env({})
    assert settings.key_provider is None
    assert settings.config_error is None


def test_aws_provider_wraps_data_keys_and_does_not_hold_the_master_key():
    fake = FakeKms()
    blob = fake.encrypt(
        key_id=_MASTER,
        plaintext=_HMAC_KEY,
        encryption_context=hmac_encryption_context("identifier", "email-new"),
    )
    old_blob = fake.encrypt(
        key_id=_MASTER,
        plaintext=_HMAC_KEY_OLD,
        encryption_context=hmac_encryption_context("identifier", "email-old"),
    )
    provider = AwsKmsEnvelopeProvider(
        key_id=_MASTER,
        region="us-east-1",
        client=fake,
        wrapped_hmac={
            "identifier": [
                {"kid": "email-old", "wrapped": _b64(old_blob)},
                {"kid": "email-new", "wrapped": _b64(blob), "active": True},
            ]
        },
    )
    assert provider.production_custody is True
    assert provider.custody == "aws-kms-envelope"
    assert _KMS_KEK not in vars(provider).values()
    token = provider.hmac(_EMAIL, purpose="identifier")
    assert token.encode() == "v1:email-new:" + _independent_hmac(_HMAC_KEY, "identifier", _EMAIL)
    assert provider.verify(
        "v1:email-old:" + _independent_hmac(_HMAC_KEY_OLD, "identifier", _EMAIL),
        _EMAIL,
        purpose="identifier",
    )
    sealed = provider.seal(b"SYNTHETIC TEST DATA", subject_id="prn_synthetic")
    assert b"SYNTHETIC TEST DATA" not in sealed.encode()
    assert provider.unseal(sealed, subject_id="prn_synthetic") == b"SYNTHETIC TEST DATA"
    with pytest.raises(KeyCustodyError):
        provider.unseal(sealed, subject_id="prn_other")
    plain, wrapped = provider.issue_dek("prn_synthetic")
    assert plain != _KMS_KEK
    assert provider.unwrap_dek("prn_synthetic", wrapped) == plain
    with pytest.raises(KeyCustodyError):
        provider.unwrap_dek("prn_other", wrapped)
    assert "generate_data_key" in fake.calls
    assert dek_encryption_context("prn_synthetic")["gab"] == "subject-dek"


def test_aws_settings_do_not_import_a_network_client():
    settings = settings_from_env(
        {
            "GAB_KEY_PROVIDER": "aws-kms",
            "GAB_KMS_KEY_ID": _MASTER,
            "GAB_KMS_REGION": "us-east-1",
        }
    )
    assert settings.config_error is None
    assert settings.key_provider.region == "us-east-1"
    assert settings.key_provider._client is None
    missing = settings_from_env({"GAB_KEY_PROVIDER": "aws-kms", "GAB_KMS_REGION": "us-east-1"})
    assert missing.key_provider is None
    assert "GAB_KMS_KEY_ID" in (missing.config_error or "")
    unknown = settings_from_env({"GAB_KEY_PROVIDER": "vault"})
    assert unknown.config_error is not None
    assert "GAB_KEY_PROVIDER" in unknown.config_error


def test_provider_from_env_single_active_kid_skips_other_purposes():
    provider = provider_from_env(
        {
            "GAB_KEY_PROVIDER": "env",
            "GAB_ALLOW_ENV_KEYS": "1",
            "GAB_HMAC_ACTIVE_KID": "email-new",
            "GAB_HMAC_KEYS": _env_json(),
        },
        deployment_env="production",
    )
    assert provider.active_kid("identifier") == "email-new"
    assert provider.active_kid("kek") == "local-kek"


def test_malformed_token_and_short_secret_are_rejected():
    provider = EnvKeyProvider(_ring())
    assert provider.verify("sha256:" + "ab" * 32, _EMAIL, purpose="identifier") is False
    assert parse_hmac_token("v1:email-new:abcd") is None
    with pytest.raises(KeyCustodyError):
        EnvKeyProvider({"short": {"secret": b"tiny", "purposes": ["identifier"], "active": True}})
    with pytest.raises(KeyCustodyError):
        provider.hmac("", purpose="identifier")
