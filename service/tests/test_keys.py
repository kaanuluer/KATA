# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Key custody. SYNTHETIC TEST DATA only. No production keys."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kata_service.keys import (
    ENV_PROVIDER_NOTICE,
    AwsKmsEnvelopeProvider,
    EnvKeyProvider,
    KeyCustodyError,
    DatabaseDekStore,
    KeyUsageEvent,
    dek_encryption_context,
    hmac_encryption_context,
    opaque_subject,
    open_detached,
    parse_hmac_token,
    provider_from_env,
    seal_detached,
    shred_subject,
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


def test_env_provider_is_refused_in_production_with_no_flag_override():
    blocked = settings_from_env(
        {
            "GAB_ENV": "production",
            "GAB_KEY_PROVIDER": "env",
            "GAB_SYNTHETIC_DATA": "1",
            "GAB_ALLOW_ENV_KEYS": "1",
            "GAB_HMAC_KEYS": _env_json(),
        }
    )
    assert blocked.key_provider is None
    assert blocked.config_error is not None
    assert "refused" in blocked.config_error
    assert "GAB_SYNTHETIC_DATA" in blocked.config_error
    assert _HMAC_KEY.decode() not in blocked.config_error

    allowed = settings_from_env(
        {"GAB_ENV": "sandbox", "GAB_KEY_PROVIDER": "env", "GAB_HMAC_KEYS": _env_json()}
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
            "GAB_HMAC_ACTIVE_KID": "email-new",
            "GAB_HMAC_KEYS": _env_json(),
        },
        deployment_env="sandbox",
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


def test_subject_ref_is_opaque_and_usage_omits_the_value():
    provider = EnvKeyProvider(_ring())
    context = dek_encryption_context("prn_synthetic")
    assert "subject_id" not in context
    assert context["subject_ref"] == opaque_subject("prn_synthetic")
    assert "prn_synthetic" not in json.dumps(context)
    provider.hmac(_EMAIL, purpose="identifier")
    dumped = json.dumps([event.__dict__ for event in provider.usage()])
    assert _EMAIL not in dumped
    assert "prn_" not in dumped
    assert provider.usage()[0].latency_ms >= 0
    assert isinstance(provider.usage()[0], KeyUsageEvent)
    sealed = provider.seal(b"SYNTHETIC TEST DATA", subject_id="prn_synthetic")
    assert "prn_synthetic" not in sealed


def test_dek_cache_records_a_hit_and_skips_the_second_unwrap(monkeypatch):
    provider = EnvKeyProvider(_ring())
    _plain, wrapped = provider.issue_dek("prn_synthetic")
    provider.forget_dek("prn_synthetic")
    calls = {"n": 0}
    import kata_service.keys as keys

    real = keys._open_aes

    def counted(key, nonce, ciphertext, aad):
        calls["n"] += 1
        return real(key, nonce, ciphertext, aad)

    monkeypatch.setattr(keys, "_open_aes", counted)
    assert provider.unwrap_dek("prn_synthetic", wrapped) == _plain
    assert provider.unwrap_dek("prn_synthetic", wrapped) == _plain
    assert calls["n"] == 1
    unwraps = [event for event in provider.usage() if event.operation == "unwrap_dek"]
    assert [event.cache for event in unwraps] == ["miss", "hit"]


def test_master_key_selects_the_env_provider_outside_production():
    selected = settings_from_env({"GAB_ENV": "sandbox", "GAB_MASTER_KEY": _b64(_KEK)})
    assert selected.config_error is None
    assert selected.key_provider.provider == "env"
    assert selected.key_provider.provider != "aws-kms"
    assert selected.key_provider.active_kid("kek") == "master"
    plain, wrapped = selected.key_provider.issue_dek("prn_synthetic")
    assert selected.key_provider.unwrap_dek("prn_synthetic", wrapped) == plain
    sealed = selected.key_provider.seal(b"SYNTHETIC TEST DATA", subject_id="prn_synthetic")
    assert selected.key_provider.unseal(sealed, subject_id="prn_synthetic") == b"SYNTHETIC TEST DATA"
    assert selected.key_provider.unseal(sealed, subject_id="prn_synthetic") == b"SYNTHETIC TEST DATA"
    unwraps = [event for event in selected.key_provider.usage() if event.operation == "unwrap_dek"]
    seals = [event for event in selected.key_provider.usage() if event.operation == "unseal"]
    assert unwraps and unwraps[0].cache == "hit"
    assert seals and seals[0].latency_ms >= 0
    refused = settings_from_env(
        {"GAB_MASTER_KEY": _b64(_KEK), "GAB_SYNTHETIC_DATA": "1", "GAB_ALLOW_ENV_KEYS": "1"}
    )
    assert "refused" in (refused.config_error or "")
    assert settings_from_env({}).key_provider is None


def test_detached_ciphertext_shreds_when_the_stored_key_is_deleted():
    provider = EnvKeyProvider(_ring())
    from kata_service.keys import InProcessDekStore

    store = InProcessDekStore()
    encoded, wrapped = seal_detached(provider, b"SYNTHETIC TEST DATA", subject_id="prn_synthetic")
    assert "embedded" not in encoded
    assert _b64(wrapped) not in encoded
    assert "prn_synthetic" not in encoded
    store.put("prn_synthetic", wrapped)
    assert open_detached(provider, encoded, store.get("prn_synthetic"), subject_id="prn_synthetic") == b"SYNTHETIC TEST DATA"
    assert shred_subject(provider, store, "prn_synthetic") is True
    assert store.get("prn_synthetic") is None
    assert open_detached(provider, encoded, wrapped, subject_id="prn_synthetic") == b"SYNTHETIC TEST DATA"


def test_database_dek_row_is_separate_from_ciphertext():
    url = os.environ.get("GAB_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("GAB_TEST_DATABASE_URL is required in CI")
        pytest.skip("GAB_TEST_DATABASE_URL is not set")
    if urlparse(url).hostname not in {"localhost", "127.0.0.1"}:
        pytest.fail("GAB_TEST_DATABASE_URL must point at localhost")
    import psycopg

    from kata_service.bureau_pg import PostgresRepo

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("DROP SCHEMA IF EXISTS gab_sandbox CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("GRANT ALL ON SCHEMA public TO public")
    PostgresRepo(url, url).migration_versions()
    provider = EnvKeyProvider(_ring(), master_key=_KEK)
    encoded, wrapped = seal_detached(provider, b"SYNTHETIC TEST DATA", subject_id="prn_synthetic")
    store = DatabaseDekStore(lambda: psycopg.connect(url))
    store.put("prn_synthetic", wrapped)
    with psycopg.connect(url) as conn:
        row = conn.execute("SELECT subject_ref, wrapped_dek FROM gab_subject_deks").fetchone()
    assert row[0] == opaque_subject("prn_synthetic")
    assert "prn_synthetic" not in row[0]
    assert "prn_synthetic" not in row[1]
    assert row[1] not in encoded
    assert open_detached(provider, encoded, store.get("prn_synthetic"), subject_id="prn_synthetic") == b"SYNTHETIC TEST DATA"
    assert shred_subject(provider, store, "prn_synthetic") is True
    assert store.get("prn_synthetic") is None


def test_boto3_client_stays_lazy_and_accepts_a_stubber():
    import inspect

    import kata_service.keys as keys

    source = inspect.getsource(keys)
    assert "import boto3" not in source.split("def _boto")[0]
    fresh = keys.Boto3KmsClient("us-east-1")
    assert fresh._client is None
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    raw = boto3.client("kms", region_name="us-east-1")
    fresh._client = raw
    context = dek_encryption_context("prn_synthetic")
    plaintext = b"SYNTHETIC TEST DATA kms-dek!!!!!"
    blob = b"synthetic-wrapped-blob"
    stubber = Stubber(raw)
    stubber.add_response(
        "generate_data_key",
        {"Plaintext": plaintext, "CiphertextBlob": blob},
        {"KeyId": _MASTER, "KeySpec": "AES_256", "EncryptionContext": context},
    )
    stubber.add_response(
        "decrypt",
        {"Plaintext": plaintext, "KeyId": _MASTER},
        {"CiphertextBlob": blob, "EncryptionContext": context, "KeyId": _MASTER},
    )
    stubber.add_response(
        "encrypt",
        {"CiphertextBlob": blob},
        {"KeyId": _MASTER, "Plaintext": plaintext, "EncryptionContext": context},
    )
    with stubber:
        dek, wrapped = fresh.generate_data_key(key_id=_MASTER, encryption_context=context)
        opened = fresh.decrypt(key_id=_MASTER, ciphertext=wrapped, encryption_context=context)
        encrypted = fresh.encrypt(key_id=_MASTER, plaintext=plaintext, encryption_context=context)
    assert dek == plaintext == opened
    assert wrapped == blob == encrypted
    assert "prn_synthetic" not in json.dumps(context)
    stubber.assert_no_pending_responses()


def test_boto3_client_uses_web_identity_and_refuses_static_keys(monkeypatch):
    pytest.importorskip("boto3")
    from kata_service.keys import Boto3KmsClient

    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::000000000000:role/gab-example")
    monkeypatch.setenv("VERCEL_OIDC_TOKEN", "SYNTHETIC TEST DATA oidc")
    client = Boto3KmsClient("us-east-1")
    raw = client._boto()
    assert raw.meta.service_model.service_name == "kms"
    written = Path(os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"]).read_text(encoding="utf-8")
    assert written == "SYNTHETIC TEST DATA oidc"
    rendered = " ".join(str(value) for value in client.__dict__.values() if isinstance(value, str))
    assert "SYNTHETIC TEST DATA oidc" not in rendered
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_SYNTHETIC")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret")
    refused = Boto3KmsClient("us-east-1")
    with pytest.raises(KeyCustodyError, match="AWS_ACCESS_KEY_ID"):
        refused._boto()


def test_custody_doc_states_the_accepted_risk():
    text = Path(__file__).resolve().parents[2].joinpath("docs", "key-custody.md").read_text(encoding="utf-8")
    assert "if the Vercel account is compromised the master key is lost too" in text
    assert "password manager" in text
    assert "Neon backup" in text
    assert "not the default" in text
    assert "import boto3 at startup" in text
    assert "AssumeRoleWithWebIdentity" in text
    assert "kms:GenerateDataKey" in text
    assert "kms:Decrypt" in text
    assert "kms:Encrypt" in text
    assert "AWS_ACCESS_KEY_ID" in text
    assert "deletion window" in text
    assert "do not override" in text
    assert "kata-service-omega.vercel.app" not in text
