# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Onboarding writes keys to a file and does not print them."""

from __future__ import annotations

import logging
import stat

import pytest
from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.bureau import Auth, BureauError, BureauService, MemoryRepo
from kata_service.onboard import main, onboard
from kata_service.settings import Settings
from kata_service.store import MemoryStore


def _service() -> BureauService:
    return BureauService(MemoryRepo(), public_base_url="https://globalagentbureau.com")


def _args(out) -> list[str]:
    return [
        "--name",
        "Northwind",
        "--type",
        "merchant",
        "--email",
        "Ops@Northwind.example",
        "--email",
        "ops@northwind.example",
        "--email",
        "finance@northwind.example",
        "--out",
        str(out),
    ]


def test_onboard_writes_keys_once_and_keeps_them_out_of_logs(tmp_path, capsys, caplog):
    service = _service()
    caplog.set_level(logging.INFO)

    def connect():
        return service, "https://globalagentbureau.com"

    main(_args(tmp_path), connect=connect)
    printed = capsys.readouterr().out
    welcome = (tmp_path / "welcome.txt").read_text(encoding="utf-8")
    secret = (tmp_path / "keys.txt").read_text(encoding="utf-8")
    live = _field(secret, "live_token")
    test = _field(secret, "test_token")
    org_id = _field(secret, "org_id")

    assert live.startswith("gab_")
    assert not live.startswith("gab_test_")
    assert test.startswith("gab_test_")
    assert live not in printed
    assert test not in printed
    assert live not in welcome
    assert test not in welcome
    assert live not in caplog.text
    assert test not in caplog.text
    assert secret not in printed
    assert secret not in caplog.text
    assert welcome == printed
    assert "agent bureau" in welcome.lower()
    assert "PolyForm Noncommercial" in welcome
    assert "finance@northwind.example" in welcome
    assert "Ops@Northwind.example" not in welcome
    for banned in ("open source", "open-source", "credit bureau", "call"):
        assert banned not in welcome.lower()
    assert stat.S_IMODE((tmp_path / "keys.txt").stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700

    assert service.authenticate(live, admin_token=None).org_id == org_id
    assert service.authenticate(test, admin_token=None).org_id == org_id
    assert service.repo.org_login_by_email("ops@northwind.example")["org_id"] == org_id
    assert service.repo.org_login_by_email("finance@northwind.example")["org_id"] == org_id
    listed = service.list_keys(Auth(admin=True, kind="admin"), org_id)
    assert len(listed) == 2
    assert all("token" not in item and "secret_hash" not in item for item in listed)
    prefixes = {item["prefix"] for item in listed}
    assert _field(secret, "live_token").split("_")[1] in prefixes
    assert any(item.startswith("gab_test_") for item in prefixes)

    rotated = service.rotate_key(Auth(admin=True, kind="admin"), _field(secret, "test_key_id"))
    assert rotated["token"].startswith("gab_test_")
    assert rotated["token"] != test
    assert rotated["token"] not in welcome


def test_onboard_refuses_a_taken_email_and_an_existing_key_file(tmp_path):
    service = _service()
    service.repo.upsert_org_login("ops@northwind.example", "org_existing", "2026-10-16T00:00:00Z")
    with pytest.raises(BureauError, match="already registered"):
        onboard(
            service,
            name="Northwind",
            org_type="merchant",
            emails=["ops@northwind.example"],
            out_dir=tmp_path / "first",
            public_base_url="https://globalagentbureau.com",
        )
    assert service.repo.orgs == {}
    assert not (tmp_path / "first").exists()

    clean = _service()
    onboard(
        clean,
        name="Northwind",
        org_type="merchant",
        emails=["ops@northwind.example"],
        out_dir=tmp_path / "pack",
        public_base_url="https://globalagentbureau.com",
    )
    with pytest.raises(BureauError, match="key file already exists"):
        onboard(
            clean,
            name="Northwind",
            org_type="merchant",
            emails=["other@northwind.example"],
            out_dir=tmp_path / "pack",
            public_base_url="https://globalagentbureau.com",
        )
    assert len(clean.repo.orgs) == 1


def test_missing_database_url_does_not_invent_keys(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    with pytest.raises(SystemExit, match="DATABASE_URL is not set"):
        main(_args(tmp_path))
    assert capsys.readouterr().out == ""
    assert not (tmp_path / "keys.txt").exists()


def test_http_key_issue_stays_on_the_live_prefix():
    settings = Settings(None, None, None, None, None, (), "https://fx.test", admin_token="admin-test-token")
    client = TestClient(create_app(settings, MemoryStore()))
    org = client.post(
        "/v1/orgs",
        headers={"Authorization": "Bearer admin-test-token"},
        json={"name": "Northwind", "org_type": "merchant"},
    )
    assert org.status_code == 200
    issued = client.post(f"/v1/orgs/{org.json()['org_id']}/keys", headers={"Authorization": "Bearer admin-test-token"}, json={"name": "live"})
    assert issued.status_code == 200
    token = issued.json()["token"]
    assert token.startswith("gab_")
    assert not token.startswith("gab_test_")
    listed = client.get(f"/v1/orgs/{org.json()['org_id']}/keys", headers={"Authorization": "Bearer admin-test-token"})
    assert token not in listed.text


def _field(body: str, name: str) -> str:
    for line in body.splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    raise AssertionError(f"missing {name}")
