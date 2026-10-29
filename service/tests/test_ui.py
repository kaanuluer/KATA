# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""The web page and the sample intent check."""

from __future__ import annotations

from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.pages import schema_bytes
from kata_service.settings import Settings
from kata_service.store import MemoryStore


def _client() -> TestClient:
    settings = Settings(None, None, None, None, None, (), "https://fx.test")
    return TestClient(create_app(settings, MemoryStore()))


def test_home_page_explains_kata_in_english():
    page = _client().get("/")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    body = page.text
    assert "Know And Trust Agents" in body
    assert "Who is the agent?" in body
    assert "Who authorized it?" in body
    assert "What was it authorized to do?" in body
    assert "Does this behavior match?" in body
    assert 'id="demo-form"' in body
    assert "Revocation list" in body
    assert "Published keys" in body
    assert "Transparency log" in body
    assert "PolyForm Noncommercial" in body
    assert "open source" not in body.lower()
    assert '/assets/gab-logo.svg' in body
    assert "Global Agent Bureau" in body
    assert 'href="/dashboard"' in body
    assert 'href="/portal"' in body
    assert 'id="explainer"' in body
    assert 'poster="/assets/gab-explainer-poster.jpg"' in body
    assert "/assets/gab-explainer-1080.mp4" in body
    assert "/assets/gab-explainer-720.mp4" in body
    assert "/assets/gab-explainer.vtt" in body
    assert "autoplay" not in body.lower()
    assert "73.5 seconds" in body
    assert 'href="/simulation"' in body
    assert "SYNTHETIC TEST DATA – not real customers" in body
    assert "$0.71M" in body
    assert "73%" in body
    assert "$0.68M" in body
    assert "78%" in body
    assert "earlier test" not in body.lower()
    assert "v2" not in body.lower()
    assert "v3" not in body.lower()
    assert "book a call" not in body.lower()
    assert '/assets/kata-logo.svg' in body
    assert '/assets/kata-icon.svg' in body
    assert "credit bureau" not in body.lower()
    assert "an agent bureau and a technology company" in body.lower()
    assert "Explore the site" in body
    assert "5 tools" in body
    assert "streamable HTTP" in body
    assert "gab_test_" in body
    assert "Retry-After" in body
    assert "/health" in body
    assert 'href="/status"' in body
    assert "assumed mapping" in body
    assert "does not host checkout" in body
    for banned in ("316 checks", "latest test round", "malformed input", "security headers", "2026-10-16"):
        assert banned not in body.lower()
    for banned in ("compatible", "compliant", "certified"):
        assert banned not in body.lower()


def test_home_links_github_history_and_docs():
    body = _client().get("/").text
    assert body.count('href="https://github.com/kaanuluer/KATA"') >= 2
    assert 'href="/history"' in body
    assert 'href="/docs"' in body
    assert ">History<" in body
    assert ">Docs<" in body
    assert ">GitHub<" in body
    assert "2026-10-04" in body
    assert "a581f1c" in body
    assert "PolyForm Noncommercial" in body
    assert "open source" not in body.lower()
    assert "open-source" not in body.lower()


def test_history_page_uses_repository_facts():
    page = _client().get("/history")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    body = page.text
    assert "2026-10-04" in body
    assert "a581f1c" in body
    assert "Initial commit" in body
    assert "2026-10-08" in body
    assert "2026-10-09T02:05:23Z" in body
    assert "2026-10-12T22:46:54Z" in body
    assert "2026-10-13T04:16:43Z" in body
    assert "2026-10-15" in body
    assert "SYNTHETIC TEST DATA – not real customers" in body
    assert "$0.71M" in body
    assert 'href="https://github.com/kaanuluer/KATA"' in body
    assert "PolyForm Noncommercial" in body
    assert "PolyForm Noncommercial License 1.0.0" in body
    assert "Apache-2.0" in body
    assert "open source" not in body.lower()
    assert "open-source" not in body.lower()
    for banned in ("316 checks", "latest test round", "malformed input", "security headers", "2026-10-16"):
        assert banned not in body.lower()


def test_docs_index_lists_the_requested_pages():
    page = _client().get("/docs")
    assert page.status_code == 200
    body = page.text
    for href in (
        "/docs/design",
        "/docs/design#lifecycle",
        "/docs/authorization",
        "/docs/intent",
        "/docs/threat-model",
        "/docs/schemas",
        "/docs/api",
    ):
        assert f'href="{href}"' in body
    assert "PolyForm Noncommercial" in body
    assert "open source" not in body.lower()
    assert "open-source" not in body.lower()
    for banned in ("316 checks", "latest test round", "malformed input", "security headers"):
        assert banned not in body.lower()


def test_rendered_docs_come_from_the_repository():
    client = _client()
    design = client.get("/docs/design")
    assert design.status_code == 200
    assert "Intent Agreement" in design.text
    assert "Lifecycle" in design.text
    assert 'id="lifecycle"' in design.text
    assert 'href="/docs/authorization"' in design.text
    assert 'href="/docs/schemas/decision.json"' in design.text
    assert "open source" not in design.text.lower()
    assert "open-source" not in design.text.lower()
    assert "SYNTHETIC TEST DATA – not real customers" in design.text
    assert "$0.71M" in design.text
    assert "73%" in design.text
    assert 'href="/simulation"' in design.text
    assert "Still no calibrated score" not in design.text
    assert "not production ready" not in design.text.lower()

    authorization = client.get("/docs/authorization")
    assert authorization.status_code == 200
    assert "Delegation" in authorization.text
    assert "github.com/kaanuluer/KATA/blob/main/KATA.md" in authorization.text

    intent = client.get("/docs/intent")
    assert intent.status_code == 200
    assert "Intent Model" in intent.text

    threat = client.get("/docs/threat-model")
    assert threat.status_code == 200
    assert "Threat Model" in threat.text
    assert "github.com/kaanuluer/KATA/blob/main/KATA.md" in threat.text
    assert "open-source" not in threat.text.lower()


def test_schema_index_and_raw_schema():
    client = _client()
    index = client.get("/docs/schemas")
    assert index.status_code == 200
    assert "agreement.json" in index.text
    raw = client.get("/docs/schemas/agreement.json")
    assert raw.status_code == 200
    assert "application/json" in raw.headers["content-type"]
    assert raw.json()["title"] == "KATA Intent Agreement"
    missing = client.get("/docs/schemas/not-real.json")
    assert missing.status_code == 404
    assert schema_bytes("../agreement.json") is None
    assert schema_bytes("..%2fagreement.json") is None


def test_api_reference_and_openapi():
    client = _client()
    api = client.get("/docs/api")
    assert api.status_code == 200
    assert "/v1/revocations" in api.text
    assert "/v1/revocations/push" in api.text
    assert "/v1/log/entries" in api.text
    assert "/.well-known/kata-keys.json" in api.text
    assert "/v1/fx" in api.text
    assert "/demo/check" in api.text
    assert 'href="/docs/openapi"' in api.text
    assert "PolyForm Noncommercial" in api.text
    assert "open source" not in api.text.lower()
    spec = client.get("/docs/openapi")
    assert spec.status_code == 200
    assert "text/html" in spec.headers["content-type"]


def test_static_assets_are_served():
    client = _client()
    css = client.get("/assets/app.css")
    script = client.get("/assets/app.js")
    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]
    assert "--teal" in css.text
    assert script.status_code == 200
    assert "/demo/check" in script.text
    icon = client.get("/assets/kata-icon.svg")
    logo = client.get("/assets/kata-logo.svg")
    assert icon.status_code == 200
    assert "image/svg+xml" in icon.headers["content-type"]
    assert 'fill="#0F6570"' in icon.text
    assert 'stroke="#4FE0C2"' in icon.text
    assert logo.status_code == 200
    assert "KATA" in logo.text
    gab = client.get("/assets/gab-logo.svg")
    assert gab.status_code == 200
    assert "Global Agent Bureau" in gab.text
    wordmark = client.get("/assets/gab-logo.png")
    assert wordmark.status_code == 200
    assert wordmark.headers["content-type"].startswith("image/png")
    assert wordmark.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert int.from_bytes(wordmark.content[16:20], "big") == 1484
    assert int.from_bytes(wordmark.content[20:24], "big") == 792
    assert client.get("/assets/secret.txt").status_code == 404
    poster = client.get("/assets/gab-explainer-poster.jpg")
    assert poster.status_code == 200
    assert poster.headers["content-type"].startswith("image/jpeg")
    wide = client.get("/assets/gab-explainer-1080.mp4")
    narrow = client.get("/assets/gab-explainer-720.mp4")
    assert wide.status_code == 200
    assert narrow.status_code == 200
    assert wide.headers["content-type"].startswith("video/mp4")
    assert narrow.headers["content-type"].startswith("video/mp4")
    captions = client.get("/assets/gab-explainer.vtt")
    assert captions.status_code == 200
    assert captions.headers["content-type"].startswith("text/vtt")
    assert captions.text.startswith("WEBVTT")
    assert "credit bureau" not in captions.text.lower()
    assert "open source" not in captions.text.lower()


def test_simulation_page_labels_every_figure_as_synthetic():
    client = _client()
    page = client.get("/simulation")
    assert page.status_code == 200
    body = page.text
    assert "SYNTHETIC TEST DATA – not real customers" in body
    assert body.count("SYNTHETIC TEST DATA – not real customers") >= 8
    for name in (
        "chart-final-1-fraud-dollars.png",
        "chart-final-2-ring-scores.png",
        "chart-final-3-fake-reports.png",
        "chart-final-4-loss-by-attacker.png",
        "chart-final-5-friction-sybils.png",
    ):
        assert f"/assets/{name}" in body
        asset = client.get(f"/assets/{name}")
        assert asset.status_code == 200
        assert asset.headers["content-type"].startswith("image/png")
    assert "$0.71M" in body
    assert "73%" in body
    assert "370 of 371" in body
    assert "agent bureau" in body.lower()
    assert "https://globalagentbureau.com" in body
    assert "PolyForm Noncommercial" in body
    assert "v1" not in body.lower()
    assert "v2" not in body.lower()
    assert "proposed defense" not in body.lower()
    assert "open source" not in body.lower()
    assert "open-source" not in body.lower()
    assert "credit bureau" not in body.lower()
    assert "book a call" not in body.lower()
    for table in body.split("<table")[1:]:
        header, _, rest = table.partition("</tr>")
        width = header.count("<th>")
        for row in rest.split("<tr>")[1:]:
            cells = row.split("</tr>", 1)[0]
            assert cells.count("<th>") + cells.count("<td>") == width
    home = client.get("/")
    assert 'href="/simulation"' in home.text


def test_trust_score_abuse_note_is_public():
    page = _client().get("/docs/trust-score-abuse")
    assert page.status_code == 200
    body = page.text
    assert "Trust-score abuse" in body
    assert "Individuals are not scored" in body
    assert "agent bureau" in body.lower()
    assert "RING_DISCOUNTED" in body
    assert "DISPUTE_HOLD" in body
    assert "open source" not in body.lower()
    assert "open-source" not in body.lower()
    assert "credit bureau" not in body.lower()


def test_pages_share_the_chapters_shell():
    client = _client()
    css = client.get("/assets/app.css").text
    assert "--teal" in css
    assert "#13203B" in css or "#13203b" in css
    assert "#4FE0C2" in css or "#4fe0c2" in css
    for path in ("/", "/dashboard", "/portal", "/docs", "/history", "/simulation"):
        body = client.get(path).text
        assert 'data-theme="dark"' in body
        assert 'id="theme-toggle"' in body
        assert "Light mode" in body
        assert 'alt="GAB_"' in body
        assert "Powered by KATA · Know And Trust Agents" not in body
        assert 'class="brand-note"' not in body
        assert "book a call" not in body.lower()
        assert "credit bureau" not in body.lower()
        assert "open source" not in body.lower()
        assert "open-source" not in body.lower()
    assert client.get("/design").status_code == 404
    assert client.get("/design/b").status_code == 404
    assert client.get("/design/c").status_code == 404


def test_dashboard_and_portal_pages():
    client = _client()
    dashboard = client.get("/dashboard")
    portal = client.get("/portal")
    assert dashboard.status_code == 200
    assert 'id="login-form"' in dashboard.text
    assert "Run inquiry" in dashboard.text
    assert "/assets/dashboard.js" in dashboard.text
    assert portal.status_code == 200
    assert 'id="portal-login"' in portal.text
    assert "Dispute an incident" in portal.text
    assert "Your disputes" in portal.text
    assert 'id="portal-disputes"' in portal.text
    assert "/assets/portal.js" in portal.text
    assert "does not store a trust score" in portal.text
    assert "Add to home screen" in portal.text
    assert 'href="/manifest.webmanifest"' in portal.text
    assert "portal-score" not in portal.text
    assert "/ 1000" not in portal.text
    requirements = client.get("/docs/gab-requirements")
    assert requirements.status_code == 200
    assert "Trust score" in requirements.text
    assert "DATABASE_URL" in requirements.text
    assert "Supabase is not used" in requirements.text
    for page in (dashboard.text, portal.text, requirements.text):
        assert "open source" not in page.lower()
        assert "open-source" not in page.lower()
        assert "credit bureau" not in page.lower()


def test_demo_allows_denies_and_steps_up():
    client = _client()
    allowed = client.post("/demo/check", json=_payment(1300))
    assert allowed.status_code == 200
    assert allowed.json()["verdict"] == "ALLOW"
    assert "K. Uluer" in allowed.json()["confirmation_text"]
    assert allowed.json()["demo"] is True

    denied = client.post("/demo/check", json=_payment(4200, item="MacBook Pro 14-inch"))
    assert denied.status_code == 200
    assert denied.json()["verdict"] == "DENY"
    assert "AMOUNT_ABOVE_INTENT_CEILING" in denied.json()["reasons"]

    stepped = client.post("/demo/check", json=_payment(1300, include_expiry=False))
    assert stepped.status_code == 200
    assert stepped.json()["verdict"] == "STEP_UP"
    assert "OVER_BROAD_INTENT" in stepped.json()["reasons"]

    rejected = client.post("/demo/check", json={"intent": {"currency": "cadollars"}, "payment": {"amount": 10}})
    assert rejected.status_code == 400


def test_health_and_status_when_the_process_uses_memory():
    client = _client()
    for path in ("/health", "/v1/health"):
        page = client.get(path)
        assert page.status_code == 200
        assert page.json() == {"status": "ok", "database": "memory"}
    status = client.get("/status")
    assert status.status_code == 200
    assert "Operating" in status.text
    assert "memory" in status.text
    assert 'href="/status"' in status.text
    assert 'aria-current="page"' in status.text
    assert "agent bureau" in status.text.lower()
    assert "PolyForm Noncommercial" in status.text
    for banned in ("open source", "open-source", "credit bureau", "call"):
        assert banned not in status.text.lower()
    note = client.get("/docs/uptime")
    assert note.status_code == 200
    assert "/health" in note.text
    assert "/v1/health" in note.text
    assert "once a minute" in note.text.lower()
    assert "503" in note.text
    assert "agent bureau" in note.text.lower()
    for banned in ("open source", "open-source", "credit bureau", "call"):
        assert banned not in note.text.lower()
    api = client.get("/docs/api")
    assert "/health" in api.text
    assert "/v1/health" in api.text


def test_health_stays_on_memory_in_demo_mode():
    settings = Settings(
        "postgres://secret-host.example/db",
        "postgres://secret-host.example/db",
        None,
        None,
        None,
        (),
        "https://fx.test",
        demo=True,
    )
    client = TestClient(create_app(settings, MemoryStore()))
    page = client.get("/health")
    assert page.status_code == 200
    assert page.json() == {"status": "ok", "database": "memory"}
    assert "secret-host" not in page.text


def test_health_pings_the_database_and_hides_failures(monkeypatch):
    seen = {}

    class Connection:
        def execute(self, sql):
            seen["sql"] = sql
            return self

        def fetchone(self):
            return (1,)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    import psycopg

    def connect(url, connect_timeout=None):
        seen["url"] = url
        seen["timeout"] = connect_timeout
        return Connection()

    monkeypatch.setattr(psycopg, "connect", connect)
    settings = Settings(
        "postgres://secret-host.example/db",
        "postgres://secret-host.example/db",
        None,
        None,
        None,
        (),
        "https://fx.test",
    )
    client = TestClient(create_app(settings, MemoryStore()))
    page = client.get("/v1/health")
    assert page.status_code == 200
    assert page.json() == {"status": "ok", "database": "ok"}
    assert seen["sql"] == "SELECT 1"
    assert seen["timeout"] == 3
    assert "secret-host" not in page.text
    status = client.get("/status")
    assert "Operating" in status.text
    assert ">ok<" in status.text
    assert "secret-host" not in status.text

    def fail(url, connect_timeout=None):
        raise RuntimeError(f"could not reach {url} password=s3cret")

    monkeypatch.setattr(psycopg, "connect", fail)
    failed = client.get("/health")
    assert failed.status_code == 503
    assert failed.json() == {"status": "unavailable", "database": "unavailable"}
    assert "secret" not in failed.text
    assert "password" not in failed.text
    assert "s3cret" not in failed.text
    down = client.get("/status")
    assert down.status_code == 200
    assert "Unavailable" in down.text
    assert "secret" not in down.text


def _payment(amount: int, item: str = "Laptop", include_expiry: bool = True) -> dict:
    return {
        "intent": {
            "maximum_amount": 1500,
            "currency": "CAD",
            "purpose": "purchase",
            "category": "electronics",
            "natural_language": "Find and buy a laptop for me, maximum CAD 1,500.",
            "include_expiry": include_expiry,
            "time_limit": "2026-12-31",
        },
        "payment": {
            "amount": amount,
            "currency": "CAD",
            "merchant": "techstore.example",
            "item": item,
        },
    }
