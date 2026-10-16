# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""One command to open an organization for a first customer.

The live and test keys are written to a local file and are not printed.
"""

from __future__ import annotations

import argparse
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from kata_service.bureau import Auth, BureauError, BureauService, _email

log = logging.getLogger("kata_service.onboard")

_ADMIN = Auth(admin=True, kind="admin")


@dataclass(frozen=True)
class OnboardResult:
    org_id: str
    welcome: str
    secret_path: Path


def onboard(
    service: BureauService,
    *,
    name: str,
    org_type: str,
    emails: list[str],
    out_dir: Path,
    public_base_url: str,
) -> OnboardResult:
    """Create the org, both keys, and the email bindings. Secrets stay in the file."""

    addresses = _validated_emails(emails)
    for address in addresses:
        current = service.repo.org_login_by_email(address)
        if current is not None:
            raise BureauError(409, "email is already registered to another organization")
    secret_path = _prepare_out(out_dir)
    org = service.create_org(_ADMIN, name, org_type)
    org_id = org["org_id"]
    for address in addresses:
        service.register_org_email(_ADMIN, org_id, address)
    live = service.create_key(_ADMIN, org_id, "live", None, test=False)
    test = service.create_key(_ADMIN, org_id, "test", None, test=True)
    _write_secrets(secret_path, org_id, live, test)
    welcome = _welcome(
        name=org["name"],
        org_id=org_id,
        org_type=org["org_type"],
        emails=addresses,
        live_key_id=live["key_id"],
        live_prefix=live["prefix"],
        test_key_id=test["key_id"],
        test_prefix=test["prefix"],
        secret_path=secret_path,
        public_base_url=public_base_url.rstrip("/"),
    )
    log.info(
        "issued keys org_id=%s live_key_id=%s test_key_id=%s",
        org_id,
        live["key_id"],
        test["key_id"],
    )
    return OnboardResult(org_id=org_id, welcome=welcome, secret_path=secret_path)


def main(argv: list[str] | None = None, *, connect=None) -> None:
    parser = argparse.ArgumentParser(
        description="Create an organization, record its emails, and write a welcome pack. Keys go to a local file."
    )
    parser.add_argument("--name", required=True, help="Organization name")
    parser.add_argument("--type", required=True, dest="org_type", help="agent_operator, wallet, bank_issuer, processor_psp, or merchant")
    parser.add_argument("--email", action="append", default=[], help="Organization dashboard email. Repeat for more than one.")
    parser.add_argument("--out", required=True, help="Directory for the welcome pack and the key file")
    args = parser.parse_args(argv)
    if connect is None:
        service, public_base_url = _connect_from_env()
    else:
        service, public_base_url = connect()
    try:
        result = onboard(
            service,
            name=args.name,
            org_type=args.org_type,
            emails=list(args.email),
            out_dir=Path(args.out),
            public_base_url=public_base_url,
        )
    except BureauError as exc:
        raise SystemExit(exc.message) from exc
    print(result.welcome, end="")


def _connect_from_env() -> tuple[BureauService, str]:
    from kata_service.bureau_pg import PostgresRepo
    from kata_service.settings import settings_from_env

    settings = settings_from_env()
    if not settings.database_url:
        raise SystemExit("DATABASE_URL is not set")
    repo = PostgresRepo(settings.database_url, settings.schema_url)
    service = BureauService(repo, public_base_url=settings.public_base_url)
    return service, settings.public_base_url


def _validated_emails(emails: list[str]) -> list[str]:
    if not emails:
        raise BureauError(400, "at least one organization email is required")
    addresses: list[str] = []
    for item in emails:
        address = _email(item)
        if address not in addresses:
            addresses.append(address)
    return addresses


def _prepare_out(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    path = out_dir / "keys.txt"
    if path.exists():
        raise BureauError(400, "key file already exists")
    return path


def _write_secrets(path: Path, org_id: str, live: dict, test: dict) -> None:
    body = (
        f"org_id={org_id}\n"
        f"live_key_id={live['key_id']}\n"
        f"live_token={live['token']}\n"
        f"test_key_id={test['key_id']}\n"
        f"test_token={test['token']}\n"
    )
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, body.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    _assert_private(path)


def _welcome(
    *,
    name: str,
    org_id: str,
    org_type: str,
    emails: list[str],
    live_key_id: str,
    live_prefix: str,
    test_key_id: str,
    test_prefix: str,
    secret_path: Path,
    public_base_url: str,
) -> str:
    listed = "\n".join(f"- {item}" for item in emails)
    text = (
        "Global Agent Bureau welcome pack\n"
        "\n"
        f"Organization: {name}\n"
        f"Organization id: {org_id}\n"
        f"Type: {org_type}\n"
        "Dashboard emails:\n"
        f"{listed}\n"
        "\n"
        f"Live key id: {live_key_id}\n"
        f"Live key prefix: {live_prefix}\n"
        f"Test key id: {test_key_id}\n"
        f"Test key prefix: {test_prefix}\n"
        "\n"
        f"The secret file is {secret_path}. It is the only copy of the raw keys. "
        "This command does not print them. "
        "Hand that file to the customer through a channel you already trust, then delete it from this machine.\n"
        "\n"
        f"Base URL: {public_base_url}\n"
        "Send Authorization: Bearer and the key from the secret file. "
        "The test key prefix is gab_test_. The live key prefix is gab_. "
        "Use the test key while you integrate. Use the live key for production traffic.\n"
        "\n"
        "Global Agent Bureau is an agent bureau and a technology company. "
        "The framework is KATA. The license is PolyForm Noncommercial.\n"
    )
    (secret_path.parent / "welcome.txt").write_text(text, encoding="utf-8")
    return text


def _assert_private(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise BureauError(500, "key file is readable by other users")


if __name__ == "__main__":
    main()
