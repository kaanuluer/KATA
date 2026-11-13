# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""HTTPS directory URLs that resolve only to globally routable addresses.

Private, loopback, link-local, multicast, unspecified, and documentation ranges
are rejected before a connection is opened.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

_BLOCKED_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.internal",
    }
)
_IPV4 = re.compile(r"^(?:\d+\.){3}\d+$")


class DirectoryRejected(Exception):
    """The directory URL is not a public HTTPS URL."""


class ResolveFailed(Exception):
    """The directory name could not be resolved."""


def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not ip.is_global


def _ipv4_literal(host: str) -> None:
    if not _IPV4.match(host):
        return
    parts = host.split(".")
    if any((len(part) > 1 and part.startswith("0")) or int(part) > 255 for part in parts):
        raise DirectoryRejected("directory URL is not allowed")
    if _blocked(ipaddress.ip_address(host)):
        raise DirectoryRejected("directory URL is not allowed")


def assert_public_https(url: str, *, resolve=None) -> str:
    """Reject a non-public directory URL. Return the hostname when it is allowed.

    ``resolve`` receives a hostname and returns IP strings. The default resolver
    is ``socket.getaddrinfo``. A caller that already has a fetch stub still has
    to pass this check before that stub is called.
    """

    if not isinstance(url, str) or not url or any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise DirectoryRejected("directory URL is not allowed")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        raise DirectoryRejected("directory URL is not allowed")
    host = parsed.hostname
    if not host:
        raise DirectoryRejected("directory URL is not allowed")
    if host.endswith("."):
        host = host[:-1]
    lowered = host.lower()
    if (
        lowered in _BLOCKED_NAMES
        or lowered.endswith(".localhost")
        or lowered.endswith(".local")
        or lowered.endswith(".internal")
    ):
        raise DirectoryRejected("directory URL is not allowed")
    if re.fullmatch(r"\d+", lowered) or lowered.startswith("0x"):
        raise DirectoryRejected("directory URL is not allowed")
    if _IPV4.match(lowered):
        _ipv4_literal(lowered)
        return lowered
    try:
        literal = ipaddress.ip_address(lowered)
    except ValueError:
        literal = None
    if literal is not None:
        if _blocked(literal):
            raise DirectoryRejected("directory URL is not allowed")
        return lowered
    finder = resolve or default_resolve
    try:
        addresses = list(finder(lowered))
    except Exception as exc:  # noqa: BLE001 — a resolver failure is not a public address
        raise ResolveFailed("directory name did not resolve") from exc
    if not addresses:
        raise ResolveFailed("directory name did not resolve")
    try:
        parsed_addresses = [ipaddress.ip_address(item) for item in addresses]
    except ValueError as exc:
        raise DirectoryRejected("directory URL is not allowed") from exc
    if any(_blocked(item) for item in parsed_addresses):
        raise DirectoryRejected("directory URL is not allowed")
    return lowered


def default_resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [item[4][0] for item in infos]
