# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""JWKS fetch and TTL cache.

Only EdDSA (Ed25519) and ES256 (P-256) public keys are kept. A private ``d``
member is dropped and is not written to the cache. Fetch uses the resolved
public address, so a name cannot switch to a private address after the check.
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
from datetime import datetime, timedelta
from typing import Any, Callable
from urllib.parse import urlsplit

from kata_intent.keys import PublicKey

from kata_service.evidence.ssrf import DirectoryRejected, ResolveFailed, assert_public_https, default_resolve
from kata_service.evidence.store import EvidenceStore

Fetch = Callable[[str, float], bytes]
Resolve = Callable[[str], list[str]]

DEFAULT_TTL_SECONDS = 300
DEFAULT_MAX_ENTRIES = 64
DEFAULT_MAX_KEYS = 8
DEFAULT_MAX_BYTES = 65536
DEFAULT_TIMEOUT_SECONDS = 2.0
_ALLOWED_ALGS = frozenset({"EdDSA", "ES256"})


class FetchFailed(Exception):
    """The directory did not return a usable JWKS document."""


class JwksRejected(Exception):
    """The JWKS document was readable and was refused."""


def directory_hash(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _b64url_decode(value: str) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    padding = "=" * (-len(value) % 4)
    try:
        import base64

        return base64.urlsafe_b64decode(value + padding)
    except Exception:  # noqa: BLE001 — a bad JWK coordinate is an unusable key
        return None


def _algorithm(jwk: dict[str, Any]) -> str | None:
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return "EdDSA"
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return "ES256"
    return None


def public_jwk(value: Any) -> dict[str, Any] | None:
    """Return a cacheable public JWK, or None when the member cannot be used."""

    if not isinstance(value, dict) or "d" in value:
        return None
    algorithm = _algorithm(value)
    if algorithm is None:
        return None
    stated = value.get("alg")
    if stated is not None and stated != algorithm:
        return None
    if value.get("use") not in {None, "sig"}:
        return None
    operations = value.get("key_ops")
    if operations is not None and operations != ["verify"]:
        return None
    kid = value.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > 200:
        return None
    if algorithm == "EdDSA":
        raw = _b64url_decode(value.get("x"))
        if raw is None or len(raw) != 32:
            return None
        stored = {"alg": algorithm, "crv": "Ed25519", "kid": kid, "kty": "OKP", "use": "sig", "x": value["x"]}
    else:
        x = _b64url_decode(value.get("x"))
        y = _b64url_decode(value.get("y"))
        if x is None or y is None or len(x) != 32 or len(y) != 32:
            return None
        stored = {
            "alg": algorithm,
            "crv": "P-256",
            "kid": kid,
            "kty": "EC",
            "use": "sig",
            "x": value["x"],
            "y": value["y"],
        }
    return {"kid": kid, "alg": algorithm, "jwk": stored}


def signing_key(jwk: dict[str, Any]) -> PublicKey | None:
    algorithm = _algorithm(jwk)
    if algorithm is None:
        return None
    if algorithm == "EdDSA":
        raw = _b64url_decode(jwk.get("x"))
        if raw is None:
            return None
        return PublicKey(raw, algorithm)
    x = _b64url_decode(jwk.get("x"))
    y = _b64url_decode(jwk.get("y"))
    if x is None or y is None:
        return None
    return PublicKey(x + y, algorithm)


def parse_jwks(body: bytes, *, max_keys: int) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchFailed("jwks fetch failed") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
        raise JwksRejected("jwks document was refused")
    members = parsed["keys"]
    if len(members) > max_keys:
        raise JwksRejected("jwks document was refused")
    usable = [item for item in (public_jwk(member) for member in members) if item is not None]
    if not usable:
        raise JwksRejected("jwks document was refused")
    return usable


def read_http_response(recv, *, limit: int) -> bytes:
    """Read one HTTP/1.1 response from ``recv(n) -> bytes``. Redirects are refused."""

    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = recv(4096)
        if not chunk:
            raise FetchFailed("jwks fetch failed")
        buffer.extend(chunk)
        if len(buffer) > limit + 8192:
            raise FetchFailed("jwks fetch failed")
    head, _, rest_bytes = buffer.partition(b"\r\n\r\n")
    rest = bytearray(rest_bytes)
    lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise FetchFailed("jwks fetch failed")
    status = int(parts[1])
    if status != 200:
        raise FetchFailed("jwks fetch failed")
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    if "content-length" in headers:
        try:
            length = int(headers["content-length"])
        except ValueError as exc:
            raise FetchFailed("jwks fetch failed") from exc
        if length > limit:
            raise FetchFailed("jwks fetch failed")
        while len(rest) < length:
            chunk = recv(length - len(rest))
            if not chunk:
                raise FetchFailed("jwks fetch failed")
            rest.extend(chunk)
        return bytes(rest[:length])
    while len(rest) <= limit:
        chunk = recv(4096)
        if not chunk:
            break
        rest.extend(chunk)
    if len(rest) > limit:
        raise FetchFailed("jwks fetch failed")
    return bytes(rest)


def fetch_public_https(url: str, timeout: float, *, resolve: Resolve | None = None, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """GET a public HTTPS URL. The TCP connection uses the address that was checked."""

    host = assert_public_https(url, resolve=resolve)
    parsed = urlsplit(url)
    port = parsed.port or 443
    finder = resolve or default_resolve
    addresses = [host] if _is_ip(host) else list(finder(host))
    if not addresses:
        raise FetchFailed("jwks fetch failed")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    host_header = host if port == 443 else f"{host}:{port}"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "User-Agent: gab-evidence\r\n"
        "\r\n"
    ).encode("ascii")
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection((addresses[0], port), timeout)
    except Exception as exc:  # noqa: BLE001 — the directory did not answer
        raise FetchFailed("jwks fetch failed") from exc
    try:
        tls = context.wrap_socket(raw, server_hostname=None if _is_ip(host) else host)
        try:
            tls.settimeout(timeout)
            tls.sendall(request)

            def recv(n: int) -> bytes:
                return tls.recv(n)

            return read_http_response(recv, limit=max_bytes)
        finally:
            tls.close()
    except FetchFailed:
        raise
    except Exception as exc:  # noqa: BLE001 — the directory did not answer
        raise FetchFailed("jwks fetch failed") from exc
    finally:
        raw.close()


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class KeyCache:
    def __init__(
        self,
        store: EvidenceStore,
        *,
        fetch: Fetch | None = None,
        resolve: Resolve | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_keys: int = DEFAULT_MAX_KEYS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.store = store
        self.fetch = fetch or (lambda url, timeout_seconds: fetch_public_https(url, timeout_seconds, resolve=resolve, max_bytes=max_bytes))
        self.resolve = resolve or default_resolve
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_entries = max_entries
        self.max_keys = max_keys
        self.max_bytes = max_bytes
        self.timeout = timeout

    def keys_for(self, directory: str, kid: str, now: datetime) -> list[dict[str, Any]]:
        try:
            assert_public_https(directory, resolve=self.resolve)
        except ResolveFailed as exc:
            raise FetchFailed("jwks fetch failed") from exc
        digest = directory_hash(directory)
        cached = self.store.read_keys(digest, now)
        if any(item["kid"] == kid for item in cached):
            return cached
        return self._refresh(directory, digest, now)

    def _refresh(self, directory: str, digest: str, now: datetime) -> list[dict[str, Any]]:
        try:
            body = self.fetch(directory, self.timeout)
        except FetchFailed:
            raise
        except Exception as exc:  # noqa: BLE001 — a stub or the network failed closed
            raise FetchFailed("jwks fetch failed") from exc
        if not isinstance(body, (bytes, bytearray)) or len(body) > self.max_bytes:
            raise FetchFailed("jwks fetch failed")
        keys = parse_jwks(bytes(body), max_keys=self.max_keys)
        self.store.put_keys(digest, keys, now=now, expires_at=now + self.ttl, max_entries=self.max_entries)
        return self.store.read_keys(digest, now)
