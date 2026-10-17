# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Loopback load of /v1/verify. Not part of default pytest.

synthetic data, shared VM, loopback, no upstream.

Defenses stay at the service defaults (velocity on, verify cap 60/minute,
general cap 120/minute). Each repetition uses a new key and a new agent so
the counters start at zero. GAB_TEST_DATABASE_URL must be localhost.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from kata_intent import Actor, Agreement, private_key_from_seed

OUTPUT = Path(__file__).resolve().parent / "output" / "load"
LABEL = "synthetic data, shared VM, loopback, no upstream"
AT = "2026-10-17T12:00:00Z"
EXPIRY = "2026-12-31T23:59:59Z"
PORT = 8876


def _database_url() -> str:
    url = os.environ.get("GAB_TEST_DATABASE_URL") or ""
    host = urlparse(url).hostname
    if host not in {"localhost", "127.0.0.1"}:
        raise SystemExit("GAB_TEST_DATABASE_URL must point at localhost")
    return url


def _scrub(text: str, url: str) -> str:
    return text.replace(url, "<database>")


def _keys(agent_id: str):
    principal = private_key_from_seed(hashlib.sha256(b"synthetic-principal-" + agent_id.encode()).digest())
    agent = private_key_from_seed(hashlib.sha256(b"synthetic-agent-" + agent_id.encode()).digest())
    return principal, agent


def _agreement(agent_id: str, principal_id: str, agreement_id: str) -> Agreement:
    principal, agent = _keys(agent_id)
    agreement = Agreement.propose(
        agreement_id=agreement_id,
        principal={"display_name": "SYNTHETIC TEST DATA", "id": principal_id, "type": "human"},
        agent={"agent_id": agent_id},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_load",
            "maximum_amount": 100,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 100000},
        parent_limits={"cumulative_maximum": 100000, "currency": "CAD", "maximum_amount": 100},
        actor=Actor("agent", agent_id),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    return agreement


class Server:
    def __init__(self, url: str, *, workers: int, keep_alive: int) -> None:
        self.url = url
        self.workers = workers
        self.keep_alive = keep_alive
        self.proc: subprocess.Popen[str] | None = None
        self.log_path = OUTPUT / f"uvicorn-w{workers}-ka{keep_alive}.log"

    def start(self) -> None:
        OUTPUT.mkdir(parents=True, exist_ok=True)
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GAB_") and not key.startswith("KATA_") and not key.startswith("DATABASE") and not key.startswith("POSTGRES")
        }
        env.update(
            {
                "DATABASE_URL": self.url,
                "DATABASE_URL_UNPOOLED": self.url,
                "GAB_ADMIN_TOKEN": "synthetic-admin-token",
                "GAB_DB_POOL_MAX": "10",
            }
        )
        log = self.log_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "kata_service.asgi:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(PORT),
                "--workers",
                str(self.workers),
                "--timeout-keep-alive",
                str(self.keep_alive),
            ],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        log.close()
        deadline = time.monotonic() + 30
        last = ""
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                response = httpx.get(f"http://127.0.0.1:{PORT}/health", timeout=2)
                last = f"{response.status_code} {response.text}"
                if response.status_code == 200:
                    return
            except httpx.HTTPError as exc:
                last = type(exc).__name__
            time.sleep(0.2)
        raise RuntimeError("server did not become ready: " + _scrub(last, self.url))

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def log_tail(self) -> str:
        if not self.log_path.exists():
            return ""
        text = self.log_path.read_text(encoding="utf-8", errors="replace")
        return _scrub(text, self.url)[-2000:]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _prepare(client: httpx.Client, agent_id: str) -> tuple[str, str]:
    org = client.post(
        "/v1/orgs",
        headers=_auth("synthetic-admin-token"),
        json={"name": "SYNTHETIC TEST DATA", "org_type": "agent_operator"},
    )
    if org.status_code != 200:
        raise RuntimeError(f"org {org.status_code} {org.text}")
    key = client.post(
        f"/v1/orgs/{org.json()['org_id']}/keys",
        headers=_auth("synthetic-admin-token"),
        json={"name": agent_id},
    )
    if key.status_code != 200:
        raise RuntimeError(f"key {key.status_code}")
    token = key.json()["token"]
    _principal, agent = _keys(agent_id)
    registered = client.post(
        "/v1/agents",
        headers=_auth(token),
        json={
            "agent_id": agent_id,
            "principal_id": "prn_" + agent_id.replace("-", "_"),
            "public_key": agent.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    if registered.status_code != 200:
        raise RuntimeError(f"register {registered.status_code} {registered.text}")
    agreement_id = "agr_" + agent_id.replace("-", "_")
    stored = client.post(
        f"/v1/agents/{agent_id}/intents",
        headers={**_auth(token), "Content-Type": "application/json"},
        content=_agreement(agent_id, "prn_" + agent_id.replace("-", "_"), agreement_id).to_json(),
    )
    if stored.status_code != 200:
        raise RuntimeError(f"store {stored.status_code} {stored.text}")
    return token, agreement_id


async def _one(client: httpx.AsyncClient, token: str, agent_id: str, agreement_id: str, index: int, close: bool) -> dict:
    headers = {**_auth(token), "Content-Type": "application/json"}
    if close:
        headers["Connection"] = "close"
    body = {
        "agent_id": agent_id,
        "agreement_id": agreement_id,
        "action": {
            "action_id": f"act_{index:05d}",
            "action_type": "purchase",
            "amount": 1,
            "context": {"merchant": "synthetic.example"},
            "currency": "CAD",
            "item": "SYNTHETIC TEST DATA",
            "parameters": {"merchant": "synthetic.example", "quantity": 1},
            "proposed_at": AT,
        },
    }
    started = time.perf_counter()
    try:
        response = await client.post("/v1/verify", headers=headers, json=body)
    except Exception as exc:  # noqa: BLE001 — the load record names the exception class
        return {"error": type(exc).__name__, "ms": round((time.perf_counter() - started) * 1000, 1)}
    reason = None
    verdict = None
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        payload = {}
    if isinstance(payload, dict):
        verdict = payload.get("verdict")
        reasons = payload.get("reasons")
        if isinstance(reasons, list) and reasons:
            reason = ",".join(str(item) for item in reasons)
        if response.status_code == 429:
            reason = response.headers.get("x-rate-limit-reason") or payload.get("error")
    return {
        "status": response.status_code,
        "verdict": verdict,
        "reason": reason,
        "ms": round((time.perf_counter() - started) * 1000, 1),
    }


async def _health_loop(base: str, stop: asyncio.Event, bucket: list[dict]) -> None:
    async with httpx.AsyncClient(base_url=base, timeout=2) as client:
        while not stop.is_set():
            started = time.perf_counter()
            try:
                response = await client.get("/health")
                bucket.append(
                    {
                        "status": response.status_code,
                        "body": response.json(),
                        "ms": round((time.perf_counter() - started) * 1000, 1),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                bucket.append({"error": type(exc).__name__, "ms": round((time.perf_counter() - started) * 1000, 1)})
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                continue


async def _burst(base: str, token: str, agent_id: str, agreement_id: str, count: int, concurrency: int, close: bool) -> tuple[list[dict], list[dict]]:
    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=0 if close else concurrency,
    )
    headers = {"Connection": "close"} if close else {}
    health: list[dict] = []
    stop = asyncio.Event()
    async with httpx.AsyncClient(base_url=base, timeout=20, limits=limits, headers=headers) as client:
        poll = asyncio.create_task(_health_loop(base, stop, health))
        sem = asyncio.Semaphore(concurrency)

        async def bound(index: int) -> dict:
            async with sem:
                return await _one(client, token, agent_id, agreement_id, index, close)

        rows = await asyncio.gather(*(bound(index) for index in range(count)))
        stop.set()
        await poll
    return list(rows), health


def _tally(rows: list[dict], health: list[dict]) -> dict:
    statuses: dict[str, int] = {}
    reasons: dict[str, int] = {}
    errors: dict[str, int] = {}
    latencies = []
    for row in rows:
        if "error" in row:
            errors[row["error"]] = errors.get(row["error"], 0) + 1
            continue
        status = str(row["status"])
        statuses[status] = statuses.get(status, 0) + 1
        if row.get("verdict"):
            key = f"{row['verdict']}:{row.get('reason') or ''}"
            reasons[key] = reasons.get(key, 0) + 1
        elif row.get("reason"):
            reasons[f"http:{row['reason']}"] = reasons.get(f"http:{row['reason']}", 0) + 1
        if isinstance(row.get("ms"), (int, float)):
            latencies.append(row["ms"])
    health_status: dict[str, int] = {}
    for item in health:
        label = str(item.get("status") or item.get("error"))
        health_status[label] = health_status.get(label, 0) + 1
    latencies.sort()
    return {
        "requests": len(rows),
        "statuses": statuses,
        "reasons": reasons,
        "errors": errors,
        "latency_ms_p50": latencies[len(latencies) // 2] if latencies else None,
        "health_samples": len(health),
        "health_status": health_status,
    }


def _run_case(server: Server, *, concurrency: int, count: int, rep: int, close: bool, client_mode: str) -> dict:
    agent_id = f"shopper-c{concurrency}-r{rep}-{client_mode}"[:80]
    with httpx.Client(base_url=f"http://127.0.0.1:{PORT}", timeout=20) as client:
        token, agreement_id = _prepare(client, agent_id)
    rows, health = asyncio.run(
        _burst(f"http://127.0.0.1:{PORT}", token, agent_id, agreement_id, count, concurrency, close)
    )
    summary = _tally(rows, health)
    summary.update(
        {
            "label": LABEL,
            "concurrency": concurrency,
            "rep": rep,
            "client_mode": client_mode,
            "workers": server.workers,
            "timeout_keep_alive": server.keep_alive,
            "pool_max_per_worker": 10,
            "defenses": "defaults on",
            "verify_rate_limit_per_minute": 60,
            "rate_limit_per_minute": 120,
            "velocity_daily_count": 25,
        }
    )
    return summary


def main() -> None:
    url = _database_url()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    cases = []
    plan = [
        (5, False, "keepalive", [(10, 80), (50, 120), (200, 240)]),
        (5, True, "close", [(200, 240)]),
        (1, False, "keepalive-1s", [(200, 240)]),
    ]
    for keep_alive, close, mode, steps in plan:
        server = Server(url, workers=3, keep_alive=keep_alive)
        server.start()
        try:
            for concurrency, count in steps:
                for rep in range(1, 4):
                    print(f"c={concurrency} rep={rep} mode={mode}", flush=True)
                    cases.append(_run_case(server, concurrency=concurrency, count=count, rep=rep, close=close, client_mode=mode))
        finally:
            tail = server.log_tail()
            server.stop()
            (OUTPUT / f"uvicorn-w3-ka{keep_alive}.tail.txt").write_text(tail, encoding="utf-8")
    (OUTPUT / "runs.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
    lines = [LABEL, "workers=3 pool_max_per_worker=10 defenses=defaults", ""]
    for case in cases:
        lines.append(
            "c={concurrency} rep={rep} mode={client_mode} ka={timeout_keep_alive} "
            "statuses={statuses} reasons={reasons} errors={errors} health={health_status} p50_ms={latency_ms_p50}".format(**case)
        )
    text = "\n".join(lines) + "\n"
    (OUTPUT / "summary.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)


if __name__ == "__main__":
    main()
