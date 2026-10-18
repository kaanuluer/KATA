# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Loopback load of /v1/verify. Not part of default pytest.

synthetic data, shared VM, loopback, no upstream.

Two sets, each 3000 requests per run, c=10/50/200, workers 1, 3, and 4,
three repetitions, keepalive timeout 5:

- rate limits off: general and verify caps set to 1000000 per minute, and
  GAB_VELOCITY=0, so the run is not cut off by a 429 or a velocity DENY
- defenses on: those variables unset, so the defaults apply (general 120/minute,
  verify 60/minute, velocity daily count 25)

Each repetition uses a new key and a new agent. GAB_TEST_DATABASE_URL must be
localhost. KATA_LOAD_SMOKE=1 runs a short path check and is not the measurement.
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
    def __init__(self, url: str, *, workers: int, keep_alive: int, limits_off: bool) -> None:
        self.url = url
        self.workers = workers
        self.keep_alive = keep_alive
        self.limits_off = limits_off
        self.proc: subprocess.Popen[str] | None = None
        mode = "off" if limits_off else "on"
        self.log_path = OUTPUT / f"uvicorn-remeasure-w{workers}-{mode}.log"

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
        if self.limits_off:
            env["GAB_RATE_LIMIT_PER_MINUTE"] = "1000000"
            env["GAB_VERIFY_RATE_LIMIT_PER_MINUTE"] = "1000000"
            env["GAB_VELOCITY"] = "0"
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
    async with httpx.AsyncClient(base_url=base, timeout=60, limits=limits, headers=headers) as client:
        poll = asyncio.create_task(_health_loop(base, stop, health))
        sem = asyncio.Semaphore(concurrency)

        async def bound(index: int) -> dict:
            async with sem:
                return await _one(client, token, agent_id, agreement_id, index, close)

        rows = await asyncio.gather(*(bound(index) for index in range(count)))
        stop.set()
        await poll
    return list(rows), health


def _percentile(samples: list[float], fraction: float) -> float | None:
    if not samples:
        return None
    if len(samples) == 1:
        return round(samples[0], 1)
    rank = (len(samples) - 1) * fraction
    low = int(rank)
    high = min(low + 1, len(samples) - 1)
    weight = rank - low
    return round(samples[low] * (1 - weight) + samples[high] * weight, 1)


def _latency(samples: list[float]) -> dict[str, float | None]:
    ordered = sorted(samples)
    return {
        "p50": _percentile(ordered, 0.50),
        "p95": _percentile(ordered, 0.95),
        "p99": _percentile(ordered, 0.99),
    }


def _tally(rows: list[dict], health: list[dict]) -> dict:
    statuses: dict[str, int] = {}
    reasons: dict[str, int] = {}
    errors: dict[str, int] = {}
    latencies: list[float] = []
    by_status: dict[str, list[float]] = {}
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
            latencies.append(float(row["ms"]))
            by_status.setdefault(status, []).append(float(row["ms"]))
    health_status: dict[str, int] = {}
    for item in health:
        label = str(item.get("status") or item.get("error"))
        health_status[label] = health_status.get(label, 0) + 1
    http_latency = _latency(latencies)
    return {
        "requests": len(rows),
        "statuses": statuses,
        "reasons": reasons,
        "errors": errors,
        "error_count": sum(errors.values()),
        "allow_count": reasons.get("ALLOW:", 0),
        "latency_ms": http_latency,
        "latency_ms_p50": http_latency["p50"],
        "latency_ms_200": _latency(by_status.get("200", [])),
        "latency_ms_429": _latency(by_status.get("429", [])),
        "health_samples": len(health),
        "health_status": health_status,
    }


def _run_case(server: Server, *, concurrency: int, count: int, rep: int) -> dict:
    mode = "limits-off" if server.limits_off else "defenses-on"
    agent_id = f"w{server.workers}-c{concurrency}-r{rep}-{mode}"
    with httpx.Client(base_url=f"http://127.0.0.1:{PORT}", timeout=30) as client:
        token, agreement_id = _prepare(client, agent_id)
    rows, health = asyncio.run(
        _burst(f"http://127.0.0.1:{PORT}", token, agent_id, agreement_id, count, concurrency, False)
    )
    summary = _tally(rows, health)
    summary.update(
        {
            "label": LABEL,
            "concurrency": concurrency,
            "count": count,
            "rep": rep,
            "client_mode": "keepalive",
            "workers": server.workers,
            "timeout_keep_alive": server.keep_alive,
            "pool_max_per_worker": 10,
            "defenses": "rate_limits_off_velocity_off" if server.limits_off else "defaults_on",
            "verify_rate_limit_per_minute": 1000000 if server.limits_off else 60,
            "rate_limit_per_minute": 1000000 if server.limits_off else 120,
            "velocity_daily_count": None if server.limits_off else 25,
        }
    )
    return summary


def _reset(url: str) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS gab_sandbox CASCADE")
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("GRANT ALL ON SCHEMA public TO public")


def _line(case: dict) -> str:
    latency = case["latency_ms"]
    return (
        "workers={workers} c={concurrency} rep={rep} defenses={defenses} n={count} "
        "statuses={statuses} reasons={reasons} errors={errors} error_count={error_count} "
        "allow_count={allow_count} health={health_status} "
        "p50_ms={p50} p95_ms={p95} p99_ms={p99} "
        "p50_200_ms={p50_200} p95_200_ms={p95_200} p99_200_ms={p99_200} "
        "p50_429_ms={p50_429} p95_429_ms={p95_429} p99_429_ms={p99_429}"
    ).format(
        p50=latency["p50"],
        p95=latency["p95"],
        p99=latency["p99"],
        p50_200=case["latency_ms_200"]["p50"],
        p95_200=case["latency_ms_200"]["p95"],
        p99_200=case["latency_ms_200"]["p99"],
        p50_429=case["latency_ms_429"]["p50"],
        p95_429=case["latency_ms_429"]["p95"],
        p99_429=case["latency_ms_429"]["p99"],
        **case,
    )


def main() -> None:
    url = _database_url()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    smoke = os.environ.get("KATA_LOAD_SMOKE") == "1"
    _reset(url)
    count = 30 if smoke else 3000
    reps = (1,) if smoke else (1, 2, 3)
    worker_counts = (1,) if smoke else (1, 3, 4)
    concurrencies = (10,) if smoke else (10, 50, 200)
    modes = (True, False) if not smoke else (True, False)
    cases = []
    for limits_off in modes:
        for workers in worker_counts:
            server = Server(url, workers=workers, keep_alive=5, limits_off=limits_off)
            server.start()
            try:
                for concurrency in concurrencies:
                    for rep in reps:
                        print(
                            f"workers={workers} c={concurrency} rep={rep} limits_off={limits_off} n={count}",
                            flush=True,
                        )
                        cases.append(_run_case(server, concurrency=concurrency, count=count, rep=rep))
                        print(_line(cases[-1]), flush=True)
            finally:
                tail = server.log_tail()
                server.stop()
                mode = "off" if limits_off else "on"
                (OUTPUT / f"uvicorn-remeasure-w{workers}-{mode}.tail.txt").write_text(tail, encoding="utf-8")
    name = "smoke" if smoke else "remeasure"
    (OUTPUT / f"{name}_runs.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
    lines = [
        LABEL,
        "SYNTHETIC TEST DATA",
        "requests_per_run=" + str(count),
        "rate_limits_off_velocity_off: GAB_RATE_LIMIT_PER_MINUTE=1000000 GAB_VERIFY_RATE_LIMIT_PER_MINUTE=1000000 GAB_VELOCITY=0",
        "defaults_on: general 120/minute, verify 60/minute, velocity daily count 25",
        "workers 1, 3, and 4; c=10, 50, 200; three repetitions; keepalive timeout 5; pool max 10 per worker",
        "percentiles are client latency for responses that returned an HTTP status",
        "transport failures are errors, not included in the percentiles",
        "",
    ]
    for case in cases:
        lines.append(_line(case))
    on_three = [case for case in cases if case["defenses"] == "defaults_on" and case["workers"] == 3]
    over = [case for case in on_three if case["allow_count"] > 25]
    lines.extend(
        [
            "",
            "velocity finding, defenses on, 3 workers, cap 25:",
            f"runs={len(on_three)} allow_counts={[case['allow_count'] for case in on_three]}",
            f"runs_over_25={len(over)}",
        ]
    )
    text = "\n".join(lines) + "\n"
    (OUTPUT / f"{name}_summary.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)


if __name__ == "__main__":
    main()
