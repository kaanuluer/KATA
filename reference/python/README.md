# KATA intent agreement — reference library

**Status: Concept / Open Design — not production ready.**

Python reference for the signed intent mandate and the agreement lifecycle in [docs/intent-agreement.md](../../docs/intent-agreement.md). PolyForm Noncommercial 1.0.0, copyright 2026 Kaan Uluer.

The library can:

- produce the canonical confirmation text and its hash (English is built in; another language needs the same registered renderer on both sides)
- sign that mandate with Ed25519 (`alg: EdDSA`) or P-256 (`alg: ES256`), as a flattened JWS
- verify either signature
- walk propose → clarify → accept → acknowledge → amend → add an intent → revoke or expire
- keep a hash-chained spend ledger on the agreement and evaluate one action as `ALLOW`, `STEP_UP`, or `DENY`
- check a pull revocation cache, a signed push, a Merkle transparency log, a daily FX ceiling, and an institution key directory when the caller supplies them

KATA does not render a user interface and does not open a socket. The wallet displays the confirmation. A deployment supplies the fetcher, the webhook, and the rate source.

`DENY` maps to the KATA decision `BLOCK`. This package does not score behavior and does not emit `REVOKE` or `QUARANTINE`.

## Run

```bash
cd reference/python
python3 -m pip install -e '.[dev]'
python3 -m pytest
PYTHONPATH=src python3 examples/purchase_check.py
```

The example signs a CAD 1,500 electronics intent, allows a CAD 1,300 laptop, denies a CAD 4,200 laptop, then revokes the agreement and denies the in-scope purchase.

Demo keys in the example are derived from public seeds. They are not a real principal key.
