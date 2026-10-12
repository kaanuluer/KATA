# KATA intent agreement — reference library

**Status: Concept / Open Design — not production ready.**

Python reference for the signed intent mandate and the agreement lifecycle in [docs/intent-agreement.md](../../docs/intent-agreement.md). Apache-2.0, copyright 2026 Kaan Uluer.

The library can:

- render a mandate in the words the principal confirms
- sign that mandate with Ed25519, as a flattened JWS (`alg: EdDSA`)
- verify the signature
- walk propose → clarify → accept → acknowledge → amend → revoke or expire
- evaluate one action as `ALLOW`, `STEP_UP`, or `DENY`, with reason codes

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
