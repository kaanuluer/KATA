# Verifiable Intent — Worked KATA Evaluation

**Status: Concept / Open Design — not production ready.**

KATA is not affiliated with Mastercard or the Verifiable Intent Working Group.

This request is a static composition of the reference autonomous flow at commit `356c29635f1c44df7de02edb58699ca9f29bece6` (`examples/autonomous_flow.py`, `examples/helpers.py`), using claim names from spec 0.1-draft (`spec/credential-format.md`, `spec/constraints.md`, dated 2026-02-18). The live example calls `time.time()` and `uuid.uuid4()`. Here L1 `iat` is the spec §3.6 sample `1700000000`, L2 lifetime is the example's `+86400`, and L3 lifetime is the example's `+300`. Nonces and hashes the example computes at runtime are the stand-in strings in [`source-claims.json`](source-claims.json). They are not digests.

Field-by-field mapping: [docs/interoperability.md](../../docs/interoperability.md).

## What the chain says

L1 `scheme` is the example's `"Mastercard"`. The spec §3.6 sample uses `"mastercard"`. The user `user-alice-001` delegated to `https://agent.verifiable-intent.example` (`L2.aud`). The agent key id in the example is `agent-key-1`. Constraints include `mandate.payment.amount_range` USD `10000`–`40000` minor units ($100.00–$400.00) and checkout items `BAB86345` and `HEA23102`, quantity cap 1. The agent selects `BAB86345`. Catalog `price` is `27999` cents. The example checkout JWT writes `unitPrice` `279.99` dollars. L3a `payment_amount.amount` is `27999`.

`prompt_summary` is "Buy a Babolat tennis racket under $400". That sentence is a ceiling, not a quote. `price_expectation` is omitted. `price.listed_price` and `price.charged_amount` are both `279.99`. No fee line appears in the example checkout payload, so there is no `fee_breakdown` and no `UNDISCLOSED_FEE`.

## KATA fills that are not VI claims

| KATA field | Value | Why |
|---|---|---|
| `agent.provider` | `https://agent.example.com` | Required by [`schemas/agent.json`](../../schemas/agent.json). Copied from the example's L3 `iss`. The L3 always-visible table in §5.3 does not list `iss`. |
| `intent.intent_id` | `kata-vi-l2` | VI has no intent id. |
| `intent.purpose` | `purchase` | KATA label for a checkout/payment mandate. |
| `intent.version` | `1` | KATA integer. The vct suffix on these mandates is `.1`. |
| `delegation.delegation_id` | `stand-in-l2-nonce` | Mapped from L2 `nonce`. |
| `delegation.status` | `active` | KATA enum. VI uses `exp`. |
| `principal.type` | `human` | KATA enum. L1 `sub` supplies the id only. |

JWK coordinates are generated in `helpers.py` and are not copied.

## Decision

`ALLOW_WITH_MONITORING`. The verified chain is Q2 and Q3 evidence: merchant `merchant-uuid-1` is on the allowlist, the SKU is acceptable, and `27999` is inside `10000`–`40000`. There is no behavior history, so this is not a bare `ALLOW`. `reasons` is empty. `required_action` is `NONE`. `risk_score` `35` is illustrative.

`REVOKE` does not apply. The grant is the object that was verified.

## Files

- [`source-claims.json`](source-claims.json) — decoded VI claims used as inputs. Not a KATA object.
- [`evaluate-request.json`](evaluate-request.json) — `POST /kata/evaluate`
- [`evaluate-response.json`](evaluate-response.json) — the decision
