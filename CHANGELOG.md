# Changelog

## 2026-10-12

KATA's docs were updated from a reading of Sardine's public report *[Rethinking Fraud Prevention for Agentic Commerce](https://www.sardine.ai/whitepapers/rethinking-fraud-prevention-for-agentic-commerce)* (2026). No schema or example changed. Nothing in the update is a measured result.

- Mapped Sardine's four Know Your Agent responsibilities onto Q1–Q4. Noted where KATA asks for a signed delegation and a signed structured intent, and where that record is evidence in a first-party "I didn't authorize this" dispute.
- Extended the threat model: a compromised AI application account as an upstream account-takeover path (verification succeeds, and the outcome is still fraud); agent spoofing; undeclared automation, with bot detection running alongside KATA; authorized agents acting inside their authority toward an illegitimate outcome; merchant, first-party, and third-party typologies in agentic flows.
- Cited [IETF Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/) as the emerging standard Visa and Mastercard agentic protocols use for agent authentication.
- Described segmented scoring and monitoring for agentic traffic, configurable `STEP_UP` thresholds (including per-session re-verification such as 3-D Secure), and the ways device and behavior signals degrade.
- Recorded the liability asymmetry: trust along the chain is transitive, and liability is not, across the user, the AI provider, the merchant, the PSP or acquirer, the network, and the issuer.
