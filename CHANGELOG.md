# Changelog

## 2026-10-12

README now states what is core and what is optional. An implementation needs the four questions, the intent and delegation schemas, and the decision outcomes. Use-case examples (payments, MCP or tool calls, checkout) are profiles. Sardine, Darwinium, and AgentCommerceBench are related work: they position KATA and do not extend it.

Darwinium's press release of 8 October 2026 is that related-work entry. Intent Intelligence infers intent from behavior (Journey Transition Probability on the order and timing of steps; MCP Protection links tool calls to the journey, checks agent credentials, and can step up before a payment). Darwinium reports that about one in four agentic transactions on its network self-declare. KATA records a signed intent and measures behavior against it. Under Q4, MCP tool-call sequences and aggregate drift across many requests are named as example signal sources. No new question, layer, or schema.

## 2026-10-12

KATA's docs were updated from a reading of Sardine's public report *[Rethinking Fraud Prevention for Agentic Commerce](https://www.sardine.ai/whitepapers/rethinking-fraud-prevention-for-agentic-commerce)* (2026). No schema or example changed. Nothing in the update is a measured result.

- Mapped Sardine's four Know Your Agent responsibilities onto Q1–Q4. Noted where KATA asks for a signed delegation and a signed structured intent, and where that record is evidence in a first-party "I didn't authorize this" dispute.
- Extended the threat model: a compromised AI application account as an upstream account-takeover path (verification succeeds, and the outcome is still fraud); agent spoofing; undeclared automation, with bot detection running alongside KATA; authorized agents acting inside their authority toward an illegitimate outcome; merchant, first-party, and third-party typologies in agentic flows.
- Cited [IETF Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/) as the emerging standard Visa and Mastercard agentic protocols use for agent authentication.
- Described segmented scoring and monitoring for agentic traffic, configurable `STEP_UP` thresholds (including per-session re-verification such as 3-D Secure), and the ways device and behavior signals degrade.
- Recorded the liability asymmetry: trust along the chain is transitive, and liability is not, across the user, the AI provider, the merchant, the PSP or acquirer, the network, and the issuer.
