# Individual portal on a phone

This note is the design for the individual portal: a phone layout, an installable home-screen app, passkey sign-in, and device registration. It is not a public product claim. Approval notices are specified in `docs/step-up-approval.md` and stay off unless the host sets the flag.

## What this covers

1. The individual portal is laid out for a phone and can be installed: a web manifest, GAB_ icons, a service worker with an offline shell, and an add-to-home-screen control.
2. Sign-in accepts a passkey (WebAuthn). The existing email link remains the fallback. A device is registered only when the individual asks, and the portal lists those devices and can remove them.
3. Revoking an agent, revoking an intent, and filing a dispute each require a fresh passkey assertion.

The individual portal does not show an agent score, a risk figure, or score reasons, and it does not score the individual. Organizations still receive the agent score on the organization API.

## Security rules

These four rules bind this portal and any approval notice built on it.

1. A push, when a host sends one, uses only this sentence: `an agent is waiting for your approval, open to review`. The sentence does not include a merchant, an amount, or an agent name.
2. An approval is single-use, bound to one action, and short-lived.
3. Revoking an agent, revoking an intent, and filing a dispute require a fresh passkey assertion. An email-link session alone is not enough.
4. Storing a browser push address requires explicit consent. A request without that consent is refused.

Passkey registration implements rule 3. The approval note implements rules 1, 2, and 4, and approve and reject use the same passkey check.

## Effort

The change is additive.

- One SQL migration (`009_portal_devices.sql`) for passkeys and ceremony challenges, plus matching methods on the memory store and the Postgres store. Earlier migrations stay as they are.
- A WebAuthn registration, sign-in, and assertion path. The Python dependency is `webauthn`. Challenges are single-use and expire.
- Portal HTML, script, and a small set of mobile rules in the existing stylesheet. The Chapters layout of the public site stays.
- A manifest, two PNG icons made from the GAB_ mark, and `/sw.js`.

## Risks

- The relying party id is the host the individual opened. A preview host and the production host are different passkey scopes. A passkey registered on one host does not sign in on the other.
- The service worker can keep an older copy of the portal shell. API responses are not cached. The offline page is a static shell and does not show account data.
- Revoke and dispute fail until a passkey is registered. An email-link session alone is not enough for those actions.
- A cloned authenticator is rejected when the sign counter does not increase. An authenticator that never reports a counter is accepted, which is the WebAuthn rule for that case.

## Data stored

Existing login rows stay: the email address, a hash of that address, and the pseudonymous principal id. Session tokens stay stored as hashes. The email is not copied into inquiries, the audit log, or the transparency log.

New rows, and only these:

| Store | Fields | When |
|---|---|---|
| Passkey | Credential id, COSE public key, sign counter, device label, created time, last-used time | The individual registers the device |
| Challenge | Challenge, kind (`register`, `authenticate`, or `assert`), relying party id, origin, expiry, used time | Issued for a ceremony, then marked used |

Not stored here: the private half of a passkey, a score of the individual, or a government identifier. A browser push address and an approval record are stored only by the approval flow, and only under the rules above. The portal page states the storage list for the rows this host actually keeps.
