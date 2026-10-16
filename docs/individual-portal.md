# Individual portal on a phone

This note is the design for the individual portal. It is not a public product claim. The step-up approval flow below stays off until `GAB_STEP_UP_APPROVAL` is set.

## What this covers

1. The individual portal is laid out for a phone and can be installed: a web manifest, GAB_ icons, a service worker with an offline shell, and an add-to-home-screen control.
2. Sign-in accepts a passkey (WebAuthn). The existing email link remains the fallback. A device is registered only when the individual asks, and the portal lists those devices and can remove them.
3. When the bureau returns `STEP_UP` for an action tied to an individual, the service can open a short-lived approval and send a web push. That path is behind `GAB_STEP_UP_APPROVAL` and defaults off. Approve and reject use a passkey. Revoking an agent, revoking an intent, and filing a dispute use that same passkey check.

The individual portal does not show an agent score, a risk figure, or score reasons, and it does not score the individual. Organizations still receive the agent score on the organization API.

## Effort

The change is additive.

- One SQL migration (`009_portal_devices.sql`) and matching methods on the memory store and the Postgres store. Earlier migrations stay as they are.
- A WebAuthn registration, sign-in, and assertion path. The Python dependency is `webauthn`. Challenges are single-use and expire.
- Portal HTML, script, and a small set of mobile rules in the existing stylesheet. The Chapters layout of the public site stays.
- A manifest, two PNG icons made from the GAB_ mark, and `/sw.js`.
- Approval rows and a push sender that are idle unless the flag is on. Network delivery also needs VAPID keys in the host environment. Those keys are not in the repo.

## Risks

- The relying party id is the host the individual opened. A preview host and the production host are different passkey scopes. A passkey registered on one host does not sign in on the other.
- The service worker can keep an older copy of the portal shell. API responses are not cached. The offline page is a static shell and does not show account data.
- Web push on iPhone needs the installed home-screen app and a recent OS. With the flag off, or without VAPID keys, the service stores nothing for push and sends nothing.
- Revoke and dispute now fail until a passkey is registered. An email-link session alone is not enough for those actions.
- The approval row holds the action text so the individual can review it after opening the portal. That text is removed when the approval is used or expires. The push sender accepts only one fixed sentence. A change that copied the action into the push would break the rule, so the sender rejects any other text.
- A cloned authenticator is rejected when the sign counter does not increase. An authenticator that never reports a counter is accepted, which is the WebAuthn rule for that case.

## Data stored

Existing login rows stay: the email address, a hash of that address, and the pseudonymous principal id. Session tokens stay stored as hashes. The email is not copied into inquiries, the audit log, or the transparency log.

New rows, and only these:

| Store | Fields | When |
|---|---|---|
| Passkey | Credential id, COSE public key, sign counter, device label, created time, last-used time | The individual registers the device |
| Challenge | Challenge, kind (`register`, `authenticate`, or `assert`), relying party id, origin, expiry, used time | Issued for a ceremony, then marked used |
| Push device | Endpoint, browser `p256dh` and `auth` values, consent time | Only when the individual checks consent. A request without consent is refused |
| Approval | Approval id, principal id, hash of one action, the action text, status, expiry, used time | Only while `GAB_STEP_UP_APPROVAL` is on, and only for a `STEP_UP` tied to that principal |

Not stored: the private half of a passkey, a score of the individual, a government identifier, or the merchant, amount, or agent name inside a push. The push text is only:

`an agent is waiting for your approval, open to review`

Approvals are single-use, bound to one action hash, and expire (default 300 seconds, capped at 900). After a decision or expiry the action text is cleared. The portal page states the same storage list.
