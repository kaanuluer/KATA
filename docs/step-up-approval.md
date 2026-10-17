# Step-up approval for an individual

This note is the design for approval notices. It is not a public product claim. The flow stays off unless `GAB_STEP_UP_APPROVAL` is set. It builds on the installable portal and the passkey already used to revoke and dispute.

## What this covers

When verify returns `STEP_UP` for an action tied to an individual, the service can open one short-lived approval and send a web push to devices that individual consented to. Approve and reject use a fresh passkey assertion. With the flag off, verify still returns `STEP_UP` and the service stores no approval and sends no push.

The review the individual sees after opening the signed-in portal can include the action. The push cannot.

## Security rules

These four rules bind the individual portal and this approval flow.

1. A push uses only this sentence: `an agent is waiting for your approval, open to review`. The sentence does not include a merchant, an amount, or an agent name. The sender checks the sentence before it reads the device.
2. An approval is single-use, bound to one action hash, and short-lived. The default lifetime is 300 seconds and the cap is 900. After a decision or expiry the action text is cleared. A second use is refused.
3. Revoking an agent, revoking an intent, and filing a dispute require a fresh passkey assertion. Approve and reject use that same check. An email-link session alone is not enough.
4. Storing a browser push address requires explicit consent. A request without `consent` true is refused.

The individual portal does not show a trust score and does not score individuals. The portal page states what is stored, including a push address only after consent and an approval only while this flow is on.

## Effort

The change is additive on the passkey portal.

- One SQL migration (`010_step_up.sql`) for push devices and approvals. Earlier migrations stay as they are.
- Matching methods on the memory store and the Postgres store. A pending row for the same principal and action hash is reused, so a repeat verify does not send a second push.
- Settings `GAB_STEP_UP_APPROVAL` (default off), `GAB_STEP_UP_TTL_SECONDS`, and the VAPID public key, private key, and subject. The private key is a host secret and is not in the repo.
- A push sender that accepts only the fixed sentence. Network delivery uses `pywebpush` when that library and the VAPID keys are present. Otherwise the approval is still stored and delivery is reported as not configured.
- Portal controls to consent, to list and remove a push device, and to approve or reject. Each mutation uses a passkey assertion.

## Risks

- The approval row holds the action text so the individual can review it after opening the portal. That text is removed when the approval is used or expires. A change that copied the action into the push would break rule 1, so the sender rejects any other text.
- Web push on iPhone needs the installed home-screen app and a recent OS. With the flag off, or without VAPID keys, no push is sent.
- The relying party id is the host the individual opened. A passkey registered on a preview host does not approve an action on another host.
- The service worker can keep an older portal shell. API responses, including approval rows, are not cached.

## Data stored

Only while this flow is on, and only for a `STEP_UP` tied to that principal:

| Store | Fields | When |
|---|---|---|
| Push device | Endpoint, browser `p256dh` and `auth` values, consent time | The individual checks consent |
| Approval | Approval id, principal id, hash of one action, the action text, status, expiry, used time | Verify returns `STEP_UP` for that principal |

Not stored: a score of the individual, or the merchant, amount, or agent name inside a push. The push text is only:

`an agent is waiting for your approval, open to review`
