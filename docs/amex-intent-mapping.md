# AmEx Intent Intelligence mapping

**Status: research note. Nothing here is implemented.**

Global Agent Bureau is an agent bureau and a technology company. The license is PolyForm Noncommercial 1.0.0. This note maps the public American Express Intent Intelligence material onto the KATA intent agreement. It does not add a route, a token, or an adapter.

KATA objects below are the ones in [schemas/intent.json](../schemas/intent.json), [schemas/intent-mandate.json](../schemas/intent-mandate.json), [schemas/agreement.json](../schemas/agreement.json), and [schemas/action.json](../schemas/action.json). The rules that check them are in [intent-agreement.md](intent-agreement.md).

## Which AmEx source

This note means the **Intent Intelligence** framework published on 13 October 2026 by American Express Technology, plus the ACE Developer Kit pages that American Express itself hosts. It does not mean a news article, a recap, or a third-party field list.

### Pages opened on 16 October 2026

| Page | What came back |
| --- | --- |
| [Intent Intelligence: Building Trust in Agentic Commerce](https://americanexpress.io/intent-intelligence-building-trust-in-agentic-commerce/) | The framework. The page says it was published 13 October 2026. Authors named on the page: Inderpreet Hundal and Gianna Rotondo. |
| Sample images on that page: [item details](https://americanexpress.io/_post_assets/intent-intelligence-building-trust-in-agentic-commerce/img/sampledata1.jpg), [merchant details](https://americanexpress.io/_post_assets/intent-intelligence-building-trust-in-agentic-commerce/img/sampledata2.jpg), [purchase criteria](https://americanexpress.io/_post_assets/intent-intelligence-building-trust-in-agentic-commerce/img/sampledata3.jpg) | The only field lists. They are pictures, not a schema file. |
| [Agentic Commerce Experiences](https://www.americanexpress.com/en-us/company/agentic-commerce/) | Product page for the ACE Developer Kit. It says Account Enablement, Intent Intelligence, and Payment Credentials specifications are available as of 14 April 2026, and that Agent Registration and Cart Context specifications are still under development. |
| [Developer kit overview](https://developer.americanexpress.com/products/nextgen-agentic-payments/overview) | HTML shell. The product text is not in the document. |
| [ACE overview JSON](https://icm.aexp-static.com/Internet/EnterpriseAPIPortal/products/nextgen-agentic-payments/nextgen-agentic-payments-overview.json) | Product copy the portal loads for that overview. `Last Updated` inside the file is 10 April 2026. The terms say ACE materials require developer information and a confidentiality agreement with American Express. |
| [Agentic Payments guide JSON](https://icm.aexp-static.com/Internet/EnterpriseAPIPortal/products/nextgen-agentic-payments/nextgen-agentic-payments-guide.json) | Unfilled template. The header date reads `Monthtober 84, 3162`. Sentences still say to enter a description. It is not a field source. |
| `.../products/nextgen-agentic-payments/openapi-specification.json` on the same host | HTTP 302 to `https://www.americanexpress.com/us/homepage/error.html`. No schema body. |

The Create Intent API, the Intent ID, the Proof of Intent Token, the scoped payment credential, later use of the intent, and edit or cancel are described in prose on the 13 October page. Wire paths, JWT claims, and credential fields are not in any file opened here.

## How the sample pictures were read

The three samples are JPEG screenshots. Names below are the words visible in those pictures. A few glyphs are ambiguous:

- `itemReferenceId` and `merchantReferenceId` end in `Id`. A reader can confuse a capital `I` with a lowercase `l`. The 13 October prose says "item reference ID" and "merchant reference ID", which matches `Id`.
- `isRefundable` shows an enum whose first token is `YES`. The second token's capitalization is uncertain.
- `isRecurBill` is marked required. Its enum tokens read as `yes` and `No`, so capitalization is uncertain.
- `pricePreference` shows `MINIMUM PRICE`, `BETWEEN RANGE`, and `MAXIMUM PRICE` on the enum line. The sentence under `maxAmount` uses `BETWEEN_RANGE` with an underscore. This note does not choose one spelling.
- The merchants sample shows the words `Any of` under the array. No second shape's fields were readable, so only the properties listed below are recorded.

## Create Intent API

The 13 October page says the Create Intent API shares the user's confirmed purchase intent, including merchant, maximum budget, and other preferences, and that this creates a Proof of Intent Token. It does not publish a method, a path, or a request schema. The data elements in the next tables are what that page says is shared.

| AmEx element | Where it is stated | KATA field | Fit |
| --- | --- | --- | --- |
| Create Intent API | Prose heading only | `Agreement.propose`, principal acceptance, then the stored agreement | The bureau stores a signed agreement. It does not expose an issuer intent API. |
| Confirmed intent before the token exists | The user confirms, selects a payment instrument, then the intent can be authenticated | Mandate `status` moves through `proposed` to `accepted`. The evaluator trusts the signature, not the word `active` | Same order of events: confirm, then a record other parties can check. |
| Purchase Summary | Prose row. Personal details that are irrelevant to the purchase should be removed. The flight example keeps "Flight on July 12th" and drops the birthday context. No key in the three samples | `natural_language_source` keeps the original instruction. `rendering` is the canonical confirmation text and its SHA-256, both inside the signature | KATA keeps the source sentence. AmEx tells the sender to withhold personal detail. Those are different rules. |
| Max Amount | Prose: the maximum the user is willing to pay. Not given a key | `intent.maximum_amount` is the per-transaction ceiling. `limits.cumulative_maximum` is that intent's slice of the parent total | The page does not say which of those two the prose amount is. See Assumed. |
| Intent Expiry | Prose: the latest date by which the intent can be actioned | `intent.time_limit` and mandate `expires_at`. When both are set they are the same instant. `not_before` is a separate start | AmEx states an end date. It does not state a start date in this row. |
| Merchant Data | Prose: included if the user indicated a merchant preference. Sample keys are in the merchants table | `intent.merchant_constraints`. Empty means no allowlist. `limits.merchant_denylist` refuses merchants even when the allowlist is empty | A preference is narrower than "any merchant". KATA can store an allowlist. It has no separate "preference vs requirement" flag. |
| Item-Level Conditions | Prose: one item may depend on another. If no conditions are specified, each item is fulfilled independently | No dependency list in the intent schema | `dependentItems` in the purchase-criteria sample is the only structured form opened. KATA does not evaluate it. |
| Maximum Number of Transactions | Prose: the agent states the expected maximum number of purchases, and that number maps to the maximum number of payment credentials that can be issued | `limits.frequency` is `{max_count, per}` with `per` of `agreement`, `P1D`, `P7D`, or `P1M` (thirty days) | Both are counts. AmEx counts credentials. KATA counts recorded charges in a window. See Assumed. |
| Order Context | Prose: type `Intent` for parameters and preferences, type `Cart` for products the user approved. Item and merchant reference IDs are for the same request body, not stable ecosystem identifiers | No order-context type | The samples are titled as order context and do not show a type key. Line items are closer to an action than to the signed grant. |
| Purchase Criteria | Prose examples: buy when it restocks, or buy on a named date. Sample keys are in the purchase-criteria table | `constraints` is an open object. The evaluator's hard checks are the ceiling, currency, merchants, verbs, expiry, and frequency | A restock rule has no KATA field. A date range is `not_before` plus `expires_at` only if someone maps it. The page does not define that map. |

Broad intent on the page ("do not spend more than $100") is a ceiling. Specified intent (restock, size, price) adds conditions the intent schema only partly holds. Cart modes (order-ready cart, proposed cart) are user sign-off on a cart. KATA checks a proposed action against an already signed mandate. It does not store a cart version.

## Intent ID

| AmEx element | Where it is stated | KATA field | Fit |
| --- | --- | --- | --- |
| Intent ID | After authentication. "A unique identifier representing the purchase intent record, used as the primary key for any subsequent intent requests (e.g., intent lifecycle activities)." No format, prefix, or length | `agreement_id` is stable across versions. `intent_id` identifies one declaration inside a mandate. `mandate_id` identifies one signed version | The sentence matches a stable record key. `agreement_id` is the closer KATA id. `intent_id` is not, by itself, the key of later update and cancel operations. See Assumed. |

## Proof of Intent Token

| AmEx element | Where it is stated | KATA field | Fit |
| --- | --- | --- | --- |
| Proof of Intent Token | "A JSON Web Token representing the high-level constraints of the intent." Issued with the Intent ID after authentication | The mandate signature is a flattened JWS. `alg` is `EdDSA` or `ES256`. `typ` is `kata-mandate+jws`. The payload is the signing document, including `rendering` | Both are signed constraint records. The claim names are not the same, because AmEx does not publish claims. |
| Expires on the date the user set and confirmed | Bullet under the token | `expires_at` / `intent.time_limit` | The page ties token expiry to that user date. It does not show an `exp` claim. |
| Single-use or multi-use, to obtain payment credentials for one merchant or several | Same bullet | `limits.frequency` and `merchant_constraints` | "Use" on the page means credential issuance. It is not defined as a KATA charge count. |
| User sign-off | Passkey, or the issuer delegates sign-off to the agent or a wallet. The issuer may require more data for that delegation | The principal signs the canonical confirmation. The wallet or bank app displays that text and collects the signature. A sentence the wallet invents does not verify | Both require the holder to sign the captured intent. Passkey is not defined as Ed25519 or ES256 on the pages opened. |
| ACE overview, 10 April 2026 | Passkey authorization is described as signed evidence of consent. The merchant benefit line says a delegated purchase intent has signed evidence that can be audited | The mandate hash and the signature are the audit record | The overview states that the evidence is signed. It does not name an algorithm. |

## Scoped payment credential

| AmEx element | Where it is stated | KATA field | Fit |
| --- | --- | --- | --- |
| Credential obtained from the Proof of Intent Token | 13 October page. The agent uses it at checkout instead of the card number | None. The bureau does not issue a payment credential | The KATA result of a check is `ALLOW`, `STEP_UP`, or `DENY`. That is not a network token. |
| Scoped by the user-defined constraints | Same page, and the 10 April overview: "Payment credentials are scoped for limited use, enforcing the Card Member's intent and preferences." | The evaluator compares the action amount, currency, merchant, and verb with the mandate | Scoping is the shared idea. The credential object itself was not published. |
| Agent requests a payment token against a previously verified intent | 10 April overview, Fulfill | `POST /v1/verify` checks an action against a stored agreement | The bureau checks. It does not mint the token. |
| Issuer risk assessment, with the option to bring the cardholder back | 10 April overview | `STEP_UP` with `HUMAN_APPROVAL` for an over-broad intent. Other step-up reasons are in the agreement document | Both can pause for a person. The AmEx pause is before credential issuance. The KATA pause is a verdict on an action. |
| Transactions use existing network authorization standards | 10 April overview | Out of scope for the agreement check | No KATA field. |

The 13 October page also says the maximum number of transactions maps to the maximum number of payment credentials. That sentence is the only published link between the count and the credential. No credential property list was opened.

## Post-purchase use

| AmEx element | Where it is stated | KATA field | Fit |
| --- | --- | --- | --- |
| Intent ID and Proof of Intent Token as controls in later steps | Validating that a purchase request maps to an authorized intent | The action check against the live mandate. `parameters.intent_id` selects one mandate when several are live | The check is the analogue. AmEx does not show the purchase-request fields that would be compared. |
| Evidence if a dispute arises | The issuer can evaluate a later dispute against the intent the cardholder confirmed | The signed mandate and `rendering` are the authorization record. Bureau incident reports are a separate object | A report is not an AmEx dispute. No dispute payload was published, so this note does not map report fields. |
| Issuer keeps the intent record for later credential issuance, validation, and servicing | Issuer or Network section | The bureau stores the agreement, including `ledger` entries from `record_allowed` | Storage matches. The ledger counts charges KATA recorded. It is not a credential-issuance log. |
| Order context for dispute adjudication | Prose on 13 October. The company page says the Cart Context specification is still under development. The 10 April overview says cart context can also be evidence after the transaction | Action `item`, `amount`, `price`, and `counterparty` describe the charge being checked | Cart Context's fields were not opened. The item sample is labeled order context at intent creation, not a post-purchase message. |

## Edit and cancel

The 13 October page says Intent Intelligence is a suite of services to create, update, and cancel an authenticated intent. It does not publish an update body or a cancel body.

| AmEx element | Where it is stated | KATA field | Fit |
| --- | --- | --- | --- |
| Update | Named in the suite. The agent may store the intent so the user can view, modify, or cancel it | A new mandate version. `supersedes` is the hash of the replaced signing document. `mandate_history` keeps the old version. A child intent must stay inside the parent set | KATA's edit is a new signed version. AmEx does not say whether the Intent ID changes. |
| Cancel | Named in the suite | `revoke` accepts only the principal key that signed the mandate. `status` can read `revoked`. The signature is the authority | Cancel exists on both sides. Who may cancel is specified for KATA and only described for AmEx. |
| Issuer servicing: review, manage, or revoke | Issuer or Network section. The 10 April overview says cardholders view, manage, or revoke intents in the American Express application and supported issuer applications | Decision 8: nobody but the signing principal revokes | AmEx describes issuer and application servicing. KATA's reference `revoke` does not accept an issuer key. |
| View | Agent storage, wallet storage, issuer customer service | `GET` of stored agreements for the operator or the principal | A read of the stored record. No AmEx response schema was opened. |

## Sample: order context, item details

The picture is titled as item-level data the user requested and approved at intent creation. `items` is a required array of objects. The description reads: line items associated with the order, used for merchandise, retail, or electronics purchases.

| AmEx field | Stated type and rule | KATA field | Fit |
| --- | --- | --- | --- |
| `itemReferenceId` | string, required. Partner reference for this item in the request | None | The prose says this reference is not a stable ecosystem identifier. |
| `merchantReferenceId` | string. Partner reference for the merchant associated with this item | None as a stable id | Same request-local warning in the prose. |
| `name` | string, required. The name of the item | Action `item` | The grant does not require an item name. The action may carry one. |
| `unitAmount` | string. The unit price | Action `amount` and `price.charged_amount` are numbers | AmEx does not say major or minor units. KATA amounts are major units. A string was not converted here. |
| `currency` | string, ISO 4217. Required when `unitAmount` is provided | `intent.currency`, action `currency` | Same code standard. KATA requires `currency` on the intent when an amount is signed, rather than only when a unit price is present. |
| `quantity` | integer, required | `constraints` may hold a key such as `max_items`. That key is an example, not a line quantity the evaluator sums | No line-quantity check. |
| `condition` | string. Examples in the picture: new, refurbished, or used | None | No KATA enum. |
| `category` | string. Category associated with the item | `intent.category` is a domain such as `electronics` | Same word, coarser object. An item category is not defined as the intent category. |
| `brand` | string | None | No KATA field. |
| `imageLink` | string. Main product image URL | None | No KATA field. |
| `isRefundable` | string enum beginning with `YES` | None | No KATA field. |
| `isRecurBill` | string, required, enum for whether the item is a recurring purchase | None | No KATA field. |
| `purchaseCriteria` | array of objects. Constraints or preferences for the item | See the purchase-criteria table | Nested, not a top-level intent object. |
| `metadata` | object. String keys and string values | `constraints` allows extra keys. The evaluator does not treat unknown keys as rules | A bag of strings is not a signed limit unless a known field carries it. |

## Sample: order context, merchant details

`merchants` is a required array. The description reads: merchants associated with the order.

| AmEx field | Stated type and rule | KATA field | Fit |
| --- | --- | --- | --- |
| `name` | string, required. The merchant's display or registered name | A string in `merchant_constraints`, or action `context.merchant` | KATA does not split display name from registered name. |
| `merchantReferenceId` | string, required. Partner reference for this merchant in the request | None as a stable id | Request-local, per the prose note. |
| `seNumber` | string. Service establishment number associated with the merchant | None | No KATA field. |
| `categoryName` | string. The merchant's category name | `merchant_constraints` may hold a category string. The schema does not distinguish a category from a merchant name | Possible place to put the text. Not a defined category object. |
| `metadata` | object. String keys and string values | None required | Same limit as item `metadata`. |

## Sample: purchase criteria

`purchaseCriteria` is an array of objects. The description reads: constraints or preferences associated with the item.

| AmEx field | Stated type and rule | KATA field | Fit |
| --- | --- | --- | --- |
| `type` | string enum `PRICE` or `DATE` | None | KATA does not switch a criteria object on this enum. |
| `fromDate` | string, date-time. Required when `type` is `DATE`. Start of the fulfillment range | Mandate `not_before` | A start instant exists on the mandate. The page does not say `fromDate` is that field. |
| `toDate` | string, date-time. Required when `type` is `DATE`. End of the fulfillment range | `expires_at` / `intent.time_limit` | An end instant exists. The page does not define the assignment. |
| `pricePreference` | string enum. Required when `type` is `PRICE`. Tokens for a minimum, a range, and a maximum, with the spelling caveat above | `maximum_amount` is only a ceiling. `price_expectation` holds `quoted_price`, `listed_price`, and `tolerance_ratio` | A minimum price and a closed range are not KATA intent fields. The tolerance band is a different test. |
| `maxAmount` | string. Maximum price for the item. Required when `pricePreference` is `BETWEEN_RANGE` | `intent.maximum_amount` if a mapper chose the ceiling. The picture requires this field for a range, not for every intent | Do not treat this as the prose Max Amount. The picture's rule is narrower. |
| `minAmount` | string. Minimum price for the item. Required when `pricePreference` is `BETWEEN_RANGE` | None | KATA has no minimum purchase price on the intent. |
| `currency` | string, ISO 4217, for the price values | `intent.currency` | Same standard. Scale still unpublished. |
| `isShippingIncluded` | string enum `YES` / `NO`. Whether shipping is included in the price | `fee_policy.allowed_codes` can name `shipping`. `price.fee_breakdown` is on the action | Inclusion in the price is not the same as an accepted fee code. |
| `dependentItems` | array, marked recursive. Dependencies that must be satisfied before the item can be purchased | None | Matches the prose item-level conditions. No KATA evaluator for it. |

## Verified

- The framework page is `https://americanexpress.io/intent-intelligence-building-trust-in-agentic-commerce/`, published 13 October 2026, read 16 October 2026.
- Intent Intelligence is described there as a suite to create, update, and cancel an authenticated intent.
- After the user authenticates and signs off, an Intent ID and a Proof of Intent Token are issued.
- The Intent ID is a unique identifier for the purchase intent record and the primary key for later intent requests, including lifecycle activity.
- The Proof of Intent Token is a JSON Web Token of the high-level constraints. It expires on the date the user set and confirmed. It can be single-use or multi-use for payment credentials across one or more merchants.
- Sign-off can be a passkey, or the issuer can delegate sign-off to the agent or a wallet. The issuer may require more data for that delegation.
- The token is how a scoped payment credential is obtained. The credential stands in for the card number. The user's constraints scope it.
- Prose data elements on that page are Purchase Summary, Max Amount, Intent Expiry, Merchant Data, Item-Level Conditions, Maximum Number of Transactions, Order Context, and Purchase Criteria, with the definitions in the tables above.
- Order context type `Intent` means user parameters and preferences. Type `Cart` means products approved for purchase. Reference IDs are for one request body.
- The three sample pictures contain the fields listed in the sample tables, with the reading caveats in this note.
- The ACE company page lists five services: Agent Registration, Account Enablement, Intent Intelligence, Payment Credentials, and Cart Context. It says the first of those and Cart Context are still under development, and that the other three specifications are available as of 14 April 2026.
- The overview JSON dated 10 April 2026 describes passkey authorization as cryptographic evidence of consent, scoped limited-use payment credentials, and cardholder revoke in issuer applications.
- The OpenAPI file name the portal uses for this product was requested and was not served. The guide JSON on the public content host is still a template.
- KATA amounts are major units. The mandate is a flattened JWS, `EdDSA` or `ES256`. `revoke` in the reference library accepts the principal key that signed. Those sentences are from this repository's agreement document, not from American Express.

## Assumed

- `agreement_id` is the KATA id that should carry an Intent ID, because the AmEx sentence is about later lifecycle requests. `intent_id` remains the id of one signed declaration. The framework does not say which KATA name to use.
- Prose Max Amount is the per-transaction ceiling `maximum_amount`. It might instead be the cumulative slice, or the item `maxAmount` from the sample. The page does not choose.
- `limits.frequency.max_count` is the nearest place for Maximum Number of Transactions. The counters differ: credentials issued versus charges recorded.
- `fromDate` and `toDate` could be written to `not_before` and `expires_at`. The sample does not say to do that.
- A passkey sign-off and a KATA principal signature are both holder consent over the captured intent. They are not the same ceremony, and this note does not claim a passkey verifies as `kata-mandate+jws`.
- Item `name`, `unitAmount`, and `currency` could be copied onto the action that is checked. That is a charge, not the grant. The sample does not define that copy.
- Putting `categoryName` into `merchant_constraints` would preserve the text. KATA would then treat it as an allowlist entry, which may be stricter than a display category.

## Not accessible

- Create Intent method, path, host, headers, and error codes.
- The request schema that would bind the prose rows to JSON keys. Purchase Summary, Max Amount, Intent Expiry, and Maximum Number of Transactions do not appear as keys in the three samples.
- An order-context `type` key. The prose requires the values `Intent` and `Cart`. The samples do not show the key.
- Proof of Intent Token header, `alg`, `kid`, and claim names, including whether expiry is an `exp` claim.
- Who signs that JWT: the issuer, the user, the agent, or the wallet.
- Payment-credential fields: token value, cryptogram, merchant lock, credential expiry separate from the intent date, and single-use enforcement.
- Update and cancel paths and bodies. Whether an edit keeps the Intent ID. Whether cancel invalidates a credential already issued.
- Agent Registration and Cart Context specifications. The company page says they are still under development. They were not opened.
- The ACE specification behind the confidentiality agreement named in the 10 April overview terms.
- Unit scale for `unitAmount`, `maxAmount`, and `minAmount`.
- Any field that appeared only in a news article. Those pages were not used.
