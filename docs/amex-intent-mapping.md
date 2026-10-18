# AmEx Intent Intelligence mapping

**Status: research note. Nothing here is implemented.**

Global Agent Bureau is an agent bureau and a technology company. The license is PolyForm Noncommercial 1.0.0. This note maps the public American Express Agentic Commerce OpenAPI document onto the KATA intent agreement. It does not enroll an account, create an intent at American Express, issue a payment credential, or send a notification.

The sandbox mapper `POST /v1/sandbox/amex-intent/to-kata` reads [adapters/amex/mapping.v1.json](../adapters/amex/mapping.v1.json) when `GAB_ENV` is `sandbox` and the key is a `gab_test_` key. It converts a JSON object in this process. It does not contact American Express.

KATA objects below are the ones in [schemas/intent.json](../schemas/intent.json), [schemas/intent-mandate.json](../schemas/intent-mandate.json), [schemas/agreement.json](../schemas/agreement.json), and [schemas/action.json](../schemas/action.json). The rules that check them are in [intent-agreement.md](intent-agreement.md).

## Which AmEx source

The field source is the OpenAPI 3.1.0 document **American Express Agentic Commerce Experience - Enrollment, Intent, Payment Credential, and Notification API (1.0.0)**, downloaded 18 October 2026.

| Fact | Value |
| --- | --- |
| URL | [nextgen-agentic-payments-openapi-specification.json](https://icm.aexp-static.com/Internet/EnterpriseAPIPortal/products/nextgen-agentic-payments/nextgen-agentic-payments-openapi-specification.json) |
| `openapi` | `3.1.0` |
| `info.version` | `1.0.0` |
| `info.x-lastUpdated` | April 28, 2026 |
| SHA-256 | `811381ed6dea4e4293f44108b1e8de2d75f1629a4a803729713c7c956ea7c47d` |
| Size | 286,306 bytes |
| Operations | 8, on 7 paths |
| Schemas | 64, under `components.schemas` |

Servers in the file are `https://apisandboxm.americanexpress.com` (sandbox) and `https://apigwm.americanexpress.com` (production). Request bodies that carry account, intent, or credential data are described as JWE on the wire. The `application/json` schema is the decrypted model.

`info.version` is `1.0.0`. No request schema has a `schemaVersion` property. A sender may still include `schemaVersion`. The value `1.0.0` matches the document version. The mapper keeps it and reports it as assumed.

### Earlier pages

The [Intent Intelligence](https://americanexpress.io/intent-intelligence-building-trust-in-agentic-commerce/) page, published 13 October 2026, is the framework essay. It names Purchase Summary, Max Amount, Intent Expiry, and Maximum Number of Transactions in prose and shows three JPEG samples. On 16 October 2026 the OpenAPI URL on this host answered with an error page, so that essay was the only field list then. It is not the field source for the keys in this note.

The [ACE company page](https://www.americanexpress.com/en-us/company/agentic-commerce/) says Account Enablement, Intent Intelligence, and Payment Credentials specifications were available as of 14 April 2026, and that Agent Registration and Cart Context were still under development. This OpenAPI file is the product document that is now served. It is one file covering enrollment, intent, payment credentials, and notifications. It does not say it is the Cart Context specification.

## Operations

| Method and path | `operationId` | What the description says |
| --- | --- | --- |
| `POST /payments/digital/v1/agentic-commerce/enrollments` | `enroll` | Enroll an account. A follow-up request completes step-up when the first response requires it. |
| `POST /payments/digital/v1/agentic-commerce/intents` | `createIntent` | Create an intent for an enrolled account. |
| `PUT /payments/digital/v1/agentic-commerce/intents/{intentId}` | `updateIntent` | Edit an intent. This is the update operation. |
| `DELETE /payments/digital/v1/agentic-commerce/intents/{intentId}` | `cancelIntent` | Cancel an intent. |
| `POST /payments/digital/v1/agentic-commerce/paymentcredentials` | `paymentCredentials` | Issue tokenized payment credentials for an approved intent. |
| `POST /payments/digital/v1/agentic-commerce/paymentcredentials/complete` | `paymentCredentialsComplete` | Acknowledge an authorization outcome: `APPROVED`, `DECLINED`, or `RETURNED`. |
| `POST /payments/digital/v1/agentic-commerce/notifications` | `notifications` | Webhook body for enrollment, intent, or payment-credential status. |
| `POST /payments/digital/v1/agentic-commerce/unenrollments` | `unenroll` | Unenroll an account. |

Every operation lists the headers `Authorization`, `trackingId`, `agentId`, and `Content-Type`. `agentId` is required. `intentId` is also a required path parameter on PUT and DELETE.

## Create intent

`IntentsRequest` requires `expirationTs`, `shipment`, and `agent`. The initial create body also requires `enrollmentId`, `prompt`, `spendControl`, `risk`, and `purchaseDecision`. A step-up follow-up is a different body: `enrollmentId` and `stepUpVerification` only.

| AmEx key | Where the document says it | KATA field | Fit |
| --- | --- | --- | --- |
| `intentId` | Required string on the create and update responses. Path parameter on PUT and DELETE. Not a property of `IntentsRequest`. | `agreement_id`, also copied to `intent.intent_id`. `mandate_id` is that id plus `.v1` | The response id is the lifecycle key. `agreement_id` is the stable KATA id. The `.v1` suffix is a draft. |
| `prompt.promptSummary` | Required string. A summary of the purchase intent derived from user input. | `intent.natural_language_source` | The key is published. The KATA placement is assumed. |
| `prompt.nlpConfidence` | Number from 0 to 1. Not required. | None | Left on the preserved record. |
| `spendControl.maxAmount` | Required string. The maximum amount that can be charged using the payment method. | `intent.maximum_amount` and `limits.per_transaction_maximum` | A decimal string is read as a major-unit number. Scale is not published. Item `purchaseCriteria.maxAmount` is a different property. |
| `spendControl.currency` | Required string, ISO 4217, on the same object. | `intent.currency` and `limits.currency` | `orderContext.currency`, `items[].currency`, and `purchaseCriteria.currency` are separate. The mapper uses the spend-control currency. |
| `expirationTs` | Required on the intent. Format `date-time`. The intent expiration in ISO 8601. | `intent.time_limit` and mandate `expires_at` | `spendControl.expirationTs` is a different property: the payment-method expiration. It is not required, and it is not this binding. |
| `maxAllowedTransactions` | Optional string. The maximum allowed transactions the user authorized to complete the purchase. | `limits.frequency.max_count`, with `per` set to `agreement` | The wire value is a string. KATA stores an integer count of recorded charges. `requestedPaymentCredentialsCount` on the credential request is a different integer and defaults to 1. |
| `orderContext.merchants[].name` | String. The merchant's display or registered name. Not marked required. | Strings in `intent.merchant_constraints` | `merchantId` is an integer. `categoryName` stays on the preserved record so it is not treated as an allowlist entry. |
| `orderContext.items[].purchaseCriteria` | Array on each item. `type` is `PRICE` or `DATE`. | `fromDate` to `not_before`, and `toDate` to the end instants only when `expirationTs` was absent, and only when `type` is `DATE` | The October reading put `purchaseCriteria` on `orderContext`. This document nests it under each item. |

`purchaseCriteria` for `DATE` requires `fromDate` and `toDate`, both `date-time`. For `PRICE` it requires `pricePreference`: `MINIMUM_PRICE`, `BETWEEN_RANGE`, or `MAXIMUM_PRICE`. `maxAmount` and `minAmount` on a criterion are required when `pricePreference` is `BETWEEN_RANGE`. Those price strings are not `spendControl.maxAmount`.

## Edit and cancel

PUT `/payments/digital/v1/agentic-commerce/intents/{intentId}` updates an intent. The description says updates are limited to supported parameters such as maximum amount and expiration. To modify other attributes, the existing intent must be cancelled and a new intent created. The body matches the create shape, including the same step-up follow-up. The response is `IntentsResponse`.

DELETE `/payments/digital/v1/agentic-commerce/intents/{intentId}` cancels an intent. The 200 response has no body schema. KATA's edit is a new signed mandate version. KATA's `revoke` accepts the principal key that signed. This mapper does not build either operation.

## purchaseDecision

`purchaseDecision` is a string on the initial create, the initial update, and the initial payment-credential request. The enum is `NON-DELEGATED` and `DELEGATED`, in that order. The description says `NON-DELEGATED` means the purchase is executed with explicit Card Member approval at the time of the transaction, and `DELEGATED` means execution is delegated to an agent. The property is required on the initial intent body. It is not mapped. KATA has no field with those two tokens.

## intentStatus

`intentStatus` is not one enum.

| Where | Tokens |
| --- | --- |
| Create and update response before step-up (`IntentsResponseBeforeStepUp`) | `PENDING_STEP_UP` only |
| Create and update response after step-up (`IntentsResponseAfterStepUp`) | `ACTIVE` only |
| Notification `notificationType` `INTENT_UPDATE` | `ACTIVE` and `CANCEL` |

DELETE does not return `intentStatus`. `CANCEL` is the notification token, not a create-response token. The mapper does not copy `intentStatus` onto `agreement.status`. The scaffold value `proposed` is a KATA draft marker.

## Step-up

Create, update, enrollment, and payment credentials each describe a two-step exchange.

1. The first intent request sends the intent body, including `risk` and `purchaseDecision`.
2. The before-step-up response has `stepUpAuthenticationRequired` (`YES` or `NO`), `enrollmentId`, `intentId`, `intentStatus` `PENDING_STEP_UP`, `stepUpSessionId`, and `availableChallenges`.
3. The follow-up intent body in the schema is `enrollmentId` plus `stepUpVerification`. `stepUpVerification` requires `stepUpSessionId` and one challenge result: SafeKey `riskToken`, issuer-surface `authenticationToken`, secure-push `authenticationToken`, or an OTP `value`.
4. The after-step-up response has `enrollmentId`, `intentId`, `intentStatus` `ACTIVE`, and `proofOfIntent`.

Challenge `type` values are `ISSUER_SURFACE`, `SECURE_PUSH`, `SAFEKEY`, `SMS_OTP`, and `EMAIL_OTP`.

The payment-credential follow-up is different. Its required properties are `proofOfIntent` and `stepUpVerification`. The description of `proofOfIntent` there is a signed JSON Web Token received as part of the create-intent response.

The create-intent description says the follow-up is made with the intent identifier and the step-up verification details. The follow-up schema does not include `intentId`. The identifier is on the before-step-up response and on the PUT and DELETE path.

## Order context and Cart Context

`orderContext.type` is `INTENT` or `CART`.

| Token | Document description |
| --- | --- |
| `INTENT` | A preliminary selection or preference. |
| `CART` | A finalized set of items ready for purchase. |

`CART` is the cart stage inside this file. The company page's separate Cart Context specification was not in the download. This note treats `orderContext.type` `CART` as the published cart marker in the Agentic Commerce document, and it does not invent fields from an unopened Cart Context specification. The mapper leaves `type` on the preserved record. KATA has no order-context type.

`orderContext` also has `merchants`, `totalAmount`, `currency`, `orderId`, `allowPartialOrder` (`YES` or `NO`), and either `items` or `airlineItems`.

Item properties in `Items` include `itemId` (required string), `merchantId` (integer), `name` (required), `unitAmount` (string), `currency` (ISO 4217, required when `unitAmount` is set), `quantity`, `condition`, `category`, `brand`, `imageLink`, `isRefundable` (`YES` or `NO`), `isGiftCard` (`YES` or `NO`, required), `isRecurBill` (`YES` or `NO`), `purchaseCriteria`, and string `metadata`. The October pictures used `itemReferenceId` and `merchantReferenceId`. Those names are not in this schema.

Merchant properties are `name`, `merchantId` (integer), `url`, `appName`, `seNumber`, `categoryName`, and string `metadata`. The merchant item lists no required array.

## Agent, principal, proof of intent, purpose

`agent` is required on the intent. Its required properties are `agentName`, `llmPlatform`, and `llmVersion`. `llmPlatform` is the enum `OPEN_AI` only. The `agentId` header is a separate required string. KATA `agent` requires `agent_id` and a public-key fingerprint. The gap stays, because those AmEx fields are not that object. The create-intent example sets `llmPlatform` to `AI_PLATFORM`, which is outside the enum.

`enrollmentId` is the enrolled account id. The intent `user` object carries `firstName`, `lastName`, a billing address, and email or phone, plus `userEmailHash` and `userPhoneNumberHash` (`PBKDF2WithHmacSHA256`, 10 iterations). KATA `principal` requires `type`, `id`, and the signing public key. The gap stays.

`proofOfIntent` is a string. On the after-step-up intent response and on `INTENT_UPDATE` notifications the description is a signed JSON Web Token associated with the intent. The schema does not publish claims or an algorithm. One example on the payment-credentials request decodes to header `alg` `RS256`, `kid` `intent-key-1`, `typ` `JWT`, and a payload with `iss`, `sub`, `intentId`, `merchantId`, `amount`, `currency`, `scope`, `iat`, and `exp`. The signature segment decodes to the text `signature_placeholder`. A nested example token uses `alg` `RS256` and payload `sub` `user_id`, and its signature segment is the text `signature`. Those are placeholders. The mapper does not produce a KATA JWS.

KATA requires `intent.purpose`. The OpenAPI document has no purpose field.

## Differences found in the file

These are places where a short field list and the downloaded document disagree. The document wins.

- The title in the file includes the words "American Express" and the suffix `(1.0.0)`. `x-lastUpdated` is the string `April 28, 2026`, not an ISO date.
- Eight operations sit on seven paths. PUT and DELETE share `/payments/digital/v1/agentic-commerce/intents/{intentId}`.
- `intentStatus` on create and update is `PENDING_STEP_UP` or `ACTIVE`. `ACTIVE` and `CANCEL` are the `INTENT_UPDATE` notification tokens. DELETE 200 has no body.
- `purchaseDecision` is ordered `NON-DELEGATED`, then `DELEGATED`.
- Two properties are named `expirationTs`. The intent-level one is required. `spendControl.expirationTs` is the payment-method expiration and is not required.
- `proofOfIntent` is an unconstrained string. Claims and `alg` are not schema constraints. The only concrete tokens are placeholder examples, including `RS256`.
- `agent.llmPlatform` allows `OPEN_AI` only. The create-intent example uses `AI_PLATFORM`.
- The create follow-up schema has `enrollmentId` and `stepUpVerification`. It does not contain `intentId`, despite the operation description.
- `INTENT_UPDATE` notifications require `notificationType`, `enrollmentId`, `intentStatus`, and `proofOfIntent`. They do not include `intentId`.
- `merchants[].name` is not marked required. Item identity is `itemId`. Merchant identity on both objects is `merchantId`, an integer.
- `isRefundable` and `isRecurBill` are `YES` or `NO`. `isGiftCard` is required and uses the same tokens. `pricePreference` is `MINIMUM_PRICE`, `BETWEEN_RANGE`, or `MAXIMUM_PRICE`.
- The `SECURE_PUSH` challenge object lists `url` and `riskToken` as required, and its properties only define `authenticationToken`.
- `IntentsRisk` requires `device` and `order`. The create-intent example omits `order`.

## Verified

- The OpenAPI document at the URL above, read 18 October 2026, is OpenAPI 3.1.0, document version `1.0.0`, `x-lastUpdated` April 28, 2026, with the SHA-256 in the table. It contains 8 operations and 64 schemas.
- `intentId` is on the create and update responses and is the PUT and DELETE path parameter.
- `prompt.promptSummary` and `prompt.nlpConfidence` are the prompt properties. `promptSummary` is required.
- `spendControl.maxAmount` and `spendControl.currency` are required strings. `spendControl.expirationTs` is a separate date-time.
- Intent `expirationTs` is a required date-time.
- `maxAllowedTransactions` is a string.
- `purchaseCriteria` is under `orderContext.items[]`, with `type` `PRICE` or `DATE`.
- `orderContext.merchants[].name` is published.
- `orderContext.type` is `INTENT` or `CART`, with the descriptions in the table above.
- `purchaseDecision` is `NON-DELEGATED` or `DELEGATED`.
- `intentStatus` tokens are the ones in the intentStatus table. `CANCEL` is on the intent notification, not on the create response.
- PUT is the edit operation. DELETE is the cancel operation. The PUT description limits updates to parameters such as maximum amount and expiration.
- The step-up flow and the five challenge types are the ones in the step-up section.
- `agent` requires `agentName`, `llmPlatform`, and `llmVersion`. The `agentId` header exists and is required. `llmPlatform` is `OPEN_AI`.
- `enrollmentId` and the intent user object exist. `proofOfIntent` is a signed JWT string whose claims and algorithm are not in the schema. No purpose property exists.
- KATA amounts are major units. The mandate signature in this repository is a flattened JWS, `EdDSA` or `ES256`. Those sentences are from this repository's agreement document, not from American Express.

## Assumed

- `agreement_id` carries `intentId`. The document does not name a KATA field. `intent_id` is a copy. `mandate_id` adds `.v1`.
- `prompt.promptSummary` is stored on `natural_language_source`.
- `spendControl.maxAmount` is the per-transaction ceiling `maximum_amount`, also copied to `limits.per_transaction_maximum`. It might instead be read as `limits.cumulative_maximum`. The document says it is the maximum that can be charged using the payment method.
- `spendControl.currency` is the intent currency and the limits currency. A mix of item currencies is not resolved.
- `maxAllowedTransactions` is `limits.frequency.max_count` over the whole mandate. The counters differ: authorized transactions versus recorded charges. The window `agreement` is not in the document.
- Merchant names are an allowlist. `categoryName` is not.
- The first item's first `DATE` criterion writes `fromDate` to `not_before`. `toDate` fills the end instants only when `expirationTs` is absent.
- A passkey, a `proofOfIntent` JWT, and a KATA principal signature are not the same ceremony. This note does not treat the placeholder `RS256` example as a KATA algorithm.
- `agreement.status` `proposed`, the empty ledger, and version `1` are scaffolds. AmEx `intentStatus` is not that status.
- `schemaVersion`, when present, is echoed. `1.0.0` matches `info.version` and is still assumed, because the property is not in the request schema.

## Not accessible

- The JWE encryption of the request body: key agreement, `enc`, and `alg` for the payload encryption. The JSON schema is the decrypted model.
- A normative `proofOfIntent` header, `alg`, `kid` registry, and claim names. The examples are placeholders.
- Who signs `proofOfIntent`: the issuer, the user, the agent, or a wallet.
- Whether DELETE invalidates a payment credential that was already issued. The 200 response has no body.
- A purpose string, a KATA principal public key, and a KATA agent public key.
- Unit scale for `spendControl.maxAmount`, `unitAmount`, and the criterion amounts.
- The separate Cart Context specification named on the company page. `orderContext.type` `CART` is what this file publishes.
- Agent Registration, beyond the `agent` object and the `agentId` header in this file.
