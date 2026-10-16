# MCP

Global Agent Bureau is an agent bureau and a technology company. The license is PolyForm Noncommercial 1.0.0.

`POST /mcp` is a remote MCP server on the streamable HTTP transport. It exposes the bureau tools on top of the existing API. It does not keep a second copy of scores. A key that starts with `gab_test_` uses the sandbox partition on this branch: test rows do not change a production score.

## Protocol version

Verified on 16 October 2026 against protocol revision **2026-07-28**. Pages opened:

- https://modelcontextprotocol.io/specification/2026-07-28
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- https://modelcontextprotocol.io/specification/2026-07-28/server/discover
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- https://modelcontextprotocol.io/specification/2026-07-28/changelog

`server/discover` returns `supportedVersions: ["2026-07-28"]`. A different `MCP-Protocol-Version` receives HTTP 400 and JSON-RPC code `-32022` (`UnsupportedProtocolVersionError`) with that list. This revision has no `initialize` handshake and no protocol session. `GET` and `DELETE` on `/mcp` receive HTTP 405. `Mcp-Session-Id` and `Last-Event-ID` are ignored.

## Request shape

Each JSON-RPC message is its own `POST` with `Content-Type: application/json`. The response is one JSON object (`application/json`), not a long-lived event stream. These tools finish in that one object.

Required headers:

- `MCP-Protocol-Version: 2026-07-28`
- `Mcp-Method`, equal to the JSON-RPC `method`
- `Mcp-Name` on `tools/call`, equal to `params.name`

`params._meta` must include `io.modelcontextprotocol/protocolVersion` with the same value as the header. A mismatch is HTTP 400 and code `-32020` (`HeaderMismatch`).

`Accept` may list `application/json` and `text/event-stream`. A present `Accept` that allows neither `application/json` nor `*/*` is refused.

An `Origin` header must match the request host. A browser origin that does not match receives HTTP 403. Clients that omit `Origin` are accepted.

## Authentication

Send `Authorization: Bearer` and a bureau API key. `tools/list` and `tools/call` require that key. `server/discover` does not.

The MCP authorization section (OAuth 2.1, protected-resource metadata, RFC 9728) is optional in the spec. This server does not implement that OAuth flow. It accepts the bureau API keys that already exist. A missing or unknown key receives HTTP 401 and `WWW-Authenticate: Bearer`. A portal session is not an API key and is refused. The raw key is not written into the response, the audit row, or the log line.

A `gab_test_` key sets the sandbox test partition for that request. On a deployment with `GAB_ENV=sandbox`, a live key is refused with the same rule as the HTTP API.

`tools/list` returns only the tools the key's scopes allow. `verify_agent` needs `verify`, `inquire` needs `inquire`, and `report` needs `report`. `check_revocation` and `fetch_signed_receipt` are available to any API key.

## Tools

| Tool | What it does |
| --- | --- |
| `verify_agent` | Checks `action` against the stored intent agreement. Result is `ALLOW`, `DENY`, or `STEP_UP`. |
| `inquire` | Reads status, authorizations, revocation notes, incident counts, and the trust score for a purpose code. The read does not change the score. |
| `report` | Files `transaction_outcome`, `fraud_incident`, `chargeback`, or `policy_violation`. `evidence_hash` is `sha256:` and 64 hex characters. |
| `check_revocation` | Reads the public revocation list. Optional `agent_id` also returns that agent's status in this key's partition. |
| `fetch_signed_receipt` | Reads one signed transparency-log entry by `sequence`. A missing sequence returns a tool error: `a signed log entry is not available`. |

A business-rule failure (unknown agent, bad purpose code, missing evidence) is HTTP 200 with `result.isError: true`. An unknown tool name is HTTP 400 and code `-32602`.

## Limits

Tool requests share the HTTP rate limits. `verify_agent` counts toward `GAB_VERIFY_RATE_LIMIT_PER_MINUTE` (default 60). `inquire` counts toward `GAB_INQUIRY_RATE_LIMIT_PER_MINUTE` (default 30). `report` counts toward `GAB_REPORT_RATE_LIMIT_PER_MINUTE` (default 10). Every `POST /mcp` also counts toward `GAB_RATE_LIMIT_PER_MINUTE` (default 120). Over the limit the response is HTTP 429 and `rate limit exceeded`.

## Example

```http
POST /mcp HTTP/1.1
Authorization: Bearer YOUR_KEY
Accept: application/json, text/event-stream
Content-Type: application/json
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: inquire
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "inquire",
    "arguments": {
      "agent_id": "shopper-01",
      "purpose_code": "payment_authorization"
    },
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "example", "version": "1"},
      "io.modelcontextprotocol/clientCapabilities": {}
    }
  }
}
```

Replace `YOUR_KEY` with a key issued to your organization. Do not commit a real key.
