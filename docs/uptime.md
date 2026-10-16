# Uptime

Global Agent Bureau is an agent bureau. This note is how to watch whether the service is answering.

## Probes

Poll both of these about once a minute from outside the host:

- `GET /health`
- `GET /v1/health`

Expect HTTP 200 and a JSON body whose `status` field is `ok`.

| `database` | Meaning |
| --- | --- |
| `ok` | The configured database answered `SELECT 1`. |
| `memory` | This process is using the in-memory store. A database URL is not in use. |
| `unavailable` | The database check failed. |

HTTP 503 with `status` set to `unavailable` means the database check failed. The body does not include the database address or the driver error.

The same reading is on the status page at `/status`.

## What to watch

Use an external uptime monitor that requests those paths over HTTPS. Alert when the status code is not 200, or when `status` is not `ok`, for two checks in a row. Once a minute is enough for a first customer. Do not send an API key on these requests. These probes return only `status` and `database`.
