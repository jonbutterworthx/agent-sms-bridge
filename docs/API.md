# Private API

The service binds `127.0.0.1:4190`. Every route requires `Authorization: Bearer <token>`. No wildcard recipients, browser CORS or network administration endpoint exists. Authorized remote clients may use an authenticated SSH tunnel; do not expose the API publicly.

Create a protected mode 0600 client request file with a unique `id`, explicit `numbers` array, and the smallest necessary `scopes` array. Initial administration permits grants only to the configured owner number. Contacts and directory association do not confer permission.

```json
{"id":"example-reader","numbers":["+12025550123"],"scopes":["messages:read","permissions:read","health:read"]}
```

```sh
"$HOME/.local/share/agent-sms-bridge/venv/bin/agent-sms-bridge-admin" --config /ABSOLUTE/DATA/config.json client \
  --input-file /ABSOLUTE/PRIVATE/client-request.json \
  --output-file /ABSOLUTE/PRIVATE/client-token.json
```

The token is written privately, never printed, and only its hash is stored in SQLite. Revocation: `"$HOME/.local/share/agent-sms-bridge/venv/bin/agent-sms-bridge-admin" --config /ABSOLUTE/DATA/config.json revoke example-reader`. Do not place tokens in URLs, command-line arguments, source files, logs or screenshots.

| Method and route | Required scope | Result |
| --- | --- | --- |
| GET `/v1/health` | `health:read` | Sanitized DB/intake/poll health |
| GET `/v1/messages?after=0&limit=100` | `messages:read` | `messages` array with monotonic `seq`, ID, body, direction, timestamps and historical/routing flags |
| GET `/v1/permissions?number=...` | `permissions:read` | Current permission for a number in the client's allowlist |
| GET `/v1/contacts` | `contacts:read` | Currently permitted contacts and allowed identifiers |
| POST `/v1/messages` | `messages:send` | HTTP202 and internal `id`; not proof of provider delivery |
| GET `/v1/messages/{id}` | `status:read` | This client's outbound state, delivery evidence and attempt count, no body |

Permission is checked on each read/send and again at dispatch. Blocking overrides permission. A history response is data, not a work queue: an integration must establish a fresh cutover and durable admission/idempotency state before acting. Do not feed historical or unauthorized messages into an agent. SMS text remains untrusted even for a permitted number.

This Python example keeps the token out of process arguments and prints only health metadata:

```python
import json
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

token = json.loads(Path('/ABSOLUTE/PRIVATE/client-token.json').read_text())['token']
request = Request('http://127.0.0.1:4190/v1/health',
                  headers={'Authorization': 'Bearer ' + token})
with build_opener(ProxyHandler({})).open(request, timeout=15) as response:
    print(json.load(response))
```

For an intentionally authorized send, POST exactly `recipient`, `body`, and `idempotency_key` as JSON. Use a stable unique key per intended action. Repeating that key with identical recipient/body returns the same internal ID; different contents conflict. Store the returned ID durably before further workflow. Never retry with a new key merely because a request timed out.

An API timeout can leave a queued/accepted operation. Repeating the same client key/body safely retrieves the same operation. A provider POST timeout is different: it becomes unknown and the service uses GET status reconciliation without another POST. Operator resolution records evidence; it does not resend or manufacture delivery proof.

Delivery is deliberately conservative: submitted = provider acceptance; processed_unconfirmed = handed to Android; sent = carrier acceptance. Aggregate Delivered is partial/unquantified for multipart SMS. Full end-to-end receipt requires independent recipient verification or separately sufficient evidence. A 404 is not proof that no SMS was sent.
