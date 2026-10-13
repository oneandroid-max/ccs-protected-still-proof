# The licence server (ours)

This replaces the public proxy in the proof. The page asks it for a viewer session, then sends
the phone's licence challenge to it with that session's token. The server decides whether this
viewer may have a licence for this asset, forwards the challenge to the licence environment with
our signer, records what the environment reported about the device, and returns the licence.

In the proof the licence environment is Google's public Widevine test environment with the
published test signer, so no account of ours is involved. Production points the same code at the
production environment with the owner's own signer; nothing else changes.

## Endpoints

| Method and path | Who | What |
|---|---|---|
| `POST /session` `{pin, asset}` | the page | a token bound to the PIN and the asset, valid `SESSION_SECONDS` |
| `POST /licence` (body: challenge bytes, header `x-viewer-token`) | the player | the licence bytes, or 401/403/429 |
| `GET /session/audit` (header `x-viewer-token`) | the page | what the server recorded for this session, device facts included |
| `GET /audit?pin=` (header `x-admin-key`) | us | the whole log |
| `POST /revoke` `{pin}` or `{sid}` (header `x-admin-key`) | us | cut a viewer off; their live token stops at the next licence request |
| `GET /health` | anyone | which licence environment and signer are configured |

## Run

Node 22, no dependencies:

```
TOKEN_SECRET=... ADMIN_KEY=... VIEWERS="48213:Family A" ALLOWED_ORIGINS=https://oneandroid-max.github.io node server/node.mjs
```

Tests: `node --test server/test.mjs`.

Cloudflare Worker: `server/wrangler.toml` has the steps.

## Files

- `licence-core.mjs` — all logic; Fetch API and WebCrypto only, so it runs on Node and on Workers.
- `widevine-uat.mjs` — the one call to the licence environment: sign the request with our signer,
  forward the challenge, parse the response.
- `node.mjs`, `worker.mjs` — the two thin hosts.
- `test.mjs` — the logic under test with the licence environment stood in.
