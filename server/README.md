# The licence server (ours)

This replaces the public proxy in the proof. The page asks it for a viewer session, then sends
the phone's licence challenge to it with that session's token. The server decides whether this
viewer may have a licence for this photo, forwards the challenge to the licence environment with
our signer, records what the environment reported about the device, and returns the licence.

In the proof the licence environment is Google's public Widevine test environment with the
published test signer, so no account of ours is involved. For production, the licence URL and the
signer become the owner's own, and three things this proof keeps simple need replacing: VIEWERS
(a fixed list) becomes the gallery's own PIN store, the request limits move to the host's own rate
limiting (on a Worker the in-memory limits below count per isolate), and the content keys come from
the owner's key service instead of Google's test key server.

## Endpoints

| Method and path | Who | What |
|---|---|---|
| `POST /session` `{pin, asset}` | the page | a token bound to the PIN and a photo that PIN may open, valid `SESSION_SECONDS` |
| `POST /licence` (body: challenge bytes, header `x-viewer-token`) | the player | the licence bytes, or 401/403/413/429 |
| `GET /session/audit` (header `x-viewer-token`) | the page | what the server recorded for this session, device facts included |
| `GET /audit?pin=` (header `x-admin-key`) | us | the whole log |
| `POST /revoke` `{pin}` or `{sid}` (header `x-admin-key`) | us | cut a viewer off; their live token stops at the next licence request (on a Worker, within about a minute everywhere) |
| `GET /health` | anyone | which licence environment and signer are configured |

An unknown PIN, a revoked PIN and a photo the PIN may not open all get the same refusal, so the
answer does not tell a guesser which one it hit.

The server, not the phone, decides which photo's key goes into a licence: the licence environment
issues the keys for the content id the server sends, which is the photo bound to the viewer's
session (measured 2026-10-14). That is why a PIN opens only the photos listed with it.

The licence response also carries `X-Licence-Device`: the device facts the licence environment
reported, URL-encoded JSON, so the page can show them without a second request.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `TOKEN_SECRET`, `ADMIN_KEY` | secrets; long random strings | required |
| `VIEWERS` | `PIN:Name:photo|photo,PIN:Name:photo`; a PIN opens only the photos listed with it | required, a secret |
| `ALLOWED_ORIGINS` | sites whose pages may call the server; none listed means none allowed | none |
| `LICENCE_LIMIT_PER_SESSION` | licences issued per session; requests per session are capped at three times this | 20 |
| `SESSION_SECONDS`, `LICENCE_DURATION_SECONDS` | how long a session and a licence last | 3600, 600 |
| `FAILED_SESSIONS_PER_IP_PER_10_MIN` | wrong PINs from one caller before a ten-minute pause | 10 |
| `SESSIONS_PER_PIN_PER_HOUR`, `FORWARDS_PER_PIN_PER_DAY` | sessions, and calls to the licence environment, per PIN | 30, 200 |
| `AUDIT_FILE` (Node only) | append the audit log to this file and replay it on start | none |

Request bodies over 64 KB are refused without being read whole.

## Run

Node 22, no dependencies:

```
TOKEN_SECRET=... ADMIN_KEY=... VIEWERS="48213:Family A:ccs-proof-pin48213" ALLOWED_ORIGINS=https://oneandroid-max.github.io node server/node.mjs
```

Tests: `node --test server/*test.mjs` runs all of them, including one that starts the real Node host.

Cloudflare Worker: `server/wrangler.toml` has the steps. Measured on 2026-10-14 under Cloudflare's
own runtime (wrangler 4.148, local mode, KV bound) with live calls to Google's test licence
environment: the certificate request returned the same 714 bytes as the public proxy, a recorded
licence request returned a licence, garbage was refused, revocation held, and the size cap and the
origin check answered as on Node.

On Cloudflare's free plan, Workers KV allows 1,000 writes and 1,000 list calls a day
(developers.cloudflare.com/kv/platform/pricing). One page view writes four rows or counts, so the
plan carries about 250 views a day; past that the audit and the licence counts stop being written
(a licence is still issued, and the failure is logged), until the quota resets. A revocation is a
KV write too, and it reaches every Cloudflare location within about a minute.

## Files

- `licence-core.mjs` — all logic; Fetch API and WebCrypto only, so it runs on Node and on Workers.
- `widevine-uat.mjs` — the one call to the licence environment: sign the request with our signer,
  forward the challenge, parse the response.
- `node.mjs`, `worker.mjs` — the two thin hosts.
- `test.mjs`, `widevine-uat.test.mjs`, `worker.test.mjs`, `node-host.test.mjs` — the tests.
