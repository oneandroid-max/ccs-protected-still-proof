// node --test server/test.mjs
// Exercises the licence server's own logic (sessions, binding, policy, revocation, audit, CORS)
// with the licence environment replaced by a stand-in that records what it was asked.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64url, createApp, memoryStore, mintToken, verifyToken } from "./licence-core.mjs";

const ORIGIN = "https://oneandroid-max.github.io";
const ENV = { TOKEN_SECRET: "test-secret", ADMIN_KEY: "admin-key", VIEWERS: "48213:Family A,77310:Family B", ALLOWED_ORIGINS: ORIGIN, LICENCE_LIMIT_PER_SESSION: "2", SESSION_SECONDS: "600" };
const CERT_REQUEST = new Uint8Array([0x08, 0x04]);
const CHALLENGE = new Uint8Array([0x08, 0x01, 0x12, 0x03, 0xaa, 0xbb, 0xcc]);

function harness(overrides = {}) {
  const calls = [];
  let clock = 1_000_000;
  const deps = {
    now: () => clock,
    newId: () => "sid-" + (calls.length + 1),
    signAndForward: async (cfg, req) => {
      calls.push({ cfg, req });
      if (overrides.forwardThrows) throw new Error("boom");
      const isCert = req.challenge.length === 2 && req.challenge[0] === 0x08 && req.challenge[1] === 0x04;
      return isCert
        ? { status: "OK", licence: new Uint8Array([0x08, 0x05, 0xff]), device: null }
        : { status: overrides.status || "OK", licence: overrides.status ? null : new Uint8Array([1, 2, 3]), device: { securityLevel: 1, make: "samsung", model: "SM-TEST", certSerial: "abc" } };
    },
  };
  const app = createApp(ENV, memoryStore(), deps);
  const call = (method, path, { headers = {}, body, origin = ORIGIN } = {}) =>
    app.handle(new Request("https://licence.example" + path, { method, headers: { Origin: origin, ...headers }, body }));
  const session = async (pin = "48213") => (await call("POST", "/session", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin, asset: "ccs-proof-pin48213" }) })).json();
  return { app, call, session, calls, advance: (s) => { clock += s; } };
}

test("CORS: pre-flight from the page origin allows the viewer-token header; other origins get nothing", async () => {
  const h = harness();
  const ok = await h.call("OPTIONS", "/licence", { headers: { "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-viewer-token" } });
  assert.equal(ok.status, 204);
  assert.equal(ok.headers.get("access-control-allow-origin"), ORIGIN);
  assert.match(ok.headers.get("access-control-allow-headers"), /x-viewer-token/);
  const other = await h.call("OPTIONS", "/licence", { origin: "https://evil.example" });
  assert.equal(other.headers.get("access-control-allow-origin"), null);
});

test("session: unknown PIN refused; known PIN gets a token bound to pin + asset that verifies", async () => {
  const h = harness();
  const bad = await h.call("POST", "/session", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin: "00000", asset: "x" }) });
  assert.equal(bad.status, 403);
  const s = await h.session();
  assert.equal(s.viewer, "Family A");
  const claim = await verifyToken(ENV.TOKEN_SECRET, s.token, 1_000_000);
  assert.deepEqual({ pin: claim.pin, asset: claim.asset, sid: claim.sid }, { pin: "48213", asset: "ccs-proof-pin48213", sid: "sid-1" });
  assert.equal(await verifyToken("other-secret", s.token, 1_000_000), null);
  assert.equal(await verifyToken(ENV.TOKEN_SECRET, s.token, 1_000_000 + 601), null, "expired token must not verify");
});

test("licence: no token → 401; with token → licence bytes, forwarded with the asset as content id", async () => {
  const h = harness();
  const none = await h.call("POST", "/licence", { body: CHALLENGE });
  assert.equal(none.status, 401);
  const s = await h.session();
  const res = await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "application/octet-stream");
  assert.deepEqual(new Uint8Array(await res.arrayBuffer()), new Uint8Array([1, 2, 3]));
  assert.equal(h.calls.length, 1);
  assert.equal(new TextDecoder().decode(h.calls[0].req.contentId), "ccs-proof-pin48213");
  assert.deepEqual(h.calls[0].req.challenge, CHALLENGE);
  assert.equal(h.calls[0].cfg.signer, "widevine_test");
});

test("policy: the certificate request is free; licences stop at the per-session limit", async () => {
  const h = harness();
  const s = await h.session();
  const t = { "x-viewer-token": s.token };
  assert.equal((await h.call("POST", "/licence", { headers: t, body: CERT_REQUEST })).status, 200);
  assert.equal((await h.call("POST", "/licence", { headers: t, body: CHALLENGE })).status, 200);
  assert.equal((await h.call("POST", "/licence", { headers: t, body: CHALLENGE })).status, 200);
  const third = await h.call("POST", "/licence", { headers: t, body: CHALLENGE });
  assert.equal(third.status, 429);
  assert.equal((await h.call("POST", "/licence", { headers: t, body: CERT_REQUEST })).status, 200, "certificate requests are still answered");
});

test("audit: the viewer sees what the licence environment reported about their device", async () => {
  const h = harness();
  const s = await h.session();
  await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
  const a = await (await h.call("GET", "/session/audit", { headers: { "x-viewer-token": s.token } })).json();
  assert.equal(a.viewer, "Family A");
  const lic = a.rows.find((r) => r.event === "licence");
  assert.deepEqual(lic.device, { securityLevel: 1, make: "samsung", model: "SM-TEST", certSerial: "abc" });
  assert.equal(lic.pin, "48213");
  const admin = await h.call("GET", "/audit?pin=48213", { headers: { "x-admin-key": "admin-key" } });
  assert.equal(admin.status, 200);
  assert.equal((await admin.json()).rows.length, 2, "session + licence");
  assert.equal((await h.call("GET", "/audit")).status, 401);
});

test("revocation: a revoked PIN gets no new session and its live token stops working", async () => {
  const h = harness();
  const s = await h.session();
  assert.equal((await h.call("POST", "/revoke", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin: "48213" }) })).status, 401);
  const rev = await h.call("POST", "/revoke", { headers: { "content-type": "application/json", "x-admin-key": "admin-key" }, body: JSON.stringify({ pin: "48213" }) });
  assert.equal(rev.status, 200);
  assert.equal((await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })).status, 403);
  assert.equal((await h.call("POST", "/session", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin: "48213", asset: "a" }) })).status, 403);
  assert.equal((await h.session("77310")).viewer, "Family B", "other viewers unaffected");
});

test("expiry: a token past its session length is refused", async () => {
  const h = harness();
  const s = await h.session();
  h.advance(601);
  assert.equal((await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })).status, 401);
});

test("licence environment down → 502 and an audit row; denied → 403 with the status", async () => {
  const down = harness({ forwardThrows: true });
  const s = await down.session();
  assert.equal((await down.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })).status, 502);
  const a = await (await down.call("GET", "/session/audit", { headers: { "x-viewer-token": s.token } })).json();
  assert.ok(a.rows.some((r) => r.event === "licence-error"));
  const denied = harness({ status: "DEVICE_REVOKED" });
  const s2 = await denied.session();
  const res = await denied.call("POST", "/licence", { headers: { "x-viewer-token": s2.token }, body: CHALLENGE });
  assert.equal(res.status, 403);
  assert.equal((await res.json()).status, "DEVICE_REVOKED");
});

test("tokens: mint/verify round trip and tamper detection", async () => {
  const token = await mintToken("s", { sid: "a", pin: "1", asset: "x", exp: 10 });
  assert.deepEqual(await verifyToken("s", token, 5), { sid: "a", pin: "1", asset: "x", exp: 10 });
  const sig = token.split(".")[1];
  // A forged claim that is valid JSON (another viewer's PIN, a later expiry) carrying the real
  // signature of the original claim: only the signature check can reject it.
  const forgedBody = b64url(new TextEncoder().encode(JSON.stringify({ sid: "a", pin: "2", asset: "x", exp: 99 })));
  assert.equal(await verifyToken("s", forgedBody + "." + sig, 5), null, "forged claim with the old signature must be rejected");
  assert.equal(await verifyToken("s", "garbage", 5), null);
});
