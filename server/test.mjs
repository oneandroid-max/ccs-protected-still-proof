// node --test server/test.mjs
// Exercises the licence server's own logic (sessions, binding, policy, revocation, audit, CORS)
// with the licence environment replaced by a stand-in that records what it was asked.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64url, createApp, memoryStore, mintToken, verifyToken } from "./licence-core.mjs";

const ORIGIN = "https://oneandroid-max.github.io";
const ENV = { TOKEN_SECRET: "test-secret", ADMIN_KEY: "admin-key", VIEWERS: "48213:Family A:ccs-proof-pin48213,77310:Family B:ccs-proof-pin48213", ALLOWED_ORIGINS: ORIGIN, LICENCE_LIMIT_PER_SESSION: "2", SESSION_SECONDS: "600" };
const CERT_REQUEST = new Uint8Array([0x08, 0x04]);
const CHALLENGE = new Uint8Array([0x08, 0x01, 0x12, 0x03, 0xaa, 0xbb, 0xcc]);

function harness(overrides = {}) {
  const calls = [];
  let clock = 1_000_000;
  let ids = 0;
  const deps = {
    now: () => clock,
    newId: () => "sid-" + ++ids,
    signAndForward: async (cfg, req) => {
      calls.push({ cfg, req });
      if (overrides.delayMs) await new Promise((r) => setTimeout(r, overrides.delayMs));
      if (overrides.forwardThrows) throw new Error("boom");
      const isCert = req.challenge.length === 2 && req.challenge[0] === 0x08 && req.challenge[1] === 0x04;
      return isCert
        ? { status: "OK", licence: new Uint8Array([0x08, 0x05, 0xff]), device: null }
        : { status: overrides.status || "OK", licence: overrides.status ? null : new Uint8Array([1, 2, 3]), device: { securityLevel: 1, make: "samsung", model: "SM-TEST", certSerial: "abc" } };
    },
  };
  const store = overrides.store || memoryStore();
  const app = createApp({ ...ENV, ...(overrides.env || {}) }, store, deps);
  const call = (method, path, { headers = {}, body, origin = ORIGIN, ip = "203.0.113.7" } = {}) =>
    app.handle(new Request("https://licence.example" + path, { method, headers: { Origin: origin, ...headers }, body }), { ip });
  const session = async (pin = "48213", asset = "ccs-proof-pin48213", ip) => (await call("POST", "/session", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin, asset }), ip })).json();
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
  assert.equal((await h.call("POST", "/session", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin: "48213", asset: "ccs-proof-pin48213" }) })).status, 403);
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

test("CORS: with no ALLOWED_ORIGINS configured, no origin is allowed", async () => {
  const h = harness({ env: { ALLOWED_ORIGINS: "" } });
  const res = await h.call("OPTIONS", "/licence", { headers: { "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-viewer-token" } });
  assert.equal(res.headers.get("access-control-allow-origin"), null);
  const post = await h.call("POST", "/session", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin: "48213", asset: "a" }) });
  assert.equal(post.headers.get("access-control-allow-origin"), null);
});

test("policy: refused licences do not use up the session's licences (the player retries each failure)", async () => {
  const h = harness({ status: "INVALID_LICENSE_CHALLENGE" });
  const s = await h.session();
  for (let i = 0; i < 3; i++) {
    const res = await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
    assert.equal(res.status, 403, "attempt " + (i + 1) + " must be a refusal, not the limit");
  }
  assert.equal(h.calls.length, 3, "every attempt reached the licence environment");
});

test("admin: the key is accepted only in the header, never in the address", async () => {
  const h = harness();
  assert.equal((await h.call("GET", "/audit?key=admin-key")).status, 401);
  assert.equal((await h.call("GET", "/audit", { headers: { "x-admin-key": "admin-key" } })).status, 200);
});

test("size: a body over the cap is refused, declared or not, and never forwarded", async () => {
  const h = harness();
  const s = await h.session();
  const big = new Uint8Array(70_000);
  const undeclared = await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: big });
  assert.equal(undeclared.status, 413);
  const declared = await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token, "content-length": "999999" }, body: CHALLENGE });
  assert.equal(declared.status, 413);
  const bigSession = await h.call("POST", "/session", { headers: { "content-type": "application/json" }, body: JSON.stringify({ pin: "48213", asset: "x".repeat(70_000) }) });
  assert.equal(bigSession.status, 413);
  assert.equal(h.calls.length, 0);
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

const sessionBody = (pin, asset) => ({ headers: { "content-type": "application/json" }, body: JSON.stringify({ pin, asset }) });

test("binding: a PIN opens only its own photos, and the one answer does not say why", async () => {
  const h = harness({ env: { VIEWERS: "48213:Family A:photo-a|photo-shared,77310:Family B:photo-b" } });
  const own = await h.call("POST", "/session", sessionBody("48213", "photo-a"));
  assert.equal(own.status, 200);
  const other = await h.call("POST", "/session", sessionBody("48213", "photo-b"));
  const unknown = await h.call("POST", "/session", sessionBody("99999", "photo-a"));
  assert.equal(other.status, 403);
  assert.equal(unknown.status, 403);
  assert.deepEqual(await other.json(), await unknown.json(), "a wrong photo and an unknown PIN read the same");
  const s = await own.json();
  await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
  assert.equal(new TextDecoder().decode(h.calls[0].req.contentId), "photo-a");
});

test("binding: a viewer taken out of VIEWERS is refused at once, with a token minted before", async () => {
  const before = harness();
  const s = await before.session("77310");
  const after = harness({ env: { VIEWERS: "48213:Family A:ccs-proof-pin48213" } });
  assert.equal((await after.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })).status, 403);
  assert.equal((await after.call("GET", "/session/audit", { headers: { "x-viewer-token": s.token } })).status, 403);
  assert.equal(after.calls.length, 0);
});

test("limits: wrong PINs from one caller pause that caller, not others, and the pause ends", async () => {
  const h = harness();
  for (let i = 0; i < 10; i++) assert.equal((await h.call("POST", "/session", { ...sessionBody("1000" + i, "ccs-proof-pin48213"), ip: "198.51.100.1" })).status, 403);
  assert.equal((await h.call("POST", "/session", { ...sessionBody("48213", "ccs-proof-pin48213"), ip: "198.51.100.1" })).status, 429, "even the right PIN waits");
  assert.equal((await h.call("POST", "/session", { ...sessionBody("48213", "ccs-proof-pin48213"), ip: "198.51.100.2" })).status, 200, "another caller is not paused");
  h.advance(600);
  assert.equal((await h.call("POST", "/session", { ...sessionBody("48213", "ccs-proof-pin48213"), ip: "198.51.100.1" })).status, 200);
});

test("limits: sessions per PIN per hour", async () => {
  const h = harness({ env: { SESSIONS_PER_PIN_PER_HOUR: "3" } });
  for (let i = 0; i < 3; i++) assert.equal((await h.call("POST", "/session", sessionBody("48213", "ccs-proof-pin48213"))).status, 200);
  assert.equal((await h.call("POST", "/session", sessionBody("48213", "ccs-proof-pin48213"))).status, 429);
  assert.equal((await h.call("POST", "/session", sessionBody("77310", "ccs-proof-pin48213"))).status, 200, "another PIN is not limited");
  h.advance(3600);
  assert.equal((await h.call("POST", "/session", sessionBody("48213", "ccs-proof-pin48213"))).status, 200);
});

test("limits: one token cannot drive unlimited calls to the licence environment", async () => {
  const h = harness({ status: "INVALID_LICENSE_CHALLENGE" });
  const s = await h.session();
  const statuses = [];
  for (let i = 0; i < 8; i++) statuses.push((await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })).status);
  assert.deepEqual(statuses, [403, 403, 403, 403, 403, 403, 429, 429], "three times the licence limit, then refused");
  assert.equal(h.calls.length, 6);
});

test("limits: simultaneous licence requests cannot pass the licence limit together", async () => {
  const h = harness({ delayMs: 5 });
  const s = await h.session();
  const all = await Promise.all(Array.from({ length: 10 }, () => h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })));
  const statuses = all.map((r) => r.status).sort();
  assert.equal(statuses.filter((x) => x === 200).length, 2, "exactly the limit is issued: " + statuses.join(","));
  assert.equal(h.calls.length, 2, "the others never reach the licence environment");
});

test("limits: calls to the licence environment per PIN per day, across sessions", async () => {
  const h = harness({ env: { FORWARDS_PER_PIN_PER_DAY: "3" } });
  const statuses = [];
  for (let i = 0; i < 4; i++) {
    const s = await h.session();
    statuses.push((await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })).status);
  }
  assert.deepEqual(statuses, [200, 200, 200, 429]);
  const b = await h.session("77310");
  assert.equal((await h.call("POST", "/licence", { headers: { "x-viewer-token": b.token }, body: CHALLENGE })).status, 200, "another PIN is not limited");
});

test("audit: other sessions cannot push a viewer's own rows out, and the stored origin is capped", async () => {
  const h = harness({ env: { AUDIT_KEEP: "5", SESSIONS_PER_PIN_PER_HOUR: "1000" } });
  const mine = await h.session();
  await h.call("POST", "/licence", { headers: { "x-viewer-token": mine.token }, body: CHALLENGE });
  for (let i = 0; i < 20; i++) await h.session("77310");
  const a = await (await h.call("GET", "/session/audit", { headers: { "x-viewer-token": mine.token } })).json();
  assert.deepEqual(a.rows.map((r) => r.event), ["session", "licence"]);
  const longOrigin = "https://" + "x".repeat(5000) + ".example";
  await h.call("POST", "/session", { ...sessionBody("48213", "ccs-proof-pin48213"), origin: longOrigin });
  const all = await (await h.call("GET", "/audit", { headers: { "x-admin-key": "admin-key" } })).json();
  assert.ok(all.rows.every((r) => !r.origin || r.origin.length <= 200));
});

test("size: an undeclared, endless body is abandoned at the cap instead of being read whole", async () => {
  const h = harness();
  const s = await h.session();
  let pulled = 0;
  const endless = new ReadableStream({ pull(controller) { pulled++; controller.enqueue(new Uint8Array(16 * 1024)); } });
  const req = new Request("https://licence.example/licence", { method: "POST", headers: { Origin: ORIGIN, "x-viewer-token": s.token }, body: endless, duplex: "half" });
  const res = await Promise.race([h.app.handle(req, { ip: "203.0.113.7" }), new Promise((r) => setTimeout(() => r({ status: "timed out" }), 3000))]);
  assert.equal(res.status, 413);
  assert.ok(pulled <= 8, "read only a little past the cap, pulled " + pulled + " chunks of 16 KB");
  assert.equal(h.calls.length, 0);
});

test("revocation by session stops that session only", async () => {
  const h = harness();
  const a = await h.session();
  const b = await h.session();
  const rev = await h.call("POST", "/revoke", { headers: { "content-type": "application/json", "x-admin-key": "admin-key" }, body: JSON.stringify({ sid: a.sid }) });
  assert.equal(rev.status, 200);
  assert.equal((await h.call("POST", "/licence", { headers: { "x-viewer-token": a.token }, body: CHALLENGE })).status, 403);
  assert.equal((await h.call("POST", "/licence", { headers: { "x-viewer-token": b.token }, body: CHALLENGE })).status, 200);
});

test("policy: the licence duration is sent to the licence environment", async () => {
  const h = harness({ env: { LICENCE_DURATION_SECONDS: "900" } });
  const s = await h.session();
  assert.equal(s.licenceDurationSeconds, 900);
  await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
  assert.deepEqual(h.calls[0].req.policy, { licenceDurationSeconds: 900 });
});

test("record: each row says what happened, when by the server's clock, and for whom", async () => {
  const h = harness();
  const s = await h.session();
  h.advance(5);
  await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CERT_REQUEST });
  await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
  await h.call("POST", "/revoke", { headers: { "content-type": "application/json", "x-admin-key": "admin-key" }, body: JSON.stringify({ sid: s.sid }) });
  await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
  const rows = (await (await h.call("GET", "/audit", { headers: { "x-admin-key": "admin-key" } })).json()).rows;
  assert.deepEqual(rows.map((r) => [r.event, r.at]), [["session", 1_000_000], ["certificate", 1_000_005], ["licence", 1_000_005], ["revoked", 1_000_005], ["licence-refused", 1_000_005]]);
  const cert = rows[1], lic = rows[2], refused = rows[4];
  assert.equal(cert.device, null);
  assert.equal(lic.viewer, "Family A");
  assert.equal(lic.device.model, "SM-TEST");
  assert.equal(refused.reason, "revoked");
});

test("the licence response carries the device facts, readable by the allowed page", async () => {
  const h = harness();
  const s = await h.session();
  const cert = await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CERT_REQUEST });
  assert.equal(cert.headers.get("x-licence-device"), null, "not on the certificate answer");
  const lic = await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE });
  assert.deepEqual(JSON.parse(decodeURIComponent(lic.headers.get("x-licence-device"))), { securityLevel: 1, make: "samsung", model: "SM-TEST", certSerial: "abc" });
  assert.match(lic.headers.get("access-control-expose-headers"), /x-licence-device/);
});

test("a store that cannot write does not stop a licence, but does stop a revocation from claiming success", async () => {
  const broken = memoryStore();
  broken.putAudit = async () => { throw new Error("quota"); };
  broken.addLicence = async () => { throw new Error("quota"); };
  const h = harness({ store: broken });
  const s = await h.session();
  assert.ok(s.token, "session still issued");
  assert.equal((await h.call("POST", "/licence", { headers: { "x-viewer-token": s.token }, body: CHALLENGE })).status, 200);
  await assert.rejects(h.call("POST", "/revoke", { headers: { "content-type": "application/json", "x-admin-key": "admin-key" }, body: JSON.stringify({ pin: "48213" }) }), /quota/);
});
