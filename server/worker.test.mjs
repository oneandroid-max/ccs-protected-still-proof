// node --test server/worker.test.mjs
// The Worker host's KV store and error path, against an in-memory stand-in for the KV binding that
// behaves like Workers KV where it matters here: keys list in lexicographic order, at most `limit`
// per call with a cursor, each with its metadata, and every call is counted.
import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { kvStore } from "./worker.mjs";

function fakeKv() {
  const m = new Map(); // key -> { value, metadata }
  const ops = { get: 0, put: 0, list: 0 };
  return {
    ops,
    async get(k) { ops.get++; return m.has(k) ? m.get(k).value : null; },
    async put(k, value, opts = {}) {
      ops.put++;
      if (opts.metadata !== undefined && new TextEncoder().encode(JSON.stringify(opts.metadata)).length > 1024) throw new Error("metadata over 1024 bytes");
      m.set(k, { value, metadata: opts.metadata });
    },
    async list({ prefix = "", cursor, limit = 1000 }) {
      ops.list++;
      const names = [...m.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0;
      const page = names.slice(start, start + limit);
      const next = start + page.length;
      return { keys: page.map((name) => ({ name, metadata: m.get(name).metadata })), list_complete: next >= names.length, cursor: next >= names.length ? undefined : String(next) };
    },
  };
}

test("audit rows written in the same second come back in the order they were written", async () => {
  const store = kvStore(fakeKv());
  const events = ["session", "certificate", "licence", "licence-denied", "revoked", "licence-refused"];
  for (const event of events) await store.putAudit({ at: 1000, event, sid: "s1", pin: "48213" }, 500);
  assert.deepEqual((await store.listAudit(null, { sid: "s1" })).map((r) => r.event), events);
  assert.deepEqual((await store.listAudit()).map((r) => r.event), events);
});

test("a viewer's own listing holds only that session's rows; the admin listing holds every session, oldest first", async () => {
  const store = kvStore(fakeKv());
  await store.putAudit({ at: 1000, event: "session", sid: "b" }, 500);
  await store.putAudit({ at: 1000, event: "session", sid: "a" }, 500);
  await store.putAudit({ at: 1001, event: "licence", sid: "b" }, 500);
  assert.deepEqual((await store.listAudit(null, { sid: "b" })).map((r) => r.event + ":" + r.sid), ["session:b", "licence:b"]);
  assert.deepEqual((await store.listAudit()).map((r) => r.event + ":" + r.sid), ["session:b", "session:a", "licence:b"]);
});

test("a log past 1,000 rows is listed whole, page by page, without a read per row", async () => {
  const kv = fakeKv();
  const store = kvStore(kv);
  for (let i = 0; i < 2500; i++) await store.putAudit({ at: 1000 + i, event: "session", sid: "s" + i, pin: "48213" }, 500);
  kv.ops.get = 0;
  kv.ops.list = 0;
  const rows = await store.listAudit();
  assert.equal(rows.length, 2500);
  assert.deepEqual([rows[0].sid, rows[2499].sid], ["s0", "s2499"], "oldest first");
  assert.equal(kv.ops.get, 0, "no reads");
  assert.equal(kv.ops.list, 3, "one list per 1,000 rows");
});

test("a row too big for KV metadata is still listed, as a marked summary", async () => {
  const store = kvStore(fakeKv());
  await store.putAudit({ at: 1, event: "licence-error", sid: "s1", pin: "48213", error: "x".repeat(2000) }, 500);
  const [row] = await store.listAudit();
  assert.equal(row.event, "licence-error");
  assert.equal(row.truncated, true);
});

test("revocations and licence counts persist in KV", async () => {
  const kv = fakeKv();
  const store = kvStore(kv);
  await store.revoke("pin:77310");
  assert.equal(await kvStore(kv).isRevoked("x", "77310"), true, "a second isolate sees the revocation");
  assert.equal(await kvStore(kv).isRevoked("x", "48213"), false);
  await store.addLicence("s1");
  await store.addLicence("s1");
  assert.equal(await kvStore(kv).licenceCount("s1"), 2);
});

test("an error the Worker produces itself is readable by an allowed page, and only by it", async () => {
  const env = { ALLOWED_ORIGINS: "https://page.example" }; // TOKEN_SECRET and the rest missing on purpose
  const allowed = await worker.fetch(new Request("https://w.example/health", { headers: { Origin: "https://page.example" } }), env);
  assert.equal(allowed.status, 500);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://page.example");
  const other = await worker.fetch(new Request("https://w.example/health", { headers: { Origin: "https://evil.example" } }), env);
  assert.equal(other.status, 500);
  assert.equal(other.headers.get("access-control-allow-origin"), null);
});
