// Our own licence server for the protected-still proof: the part that was the public proxy.
//
// What it does, in order, for every licence request from the page:
//   1. checks the viewer token (minted by POST /session for a PIN this gallery knows, and only for
//      a photo that PIN is allowed to open),
//   2. applies policy: the viewer is still listed and not revoked, the session has licences left,
//      and the session, the PIN and the caller are within their request limits,
//   3. forwards the phone's licence challenge to the licence environment with our signer
//      (in the proof: Google's Widevine UAT environment with the published test signer),
//   4. records what the licence environment reported about the device (security level, make,
//      model, certificate serial) against the viewer, in the audit log,
//   5. returns the licence bytes to the page.
//
// Runs unchanged on Node 22 (server/node.mjs) and on a Cloudflare Worker (server/worker.mjs):
// only Fetch-API Request/Response and WebCrypto are used. No dependencies.

import { signAndForward } from "./widevine-uat.mjs";

const enc = new TextEncoder();
const dec = new TextDecoder();

export const DEFAULTS = {
  licenceLimitPerSession: 20,         // licences actually issued per session
  sessionSeconds: 60 * 60,
  licenceDurationSeconds: 600,
  auditKeep: 500,                     // rows in the whole-log ring (admin listing)
  sessionAuditKeep: 50,               // rows kept per session (the viewer's own listing)
  sessionsKept: 1000,                 // sessions whose own rows are kept in memory
  failedSessionsPerIpPer10Min: 10,    // wrong PINs or photos from one caller before a pause
  sessionsPerPinPerHour: 30,
  forwardsPerPinPerDay: 200,          // calls to the licence environment for one PIN
};
export const MAX_BODY_BYTES = 64 * 1024;
const MAX_ORIGIN_CHARS = 200;
// One answer for an unknown PIN, a revoked PIN and a photo the PIN may not open, so the answer
// does not tell a guesser which of them it hit. The audit is not written for refusals here.
const REFUSED = "this PIN cannot open this photo";

// ---------- small codecs ----------

export function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64url(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- viewer tokens: HMAC-SHA256 over a small JSON claim ----------

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
export async function mintToken(secret, claim) {
  const body = b64url(enc.encode(JSON.stringify(claim)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(body)));
  return body + "." + b64url(sig);
}
export async function verifyToken(secret, token, now) {
  if (typeof token !== "string") return null;
  const dot = token.indexOf(".");
  if (dot < 1) return null;
  const body = token.slice(0, dot), sig = token.slice(dot + 1);
  let expected;
  try {
    expected = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(body)));
  } catch (e) { return null; }
  let given;
  try { given = unb64url(sig); } catch (e) { return null; }
  if (!timingSafeEqual(expected, given)) return null;
  let claim;
  try { claim = JSON.parse(dec.decode(unb64url(body))); } catch (e) { return null; }
  if (!claim || typeof claim.sid !== "string" || typeof claim.pin !== "string" || typeof claim.asset !== "string" || typeof claim.exp !== "number") return null;
  if (claim.exp <= now) return null;
  return claim;
}

// ---------- request limits: a fixed window per key, in memory ----------
// On a Cloudflare Worker each isolate keeps its own counts, so a limit there is per isolate; the
// platform's own rate limiting is the stronger option for production.

export function windowLimiter(maxKeys = 10000) {
  const m = new Map(); // key -> { start, count }
  function entry(key, windowSec, now) {
    let e = m.get(key);
    if (!e || now - e.start >= windowSec) {
      e = { start: now, count: 0 };
      m.delete(key);
      m.set(key, e);
      if (m.size > maxKeys) m.delete(m.keys().next().value);
    }
    return e;
  }
  return {
    // true while the key is under max in the current window, without counting
    open(key, max, windowSec, now) { return entry(key, windowSec, now).count < max; },
    // counts one use; false (and not counted) when the key is already at max
    take(key, max, windowSec, now) {
      const e = entry(key, windowSec, now);
      if (e.count >= max) return false;
      e.count++;
      return true;
    },
    // counts one use regardless (for failures, which are counted after they happen)
    count(key, windowSec, now) { entry(key, windowSec, now).count++; },
  };
}

// ---------- the store: licence counts, revocations, audit (memory; adapters may persist) ----------

export function memoryStore(opts = {}) {
  const sessionsKept = opts.sessionsKept || DEFAULTS.sessionsKept;
  const perSession = opts.sessionAuditKeep || DEFAULTS.sessionAuditKeep;
  const licences = new Map(); // sid -> count
  const revoked = new Set();  // sid or pin:<pin>
  const audit = [];           // whole-log ring, for the admin listing
  const bySession = new Map(); // sid -> rows, so other sessions cannot push a viewer's own rows out
  return {
    async licenceCount(sid) { return licences.get(sid) || 0; },
    async addLicence(sid) {
      licences.set(sid, (licences.get(sid) || 0) + 1);
      if (licences.size > sessionsKept * 10) licences.delete(licences.keys().next().value);
    },
    async isRevoked(sid, pin) { return revoked.has(sid) || revoked.has("pin:" + pin); },
    async revoke(key) { revoked.add(key); },
    async putAudit(rec, keep) {
      audit.push(rec);
      while (audit.length > keep) audit.shift();
      if (rec.sid) {
        let rows = bySession.get(rec.sid);
        if (!rows) {
          rows = [];
          bySession.set(rec.sid, rows);
          if (bySession.size > sessionsKept) bySession.delete(bySession.keys().next().value);
        }
        rows.push(rec);
        if (rows.length > perSession) rows.shift();
      }
    },
    async listAudit(filter, scope) {
      const rows = scope && scope.sid ? bySession.get(scope.sid) || [] : audit;
      return rows.filter(filter || (() => true));
    },
  };
}

// ---------- the app ----------

export function createApp(env, store, deps = {}) {
  const cfg = {
    tokenSecret: must(env, "TOKEN_SECRET"),
    adminKey: must(env, "ADMIN_KEY"),
    viewers: parseViewers(must(env, "VIEWERS")),
    allowedOrigins: (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean),
    licenceLimit: num(env.LICENCE_LIMIT_PER_SESSION, DEFAULTS.licenceLimitPerSession),
    sessionSeconds: num(env.SESSION_SECONDS, DEFAULTS.sessionSeconds),
    licenceDurationSeconds: num(env.LICENCE_DURATION_SECONDS, DEFAULTS.licenceDurationSeconds),
    auditKeep: num(env.AUDIT_KEEP, DEFAULTS.auditKeep),
    failedSessionsPerIp: num(env.FAILED_SESSIONS_PER_IP_PER_10_MIN, DEFAULTS.failedSessionsPerIpPer10Min),
    sessionsPerPinPerHour: num(env.SESSIONS_PER_PIN_PER_HOUR, DEFAULTS.sessionsPerPinPerHour),
    forwardsPerPinPerDay: num(env.FORWARDS_PER_PIN_PER_DAY, DEFAULTS.forwardsPerPinPerDay),
    widevine: {
      licenseUrl: env.WIDEVINE_LICENSE_URL || "https://license.uat.widevine.com/cenc/getlicense/widevine_test",
      signer: env.WIDEVINE_SIGNER || "widevine_test",
      keyHex: env.WIDEVINE_SIGNING_KEY_HEX || "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9",
      ivHex: env.WIDEVINE_SIGNING_IV_HEX || "d58ce954203b7c9a9a9d467f59839249",
    },
  };
  // Every forwarded request of a session counts here, the certificate request and refusals
  // included, so one token cannot drive unlimited signed calls to the licence environment.
  cfg.forwardsPerSession = cfg.licenceLimit * 3;
  const forward = deps.signAndForward || signAndForward;
  const now = deps.now || (() => Math.floor(Date.now() / 1000));
  const newId = deps.newId || (() => b64url(crypto.getRandomValues(new Uint8Array(12))));
  const limits = windowLimiter();
  const pending = new Map(); // sid -> licence requests in flight, so simultaneous requests cannot pass the limit together

  // Audit and count writes must not decide whether a viewer gets a licence: if the store cannot
  // write (a Worker past its daily KV write quota, a full disk), the request still completes and
  // the failure is logged. Reads that decide policy (revocation) still fail closed.
  async function record(row) {
    try { await store.putAudit(row, cfg.auditKeep); } catch (e) { console.error("audit write failed:", (e && e.message) || e); }
  }
  function viewerAllows(pin, asset) {
    const v = cfg.viewers.get(pin);
    return !!v && v.assets.has(asset);
  }

  // Only the origins listed in ALLOWED_ORIGINS may call the server from a browser. None listed
  // means none allowed: the admin calls are made with curl, which needs no CORS at all.
  function cors(origin) {
    const h = new Headers();
    h.set("Vary", "Origin");
    if (origin && cfg.allowedOrigins.includes(origin)) {
      h.set("Access-Control-Allow-Origin", origin);
      h.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
      h.set("Access-Control-Allow-Headers", "content-type, x-viewer-token");
      h.set("Access-Control-Expose-Headers", "x-licence-device");
      h.set("Access-Control-Max-Age", "600");
    }
    return h;
  }
  // A Widevine challenge is a few kilobytes and a session request a few dozen bytes. A declared
  // length over the cap is refused before reading; an undeclared body is read in pieces and
  // abandoned the moment it passes the cap, so it is never held whole.
  async function readBody(request) {
    const declared = Number(request.headers.get("content-length") || 0);
    if (declared > MAX_BODY_BYTES) return null;
    if (!request.body) return new Uint8Array(0);
    const reader = request.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        try { await reader.cancel(); } catch (e) { /* already closed */ }
        return null;
      }
      chunks.push(value);
    }
    const out = new Uint8Array(size);
    let at = 0;
    for (const c of chunks) { out.set(c, at); at += c.byteLength; }
    return out;
  }
  async function readJsonCapped(request) {
    const bytes = await readBody(request);
    if (!bytes) return { tooLarge: true };
    try { return { value: JSON.parse(dec.decode(bytes)) }; } catch (e) { return { value: null }; }
  }
  function json(status, body, headers) {
    const h = new Headers(headers);
    h.set("Content-Type", "application/json; charset=utf-8");
    h.set("Cache-Control", "no-store");
    return new Response(JSON.stringify(body), { status, headers: h });
  }

  // ctx.ip is the caller's address as the host knows it (the socket on Node, CF-Connecting-IP on
  // a Worker); it keys the limit on wrong PINs.
  async function handle(request, ctx = {}) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const ip = ctx.ip || "unknown";
    const h = cors(origin);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/" || path === "/health") {
      return json(200, { ok: true, service: "protected-still licence server", licenceEnvironment: cfg.widevine.licenseUrl, signer: cfg.widevine.signer }, h);
    }

    // 1. A viewer opens the gallery with a PIN: mint a session bound to the PIN and a photo that
    //    PIN may open.
    if (path === "/session" && request.method === "POST") {
      const t = now();
      const failKey = "fail:" + ip;
      if (!limits.open(failKey, cfg.failedSessionsPerIp, 600, t)) return json(429, { error: "too many wrong attempts; try again in a few minutes" }, h);
      const read = await readJsonCapped(request);
      if (read.tooLarge) return json(413, { error: "request too large" }, h);
      const body = read.value;
      const pin = String((body && body.pin) || "").trim();
      const asset = String((body && body.asset) || "").trim();
      if (!viewerAllows(pin, asset) || (await store.isRevoked("", pin))) {
        limits.count(failKey, 600, t);
        return json(403, { error: REFUSED }, h);
      }
      if (!limits.take("sessions:" + pin, cfg.sessionsPerPinPerHour, 3600, t)) return json(429, { error: "too many sessions for this PIN; try again later" }, h);
      const viewer = cfg.viewers.get(pin).name;
      const claim = { sid: newId(), pin, asset, exp: t + cfg.sessionSeconds };
      const token = await mintToken(cfg.tokenSecret, claim);
      await record({ at: t, event: "session", sid: claim.sid, pin, viewer, asset, origin: origin.slice(0, MAX_ORIGIN_CHARS) });
      return json(200, { token, sid: claim.sid, viewer, asset, expiresAt: claim.exp, licenceLimit: cfg.licenceLimit, licenceDurationSeconds: cfg.licenceDurationSeconds }, h);
    }

    // 2–5. The phone's licence request, with the viewer token.
    if (path === "/licence" && request.method === "POST") {
      const t = now();
      const claim = await verifyToken(cfg.tokenSecret, request.headers.get("x-viewer-token"), t);
      if (!claim) return json(401, { error: "missing, invalid or expired viewer token" }, h);
      // A viewer taken out of VIEWERS, or a photo taken off their list, stops at once, not when
      // the token expires.
      if (!viewerAllows(claim.pin, claim.asset)) return json(403, { error: REFUSED }, h);
      const who = { sid: claim.sid, pin: claim.pin, asset: claim.asset };
      if (await store.isRevoked(claim.sid, claim.pin)) {
        await record({ at: t, event: "licence-refused", reason: "revoked", ...who });
        return json(403, { error: "access revoked" }, h);
      }
      const challenge = await readBody(request);
      if (!challenge) return json(413, { error: "licence challenge too large" }, h);
      if (challenge.length === 0) return json(400, { error: "empty licence challenge" }, h);
      const isCertRequest = challenge.length === 2 && challenge[0] === 0x08 && challenge[1] === 0x04;
      if (!isCertRequest) {
        const used = (await store.licenceCount(claim.sid)) + (pending.get(claim.sid) || 0);
        if (used >= cfg.licenceLimit) {
          await record({ at: t, event: "licence-refused", reason: "limit", used, ...who });
          return json(429, { error: "licence limit reached for this session" }, h);
        }
      }
      if (!limits.take("forwards:" + claim.sid, cfg.forwardsPerSession, cfg.sessionSeconds, t)) {
        await record({ at: t, event: "licence-refused", reason: "session request limit", ...who });
        return json(429, { error: "too many licence requests for this session" }, h);
      }
      if (!limits.take("pin-forwards:" + claim.pin, cfg.forwardsPerPinPerDay, 86400, t)) {
        await record({ at: t, event: "licence-refused", reason: "daily request limit", ...who });
        return json(429, { error: "too many licence requests for this PIN today" }, h);
      }
      if (!isCertRequest) pending.set(claim.sid, (pending.get(claim.sid) || 0) + 1);
      let result;
      try {
        result = await forward(cfg.widevine, {
          challenge,
          contentId: enc.encode(claim.asset),
          policy: { licenceDurationSeconds: cfg.licenceDurationSeconds },
        });
      } catch (e) {
        await record({ at: t, event: "licence-error", ...who, error: String((e && e.message) || e).slice(0, 300) });
        return json(502, { error: "licence environment unreachable" }, h);
      } finally {
        if (!isCertRequest) {
          const n = (pending.get(claim.sid) || 1) - 1;
          if (n > 0) pending.set(claim.sid, n); else pending.delete(claim.sid);
        }
      }
      const granted = result.status === "OK" && !!result.licence;
      // Only a licence actually issued counts against the session's licence limit: the player
      // retries a failed request once, and a refusal must not use up the viewer's licences.
      if (!isCertRequest && granted) {
        try { await store.addLicence(claim.sid); } catch (e) { console.error("licence count write failed:", (e && e.message) || e); }
      }
      await record({ at: t, event: isCertRequest ? "certificate" : (granted ? "licence" : "licence-denied"), ...who, viewer: cfg.viewers.get(claim.pin).name, status: result.status, device: result.device || null });
      if (!granted) return json(403, { error: "licence not granted", status: result.status }, h);
      const rh = new Headers(h);
      rh.set("Content-Type", "application/octet-stream");
      rh.set("Cache-Control", "no-store");
      // What the licence environment reported about this device, handed to the page with the
      // licence itself, so the page shows it without a second request or a store read.
      if (!isCertRequest && result.device) rh.set("X-Licence-Device", encodeURIComponent(JSON.stringify(result.device)));
      return new Response(result.licence, { status: 200, headers: rh });
    }

    // What the server recorded for THIS viewer session (the page shows it after the photo plays).
    if (path === "/session/audit" && request.method === "GET") {
      const claim = await verifyToken(cfg.tokenSecret, request.headers.get("x-viewer-token"), now());
      if (!claim) return json(401, { error: "missing, invalid or expired viewer token" }, h);
      if (!viewerAllows(claim.pin, claim.asset)) return json(403, { error: REFUSED }, h);
      const rows = await store.listAudit((r) => r.sid === claim.sid, { sid: claim.sid });
      return json(200, { sid: claim.sid, pin: claim.pin, viewer: cfg.viewers.get(claim.pin).name, rows }, h);
    }

    // Admin: the whole audit log, and revocation. The key travels only in a header, never in the
    // address, so it does not land in access logs or browser history.
    const admin = request.headers.get("x-admin-key");
    if (path === "/audit" && request.method === "GET") {
      if (!admin || !timingSafeEqual(enc.encode(admin), enc.encode(cfg.adminKey))) return json(401, { error: "admin key required" }, h);
      const pin = url.searchParams.get("pin");
      return json(200, { rows: await store.listAudit((r) => !pin || r.pin === pin) }, h);
    }
    if (path === "/revoke" && request.method === "POST") {
      if (!admin || !timingSafeEqual(enc.encode(admin), enc.encode(cfg.adminKey))) return json(401, { error: "admin key required" }, h);
      const read = await readJsonCapped(request);
      if (read.tooLarge) return json(413, { error: "request too large" }, h);
      const body = read.value;
      const sid = body && body.sid, pin = body && body.pin;
      if (!sid && !pin) return json(400, { error: "sid or pin required" }, h);
      await store.revoke(sid ? String(sid) : "pin:" + String(pin));
      // Not through record(): on the Node host this row is what carries the revocation across a
      // restart, so if it cannot be written the admin must see a failure, not a 200.
      await store.putAudit({ at: now(), event: "revoked", sid: sid || null, pin: pin || null }, cfg.auditKeep);
      return json(200, { revoked: sid ? { sid } : { pin } }, h);
    }

    return json(404, { error: "not found" }, h);
  }

  return { handle, cfg };
}

// ---------- helpers ----------

function must(env, name) {
  if (!env[name]) throw new Error("licence server: " + name + " is not set");
  return env[name];
}
function num(v, d) { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; }
// VIEWERS: comma-separated "PIN:Name:photo|photo" entries. A PIN opens only the photos listed with
// it; an entry with no photos opens nothing.
export function parseViewers(s) {
  const m = new Map();
  for (const part of String(s).split(",")) {
    const [pin, name, photos] = part.split(":").map((x) => (x || "").trim());
    if (!pin || !name) continue;
    m.set(pin, { name, assets: new Set((photos || "").split("|").map((x) => x.trim()).filter(Boolean)) });
  }
  if (m.size === 0) throw new Error("licence server: VIEWERS has no PIN:Name:photo entries");
  return m;
}
