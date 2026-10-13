// Our own licence server for the protected-still proof: the part that was the public proxy.
//
// What it does, in order, for every licence request from the page:
//   1. checks the viewer token (minted by POST /session for a PIN this gallery knows),
//   2. applies policy: the session is not revoked and has licences left,
//   3. forwards the phone's licence challenge to the licence environment with our signer
//      (in the proof: Google's Widevine UAT environment with the published test signer; in
//      production: the production environment with the owner's own signer, same code),
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
  licenceLimitPerSession: 20,
  sessionSeconds: 60 * 60,
  licenceDurationSeconds: 600,
  auditKeep: 500,
};

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

// ---------- the store: sessions, revocations, audit (memory; adapters may persist) ----------

export function memoryStore() {
  const licences = new Map(); // sid -> count
  const revoked = new Set();  // sid or pin:<pin>
  const audit = [];
  return {
    async licenceCount(sid) { return licences.get(sid) || 0; },
    async addLicence(sid) { licences.set(sid, (licences.get(sid) || 0) + 1); },
    async isRevoked(sid, pin) { return revoked.has(sid) || revoked.has("pin:" + pin); },
    async revoke(key) { revoked.add(key); },
    async putAudit(rec, keep) { audit.push(rec); while (audit.length > keep) audit.shift(); },
    async listAudit(filter) { return audit.filter(filter || (() => true)); },
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
    widevine: {
      licenseUrl: env.WIDEVINE_LICENSE_URL || "https://license.uat.widevine.com/cenc/getlicense/widevine_test",
      signer: env.WIDEVINE_SIGNER || "widevine_test",
      keyHex: env.WIDEVINE_SIGNING_KEY_HEX || "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9",
      ivHex: env.WIDEVINE_SIGNING_IV_HEX || "d58ce954203b7c9a9a9d467f59839249",
    },
  };
  const forward = deps.signAndForward || signAndForward;
  const now = deps.now || (() => Math.floor(Date.now() / 1000));
  const newId = deps.newId || (() => b64url(crypto.getRandomValues(new Uint8Array(12))));

  function cors(origin) {
    const h = new Headers();
    const allowed = origin && (cfg.allowedOrigins.length === 0 || cfg.allowedOrigins.includes(origin));
    if (allowed) {
      h.set("Access-Control-Allow-Origin", origin);
      h.set("Vary", "Origin");
      h.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
      h.set("Access-Control-Allow-Headers", "content-type, x-viewer-token, x-admin-key");
      h.set("Access-Control-Max-Age", "600");
    }
    return h;
  }
  function json(status, body, headers) {
    const h = new Headers(headers);
    h.set("Content-Type", "application/json; charset=utf-8");
    h.set("Cache-Control", "no-store");
    return new Response(JSON.stringify(body), { status, headers: h });
  }

  async function handle(request) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const h = cors(origin);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: h });
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/" || path === "/health") {
      return json(200, { ok: true, service: "protected-still licence server", licenceEnvironment: cfg.widevine.licenseUrl, signer: cfg.widevine.signer }, h);
    }

    // 1. A viewer opens the gallery with a PIN: mint a session bound to the PIN and the asset.
    if (path === "/session" && request.method === "POST") {
      const body = await readJson(request);
      const pin = String((body && body.pin) || "").trim();
      const asset = String((body && body.asset) || "").trim();
      const viewer = cfg.viewers.get(pin);
      if (!viewer || !asset) return json(403, { error: "unknown PIN or missing asset" }, h);
      if (await store.isRevoked("", pin)) return json(403, { error: "this PIN's access has been revoked" }, h);
      const t = now();
      const claim = { sid: newId(), pin, asset, exp: t + cfg.sessionSeconds };
      const token = await mintToken(cfg.tokenSecret, claim);
      await store.putAudit({ at: t, event: "session", sid: claim.sid, pin, viewer, asset, origin }, cfg.auditKeep);
      return json(200, { token, sid: claim.sid, viewer, asset, expiresAt: claim.exp, licenceLimit: cfg.licenceLimit, licenceDurationSeconds: cfg.licenceDurationSeconds }, h);
    }

    // 2–5. The phone's licence request, with the viewer token.
    if (path === "/licence" && request.method === "POST") {
      const t = now();
      const claim = await verifyToken(cfg.tokenSecret, request.headers.get("x-viewer-token"), t);
      if (!claim) return json(401, { error: "missing, invalid or expired viewer token" }, h);
      if (await store.isRevoked(claim.sid, claim.pin)) {
        await store.putAudit({ at: t, event: "licence-refused", reason: "revoked", sid: claim.sid, pin: claim.pin, asset: claim.asset }, cfg.auditKeep);
        return json(403, { error: "access revoked" }, h);
      }
      const challenge = new Uint8Array(await request.arrayBuffer());
      if (challenge.length === 0) return json(400, { error: "empty licence challenge" }, h);
      const isCertRequest = challenge.length === 2 && challenge[0] === 0x08 && challenge[1] === 0x04;
      if (!isCertRequest) {
        const used = await store.licenceCount(claim.sid);
        if (used >= cfg.licenceLimit) {
          await store.putAudit({ at: t, event: "licence-refused", reason: "limit", sid: claim.sid, pin: claim.pin, asset: claim.asset, used }, cfg.auditKeep);
          return json(429, { error: "licence limit reached for this session" }, h);
        }
      }
      let result;
      try {
        result = await forward(cfg.widevine, {
          challenge,
          contentId: enc.encode(claim.asset),
          policy: { licenceDurationSeconds: cfg.licenceDurationSeconds },
        });
      } catch (e) {
        await store.putAudit({ at: t, event: "licence-error", sid: claim.sid, pin: claim.pin, asset: claim.asset, error: String(e && e.message || e) }, cfg.auditKeep);
        return json(502, { error: "licence environment unreachable" }, h);
      }
      if (!isCertRequest) await store.addLicence(claim.sid);
      await store.putAudit({ at: t, event: isCertRequest ? "certificate" : (result.status === "OK" ? "licence" : "licence-denied"), sid: claim.sid, pin: claim.pin, viewer: cfg.viewers.get(claim.pin), asset: claim.asset, status: result.status, device: result.device || null }, cfg.auditKeep);
      if (result.status !== "OK" || !result.licence) return json(403, { error: "licence not granted", status: result.status }, h);
      const rh = new Headers(h);
      rh.set("Content-Type", "application/octet-stream");
      rh.set("Cache-Control", "no-store");
      return new Response(result.licence, { status: 200, headers: rh });
    }

    // What the server recorded for THIS viewer session (the page shows it after the photo plays).
    if (path === "/session/audit" && request.method === "GET") {
      const claim = await verifyToken(cfg.tokenSecret, request.headers.get("x-viewer-token"), now());
      if (!claim) return json(401, { error: "missing, invalid or expired viewer token" }, h);
      const rows = await store.listAudit((r) => r.sid === claim.sid);
      return json(200, { sid: claim.sid, pin: claim.pin, viewer: cfg.viewers.get(claim.pin), rows }, h);
    }

    // Admin: the whole audit log, and revocation.
    const admin = request.headers.get("x-admin-key") || url.searchParams.get("key");
    if (path === "/audit" && request.method === "GET") {
      if (!admin || !timingSafeEqual(enc.encode(admin), enc.encode(cfg.adminKey))) return json(401, { error: "admin key required" }, h);
      const pin = url.searchParams.get("pin");
      return json(200, { rows: await store.listAudit((r) => !pin || r.pin === pin) }, h);
    }
    if (path === "/revoke" && request.method === "POST") {
      if (!admin || !timingSafeEqual(enc.encode(admin), enc.encode(cfg.adminKey))) return json(401, { error: "admin key required" }, h);
      const body = await readJson(request);
      const sid = body && body.sid, pin = body && body.pin;
      if (!sid && !pin) return json(400, { error: "sid or pin required" }, h);
      await store.revoke(sid ? String(sid) : "pin:" + String(pin));
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
function parseViewers(s) {
  const m = new Map();
  for (const part of String(s).split(",")) {
    const i = part.indexOf(":");
    if (i > 0) m.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  if (m.size === 0) throw new Error("licence server: VIEWERS has no pin:name entries");
  return m;
}
async function readJson(request) {
  try { return await request.json(); } catch (e) { return null; }
}
