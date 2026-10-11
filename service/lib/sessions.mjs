// Signed session tokens: base64url(JSON payload) + "." + base64url(HMAC-SHA256 over the payload).
// Nothing is stored server-side; a token is valid until its expiry, and every token dies when the
// secret changes. The cookie carrying it is HttpOnly and SameSite=Lax (set by the server).
import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";

export class Sessions {
  constructor(secret, ttlMs = 12 * 60 * 60 * 1000) {
    if (!secret || String(secret).length < 16) throw new Error("the session secret must be at least 16 characters");
    this.secret = String(secret);
    this.ttlMs = ttlMs;
  }
  sign(payloadB64) {
    return createHmac("sha256", this.secret).update(payloadB64).digest("base64url");
  }
  issue(username, now = Date.now()) {
    const payload = Buffer.from(JSON.stringify({ u: username, exp: now + this.ttlMs, id: randomBytes(8).toString("hex") })).toString("base64url");
    return `${payload}.${this.sign(payload)}`;
  }
  verify(token, now = Date.now()) {
    if (typeof token !== "string") return null;
    const dot = token.indexOf(".");
    if (dot < 1) return null;
    const payload = token.slice(0, dot), sig = token.slice(dot + 1);
    const want = this.sign(payload);
    if (sig.length !== want.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    let data;
    try { data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")); } catch { return null; }
    if (!data || typeof data.u !== "string" || typeof data.exp !== "number" || data.exp <= now) return null;
    return data;
  }
}

// Login attempts per address: after `maxFails` failures the address waits `lockMs` before another try.
export class LoginLimiter {
  constructor({ maxFails = 5, lockMs = 15 * 60 * 1000 } = {}) {
    this.maxFails = maxFails; this.lockMs = lockMs; this.map = new Map();
  }
  locked(ip, now = Date.now()) {
    const e = this.map.get(ip);
    if (!e) return 0;
    if (e.until && e.until > now) return e.until - now;
    if (e.until && e.until <= now) this.map.delete(ip);
    return 0;
  }
  fail(ip, now = Date.now()) {
    const e = this.map.get(ip) || { fails: 0, until: 0 };
    e.fails += 1;
    if (e.fails >= this.maxFails) { e.until = now + this.lockMs; e.fails = 0; }
    this.map.set(ip, e);
    return e.until > now ? e.until - now : 0;
  }
  success(ip) { this.map.delete(ip); }
}
