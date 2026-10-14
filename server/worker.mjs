// Cloudflare Worker adapter: the same core, deployed with `wrangler deploy` (see server/README.md).
// Bind a KV namespace named AUDIT to keep the audit log, revocations and licence counts across
// isolates and restarts. Without it they live in one isolate's memory, so a revocation may not
// reach a second isolate: fine for a quick try, not for a real proof run.
//
// KV facts this adapter is built around (developers.cloudflare.com/kv): a write is seen at once at
// the location that made it and within about 60 seconds elsewhere, a key that did not exist is
// remembered as missing for up to 60 seconds (so a revocation can take up to a minute to reach
// every location), one invocation may make at most 1,000 KV operations, and list() returns at most
// 1,000 keys per call with each key's metadata.
import { createApp, memoryStore } from "./licence-core.mjs";

let app = null;

// Audit rows are stored under audit:<order>:<sid>, where <order> is milliseconds plus a per-isolate
// counter, so a plain listing is already oldest-first: the whole-second `at` ties for every request
// made in the same second. The row also travels as the key's metadata (when it fits KV's 1,024-byte
// metadata limit), so listing the log costs one KV operation per 1,000 rows and no reads at all.
let auditSeq = 0;
export function auditOrder(nowMs) {
  auditSeq = (auditSeq + 1) % 1000000;
  return String(nowMs).padStart(13, "0") + "-" + String(auditSeq).padStart(6, "0");
}
const METADATA_MAX_BYTES = 1000;
const MAX_LIST_PAGES = 50;

export function kvStore(kv) {
  return {
    async licenceCount(sid) { const v = await kv.get("lic:" + sid); return v ? Number(v) : 0; },
    async addLicence(sid) { const n = (await this.licenceCount(sid)) + 1; await kv.put("lic:" + sid, String(n), { expirationTtl: 86400 }); },
    async isRevoked(sid, pin) { return (!!sid && (await kv.get("rev:" + sid)) !== null) || (await kv.get("rev:pin:" + pin)) !== null; },
    async revoke(key) { await kv.put("rev:" + key, "1"); },
    async putAudit(rec) {
      const order = auditOrder(Date.now());
      const row = { ...rec, order };
      const text = JSON.stringify(row);
      const fits = new TextEncoder().encode(text).length <= METADATA_MAX_BYTES;
      const metadata = fits ? row : { at: row.at, event: row.event, sid: row.sid || null, pin: row.pin || null, order, truncated: true };
      await kv.put("audit:" + order + ":" + (rec.sid || "-"), text, { expirationTtl: 7 * 86400, metadata });
    },
    async listAudit(filter, scope) {
      const rows = [];
      let cursor;
      for (let page = 0; page < MAX_LIST_PAGES; page++) {
        const res = await kv.list({ prefix: "audit:", cursor, limit: 1000 });
        for (const k of res.keys) if (k.metadata) rows.push(k.metadata);
        if (res.list_complete || !res.cursor) break;
        cursor = res.cursor;
      }
      const wanted = scope && scope.sid ? rows.filter((r) => r.sid === scope.sid) : rows;
      wanted.sort((a, b) => String(a.order || "").localeCompare(String(b.order || "")));
      return wanted.filter(filter || (() => true));
    },
  };
}

// An error the host produces itself still carries the cross-site headers for an allowed page, so
// the page can read the status instead of reporting the server as unreachable.
function errorResponse(request, env) {
  const headers = { "content-type": "application/json", "cache-control": "no-store", vary: "Origin" };
  const origin = request.headers.get("Origin");
  const allowed = String((env && env.ALLOWED_ORIGINS) || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (origin && allowed.includes(origin)) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-methods"] = "POST, GET, OPTIONS";
    headers["access-control-allow-headers"] = "content-type, x-viewer-token";
  }
  return new Response(JSON.stringify({ error: "server error" }), { status: 500, headers });
}

export default {
  async fetch(request, env) {
    try {
      if (!app) app = createApp(env, env.AUDIT ? kvStore(env.AUDIT) : memoryStore());
      // Cloudflare sets CF-Connecting-IP itself; a caller cannot choose it.
      return await app.handle(request, { ip: request.headers.get("CF-Connecting-IP") || "unknown" });
    } catch (e) {
      console.error("licence server error:", e);
      return errorResponse(request, env);
    }
  },
};
