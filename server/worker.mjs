// Cloudflare Worker adapter: the same core, deployed with `wrangler deploy` (see server/README.md).
// Bind a KV namespace named AUDIT to keep the audit log, revocations and licence counts across
// isolates and restarts. Without it they live in one isolate's memory, so a revocation may not
// reach a second isolate: fine for a quick try, not for a real proof run.
import { createApp, memoryStore } from "./licence-core.mjs";

let app = null;

// Audit rows are stored under audit:<sid>:<time>-<random>, so one viewer's own rows are a single
// prefix listing instead of a scan of the whole log.
function kvStore(kv) {
  const mem = memoryStore();
  return {
    async licenceCount(sid) { const v = await kv.get("lic:" + sid); return v ? Number(v) : 0; },
    async addLicence(sid) { const n = (await this.licenceCount(sid)) + 1; await kv.put("lic:" + sid, String(n), { expirationTtl: 86400 }); },
    async isRevoked(sid, pin) { return (!!sid && (await kv.get("rev:" + sid)) !== null) || (await kv.get("rev:pin:" + pin)) !== null; },
    async revoke(key) { await kv.put("rev:" + key, "1"); },
    async putAudit(rec, keep) {
      await mem.putAudit(rec, keep);
      const id = String(rec.at).padStart(12, "0") + "-" + Math.random().toString(36).slice(2, 8);
      await kv.put("audit:" + (rec.sid || "-") + ":" + id, JSON.stringify(rec), { expirationTtl: 7 * 86400 });
    },
    async listAudit(filter, scope) {
      const prefix = scope && scope.sid ? "audit:" + scope.sid + ":" : "audit:";
      const list = await kv.list({ prefix, limit: 1000 });
      const rows = [];
      for (const k of list.keys) { const v = await kv.get(k.name); if (v) rows.push(JSON.parse(v)); }
      rows.sort((a, b) => a.at - b.at);
      return rows.filter(filter || (() => true));
    },
  };
}

export default {
  async fetch(request, env) {
    try {
      if (!app) app = createApp(env, env.AUDIT ? kvStore(env.AUDIT) : memoryStore());
      return await app.handle(request);
    } catch (e) {
      console.error("licence server error:", e);
      return new Response(JSON.stringify({ error: "server error" }), { status: 500, headers: { "content-type": "application/json" } });
    }
  },
};
