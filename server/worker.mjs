// Cloudflare Worker adapter: the same core, deployed with `wrangler deploy` (see server/README.md).
// Audit and revocations live in memory per isolate; bind a KV namespace named AUDIT to persist
// them across isolates (the adapter below uses it when present).
import { createApp, memoryStore } from "./licence-core.mjs";

let app = null;

function kvStore(kv, keep) {
  const mem = memoryStore();
  return {
    async licenceCount(sid) { const v = await kv.get("lic:" + sid); return v ? Number(v) : 0; },
    async addLicence(sid) { const n = (await this.licenceCount(sid)) + 1; await kv.put("lic:" + sid, String(n), { expirationTtl: 86400 }); },
    async isRevoked(sid, pin) { return (sid && (await kv.get("rev:" + sid)) !== null) || (await kv.get("rev:pin:" + pin)) !== null; },
    async revoke(key) { await kv.put("rev:" + key, "1"); },
    async putAudit(rec, _keep) {
      await mem.putAudit(rec, keep);
      const id = String(rec.at).padStart(12, "0") + "-" + Math.random().toString(36).slice(2, 8);
      await kv.put("audit:" + id, JSON.stringify(rec), { expirationTtl: 7 * 86400 });
    },
    async listAudit(filter) {
      const list = await kv.list({ prefix: "audit:", limit: 1000 });
      const rows = [];
      for (const k of list.keys) { const v = await kv.get(k.name); if (v) rows.push(JSON.parse(v)); }
      rows.sort((a, b) => a.at - b.at);
      return rows.filter(filter || (() => true));
    },
  };
}

export default {
  async fetch(request, env) {
    if (!app) app = createApp(env, env.AUDIT ? kvStore(env.AUDIT, 500) : memoryStore());
    try { return await app.handle(request); }
    catch (e) { return new Response(JSON.stringify({ error: "server error", detail: String(e && e.message || e) }), { status: 500, headers: { "content-type": "application/json" } }); }
  },
};
