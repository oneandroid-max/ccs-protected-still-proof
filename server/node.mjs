// Node 22 adapter: `node server/node.mjs` (reads the environment; see server/README.md).
// When AUDIT_FILE is set, every audit row is also appended to it (JSON lines), and on start the
// file is replayed so revocations and per-session licence counts survive a restart.
import http from "node:http";
import { appendFile, readFile } from "node:fs/promises";
import { createApp, memoryStore, MAX_BODY_BYTES } from "./licence-core.mjs";

const env = process.env;
const store = memoryStore();
if (env.AUDIT_FILE) {
  const inner = store.putAudit;
  try {
    const rows = (await readFile(env.AUDIT_FILE, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
    for (const r of rows) {
      if (r.event === "revoked") await store.revoke(r.sid ? String(r.sid) : "pin:" + String(r.pin));
      if (r.event === "licence" && r.sid) await store.addLicence(r.sid);
    }
    for (const r of rows.slice(-500)) await inner(r, 500);
  } catch (e) {
    if (e.code !== "ENOENT") throw e; // first run has no file; anything else is a real fault
  }
  store.putAudit = async (rec, keep) => { await inner(rec, keep); await appendFile(env.AUDIT_FILE, JSON.stringify(rec) + "\n"); };
}
const app = createApp(env, store);
const port = Number(env.PORT || 8788);

http.createServer(async (req, res) => {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY_BYTES) {
      res.writeHead(413, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "request too large" }));
      req.destroy();
      return;
    }
    chunks.push(c);
  }
  const body = Buffer.concat(chunks);
  const url = `http://${req.headers.host || "localhost"}${req.url}`;
  const request = new Request(url, { method: req.method, headers: req.headers, body: ["GET", "HEAD", "OPTIONS"].includes(req.method) ? undefined : body });
  let response;
  try { response = await app.handle(request); }
  catch (e) {
    console.error("licence server error:", e);
    response = new Response(JSON.stringify({ error: "server error" }), { status: 500, headers: { "content-type": "application/json" } });
  }
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}).listen(port, () => console.log(`licence server listening on :${port} → ${app.cfg.widevine.licenseUrl} as ${app.cfg.widevine.signer}`));
