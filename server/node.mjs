// Node 22 adapter: `node server/node.mjs` (reads the environment; see server/README.md).
// Audit rows are also appended to AUDIT_FILE (JSON lines) when it is set, so the log survives a restart.
import http from "node:http";
import { appendFile, readFile } from "node:fs/promises";
import { createApp, memoryStore } from "./licence-core.mjs";

const env = process.env;
const store = memoryStore();
if (env.AUDIT_FILE) {
  const inner = store.putAudit;
  store.putAudit = async (rec, keep) => { await inner(rec, keep); await appendFile(env.AUDIT_FILE, JSON.stringify(rec) + "\n"); };
  try {
    const lines = (await readFile(env.AUDIT_FILE, "utf8")).split("\n").filter(Boolean);
    for (const l of lines.slice(-500)) await inner(JSON.parse(l), 500);
  } catch (e) { /* first run */ }
}
const app = createApp(env, store);
const port = Number(env.PORT || 8788);

http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  const url = `http://${req.headers.host || "localhost"}${req.url}`;
  const request = new Request(url, { method: req.method, headers: req.headers, body: ["GET", "HEAD", "OPTIONS"].includes(req.method) ? undefined : body });
  let response;
  try { response = await app.handle(request); }
  catch (e) { response = new Response(JSON.stringify({ error: "server error", detail: String(e && e.message || e) }), { status: 500, headers: { "content-type": "application/json" } }); }
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}).listen(port, () => console.log(`licence server listening on :${port} → ${app.cfg.widevine.licenseUrl} as ${app.cfg.widevine.signer}`));
