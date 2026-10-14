// Node 22 adapter: `node server/node.mjs` (reads the environment; see server/README.md).
// When AUDIT_FILE is set, every audit row is also appended to it (JSON lines), and on start the
// file is replayed line by line so revocations and per-session licence counts survive a restart;
// a line that cannot be read (a cut-off last line, say) is skipped and counted, never fatal.
import http from "node:http";
import readline from "node:readline";
import { createReadStream } from "node:fs";
import { access, appendFile } from "node:fs/promises";
import { createApp, memoryStore, MAX_BODY_BYTES } from "./licence-core.mjs";

const env = process.env;
const store = memoryStore();
if (env.AUDIT_FILE) {
  const inner = store.putAudit;
  let exists = true;
  try { await access(env.AUDIT_FILE); } catch (e) { exists = false; }
  if (exists) {
    const tail = [];
    let skipped = 0;
    const lines = readline.createInterface({ input: createReadStream(env.AUDIT_FILE, { encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of lines) {
      if (!line.trim()) continue;
      let r;
      try { r = JSON.parse(line); } catch (e) { skipped++; continue; }
      if (!r || typeof r !== "object") { skipped++; continue; }
      if (r.event === "revoked") await store.revoke(r.sid ? String(r.sid) : "pin:" + String(r.pin));
      if (r.event === "licence" && r.sid) await store.addLicence(r.sid);
      tail.push(r);
      if (tail.length > 500) tail.shift();
    }
    for (const r of tail) await inner(r, 500);
    if (skipped) console.error(`audit replay: skipped ${skipped} unreadable line(s) in ${env.AUDIT_FILE}`);
  }
  store.putAudit = async (rec, keep) => { await inner(rec, keep); await appendFile(env.AUDIT_FILE, JSON.stringify(rec) + "\n"); };
}
const app = createApp(env, store);
const port = Number(env.PORT || 8788);
const METHODS = new Set(["GET", "HEAD", "POST", "OPTIONS"]);

// An error the host produces itself still carries the cross-site headers for an allowed page, so
// the page can read the status instead of reporting the server as unreachable.
const ALLOWED = String(env.ALLOWED_ORIGINS || "").split(",").map((x) => x.trim()).filter(Boolean);
function reply(res, status, body, origin) {
  if (res.headersSent || res.destroyed) { res.destroy(); return; }
  const headers = { "content-type": "application/json", "cache-control": "no-store", vary: "Origin" };
  if (origin && ALLOWED.includes(origin)) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-methods"] = "POST, GET, OPTIONS";
    headers["access-control-allow-headers"] = "content-type, x-viewer-token";
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(body));
}

// Everything a request can throw stays inside this handler: one bad request (an odd method, a
// malformed address, a client that drops mid-upload) must never take the server down for everyone.
const server = http.createServer(async (req, res) => {
  req.on("error", () => {});
  res.on("error", () => {});
  const origin = typeof req.headers.origin === "string" ? req.headers.origin : "";
  try {
    if (!METHODS.has(req.method)) return reply(res, 405, { error: "method not allowed" }, origin);
    let url;
    try { url = new URL(req.url || "/", "http://localhost"); } catch (e) { return reply(res, 400, { error: "bad address" }, origin); }
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reply(res, 413, { error: "request too large" }, origin); req.destroy(); return; }
      chunks.push(c);
    }
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(", ") : String(v));
    const hasBody = req.method === "POST";
    const request = new Request(url, { method: req.method, headers, body: hasBody ? Buffer.concat(chunks) : undefined });
    const response = await app.handle(request, { ip: req.socket.remoteAddress || "unknown" });
    if (res.destroyed) return;
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (e) {
    console.error("licence server: request failed:", (e && e.message) || e);
    reply(res, 400, { error: "bad request" }, origin);
  }
});
server.listen(port, () => console.log(`licence server listening on :${server.address().port} → ${app.cfg.widevine.licenseUrl} as ${app.cfg.widevine.signer}`));
