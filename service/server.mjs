// The temporary test site: one password opens it (the owner's choice: no username), upload up to ten
// pictures, and open each in the proof's protected viewer. No outside packages. Every protected file and every licence
// request needs the signed-in session, every licence request is logged, and deleting a picture
// revokes it at once. Run: node service/server.mjs (PROOF_PASSWORD, DATA_DIR, PORT).
import { createServer } from "node:http";
import { promises as fs, createReadStream } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { Sessions, LoginLimiter } from "./lib/sessions.mjs";
import { Store } from "./lib/store.mjs";
import { makeQueue, newProtectionIds, PLAYREADY_TEST_SERVER } from "./lib/pipeline.mjs";
import { loginPage, galleryPage, preparingPage, buildViewTemplate, CARD } from "./lib/pages.mjs";
import { readBody, sniffImage, parseCookies, safeEqual, newId, nowIso, run } from "./lib/util.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MEDIA_FILES = { "widevine.mpd": "application/dash+xml", "playready.mpd": "application/dash+xml", "video-widevine.mp4": "video/mp4", "video-playready.mp4": "video/mp4" };
const COOKIE = "ps";

export function configFromEnv(env = process.env) {
  return {
    port: Number(env.PORT || 10000),
    dataDir: env.DATA_DIR || join(HERE, "..", "data"),
    password: env.PROOF_PASSWORD || "",
    sessionSecret: env.SESSION_SECRET || "",
    maxPhotos: Number(env.MAX_PHOTOS || 10),
    maxUploadBytes: Number(env.MAX_UPLOAD_BYTES || 25 * 1024 * 1024),
    trustProxy: env.TRUST_PROXY === "1",
    secureCookies: env.NODE_ENV === "production" || env.FORCE_SECURE_COOKIES === "1",
    tools: { ffmpeg: env.FFMPEG_BIN || "ffmpeg", ffprobe: env.FFPROBE_BIN || "ffprobe", packager: env.PACKAGER_BIN || "packager" },
    upstream: { widevine: env.WIDEVINE_LICENCE_UPSTREAM || "https://cwip-shaka-proxy.appspot.com/no_auth", playready: env.PLAYREADY_LICENCE_UPSTREAM || PLAYREADY_TEST_SERVER },
    indexHtml: env.ROUTE1_PAGE || join(HERE, "..", "web", "research", "drm", "index.html"),
  };
}

export async function createApp(cfg, log = (m) => console.log(`${nowIso()} ${m}`)) {
  if (!cfg.password) throw new Error("PROOF_PASSWORD must be set: the site never runs without a password");
  if (cfg.password.length < 8) throw new Error("PROOF_PASSWORD must be at least 8 characters");
  let secret = cfg.sessionSecret;
  if (!secret) { secret = randomBytes(32).toString("hex"); log("SESSION_SECRET is not set: sessions end when this process restarts"); }
  const sessions = new Sessions(secret);
  const limiter = new LoginLimiter();
  const store = new Store(cfg.dataDir);
  await store.init();
  const renderView = buildViewTemplate(await fs.readFile(cfg.indexHtml, "utf8"));
  const queue = makeQueue(cfg.tools, store, log);
  const tools = { ffmpeg: "", packager: "", problem: "" };
  const started = Date.now();
  for (const p of store.photos()) if (p.status === "queued") queue.enqueue(p.id);

  (async () => {
    try { tools.ffmpeg = (await run(cfg.tools.ffmpeg, ["-version"])).stdout.split("\n")[0]; } catch (e) { tools.problem = `ffmpeg: ${e.message}`; }
    try { tools.packager = (await run(cfg.tools.packager, ["--version"])).stdout.trim(); } catch (e) { tools.problem = (tools.problem ? tools.problem + "; " : "") + `packager: ${e.message}`; }
    log(`tools: ffmpeg "${tools.ffmpeg}" packager "${tools.packager}"${tools.problem ? " PROBLEM " + tools.problem : ""}`);
  })();

  const ip = (req) => (cfg.trustProxy && req.headers["x-forwarded-for"] ? String(req.headers["x-forwarded-for"]).split(",")[0].trim() : req.socket.remoteAddress) || "?";
  const nonce = () => randomBytes(16).toString("base64");
  function headers(res, n, extra = {}) {
    res.setHeader("Content-Security-Policy", `default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; style-src 'nonce-${n}'; script-src 'nonce-${n}' https://cdnjs.cloudflare.com; connect-src 'self' https://oneandroid-max.github.io; media-src 'self' blob:; worker-src 'self' blob:`);
    res.setHeader("X-Content-Type-Options", "nosniff"); res.setHeader("Referrer-Policy", "no-referrer"); res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cache-Control", "no-store");
    for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  }
  const html = (res, n, status, body) => { headers(res, n, { "Content-Type": "text/html; charset=utf-8" }); res.writeHead(status); res.end(body); };
  const json = (res, status, obj) => { headers(res, "-", { "Content-Type": "application/json; charset=utf-8", ...(status === 413 ? { Connection: "close" } : {}) }); res.writeHead(status); res.end(JSON.stringify(obj)); };
  const redirect = (res, to) => { headers(res, "-", { Location: to }); res.writeHead(303); res.end(); };
  const cookie = (token, maxAge) => `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax${cfg.secureCookies ? "; Secure" : ""}; Max-Age=${maxAge}`;
  const session = (req) => sessions.verify(parseCookies(req.headers.cookie)[COOKIE]);
  // Cross-site writes are refused: browsers mark them in Sec-Fetch-Site, and the API also wants a custom header.
  const sameSite = (req) => { const s = req.headers["sec-fetch-site"]; return !s || s === "same-origin" || s === "none"; };
  const apiWrite = (req) => sameSite(req) && req.headers["x-proof"] === "1";
  const publicPhoto = (p, views) => ({ id: p.id, name: p.name, bytes: p.bytes, type: p.type, width: p.width, height: p.height, status: p.status, error: p.error, createdAt: p.createdAt, readyAt: p.readyAt, views: views[p.id] || 0 });

  async function forwardLicence(req, res, sess, system) {
    const url = new URL(req.url, "http://x");
    const photoId = url.searchParams.get("photo") || "";
    const isCard = photoId === "card";
    const rec = isCard ? null : store.get(photoId);
    if (!isCard && !rec) return json(res, 404, { error: "no such picture" });
    if (rec && rec.status !== "ready") return json(res, 409, { error: "this picture is not ready" });
    let target, fwdHeaders = {};
    if (system === "widevine") { target = cfg.upstream.widevine; fwdHeaders["content-type"] = "application/octet-stream"; }
    else {
      const sl = url.searchParams.get("sl");
      if (sl !== "2000" && sl !== "3000") return json(res, 400, { error: "sl must be 2000 or 3000" });
      const guid = isCard ? CARD.prKidGuid : rec.prKidGuid; // never the key id the client sent
      target = `${cfg.upstream.playready}?cfg=(kid:${guid},sl:${sl})`;
      fwdHeaders["content-type"] = req.headers["content-type"] || "text/xml; charset=utf-8";
      if (req.headers.soapaction) fwdHeaders.soapaction = req.headers.soapaction;
    }
    let body;
    try { body = await readBody(req, 256 * 1024); } catch (e) { return json(res, e.code === 413 ? 413 : 400, { error: "bad licence request" }); }
    const entry = { t: nowIso(), user: sess.u, photo: photoId, system, sl: url.searchParams.get("sl") || null, ip: ip(req), ua: String(req.headers["user-agent"] || "").slice(0, 200), bytesIn: body.length };
    try {
      const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), 20000);
      const r = await fetch(target, { method: "POST", headers: fwdHeaders, body, signal: ctrl.signal });
      clearTimeout(timer);
      const out = Buffer.from(await r.arrayBuffer());
      Object.assign(entry, { status: r.status, bytesOut: out.length });
      await store.logView(entry);
      headers(res, "-", { "Content-Type": r.headers.get("content-type") || "application/octet-stream" });
      res.writeHead(r.status); res.end(out);
    } catch (e) {
      Object.assign(entry, { status: 0, error: String(e.message || e).slice(0, 200) });
      await store.logView(entry);
      json(res, 502, { error: "the licence server could not be reached" });
    }
  }

  async function serveMedia(req, res, id, file) {
    const type = MEDIA_FILES[file];
    const rec = store.get(id);
    if (!type || !rec || rec.status !== "ready") return json(res, 404, { error: "not found" });
    const path = join(store.dir(id), file);
    let size;
    try { size = (await fs.stat(path)).size; } catch { return json(res, 404, { error: "not found" }); }
    headers(res, "-", { "Content-Type": type, "Accept-Ranges": "bytes" });
    const range = req.headers.range;
    if (range) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(range);
      let start = m && m[1] !== "" ? Number(m[1]) : NaN, end = m && m[2] !== "" ? Number(m[2]) : NaN;
      if (!m) { res.writeHead(416, { "Content-Range": `bytes */${size}` }); return res.end(); }
      if (Number.isNaN(start)) { start = Math.max(0, size - end); end = size - 1; } else if (Number.isNaN(end) || end >= size) end = size - 1;
      if (start > end || start >= size) { res.writeHead(416, { "Content-Range": `bytes */${size}` }); return res.end(); }
      res.writeHead(206, { "Content-Range": `bytes ${start}-${end}/${size}`, "Content-Length": end - start + 1 });
      if (req.method === "HEAD") return res.end();
      return createReadStream(path, { start, end }).pipe(res);
    }
    res.writeHead(200, { "Content-Length": size });
    if (req.method === "HEAD") return res.end();
    createReadStream(path).pipe(res);
  }

  async function handle(req, res) {
    const url = new URL(req.url, "http://x");
    const path = url.pathname;
    const n = nonce();
    if (path === "/api/health") return json(res, 200, { ok: true, uptimeSeconds: Math.round((Date.now() - started) / 1000), photos: store.photos().length, pending: queue.pending(), tools });
    if (path === "/favicon.ico") { res.writeHead(204); return res.end(); }

    if (path === "/login" && req.method === "GET") return html(res, n, 200, loginPage({ nonce: n, error: url.searchParams.get("e") }));
    if (path === "/login" && req.method === "POST") {
      if (!sameSite(req)) return json(res, 403, { error: "cross-site request refused" });
      const who = ip(req);
      if (limiter.locked(who)) { log(`login refused (locked) from ${who}`); return redirect(res, "/login?e=locked"); }
      let form;
      try { form = new URLSearchParams((await readBody(req, 4096)).toString("utf8")); } catch { return redirect(res, "/login?e=1"); }
      if (safeEqual(form.get("password") || "", cfg.password)) {
        limiter.success(who);
        log(`login ok from ${who}`);
        headers(res, "-", { "Set-Cookie": cookie(sessions.issue("viewer"), 12 * 3600), Location: "/app" }); res.writeHead(303); return res.end();
      }
      const wait = limiter.fail(who);
      log(`login failed from ${who}${wait ? " (now locked)" : ""}`);
      return redirect(res, wait ? "/login?e=locked" : "/login?e=1");
    }
    if (path === "/logout" && req.method === "POST") {
      headers(res, "-", { "Set-Cookie": cookie("", 0), Location: "/login" }); res.writeHead(303); return res.end();
    }

    const sess = session(req);
    if (path === "/") return redirect(res, sess ? "/app" : "/login");
    if (!sess) {
      if (path.startsWith("/api/") || path.startsWith("/media/") || path.startsWith("/licence/")) return json(res, 401, { error: "sign in first" });
      return redirect(res, "/login");
    }

    if (path === "/app" && req.method === "GET") return html(res, n, 200, galleryPage({ nonce: n, maxPhotos: cfg.maxPhotos }));

    if (path === "/api/photos" && req.method === "GET") {
      const views = {};
      for (const v of await store.views(5000)) if (v.status === 200) views[v.photo] = (views[v.photo] || 0) + 1;
      return json(res, 200, { photos: store.photos().map((p) => publicPhoto(p, views)), maxPhotos: cfg.maxPhotos, views, tools });
    }
    if (path === "/api/photos" && req.method === "PUT") {
      if (!apiWrite(req)) return json(res, 403, { error: "refused" });
      if (store.photos().length >= cfg.maxPhotos) return json(res, 409, { error: `the gallery holds at most ${cfg.maxPhotos} pictures; delete one first` });
      let body;
      try { body = await readBody(req, cfg.maxUploadBytes); } catch (e) { return json(res, e.code === 413 ? 413 : 400, { error: e.code === 413 ? `a picture may be at most ${Math.round(cfg.maxUploadBytes / 1048576)} MB` : "bad upload" }); }
      const kind = sniffImage(body);
      if (!kind) return json(res, 415, { error: "only JPEG, PNG or WebP pictures are accepted" });
      if (store.photos().length >= cfg.maxPhotos) return json(res, 409, { error: `the gallery holds at most ${cfg.maxPhotos} pictures; delete one first` });
      let name = "picture";
      try { name = decodeURIComponent(String(req.headers["x-filename"] || "")).replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 120) || "picture"; } catch {}
      const id = newId();
      const rec = { id, name, bytes: body.length, type: kind.type, ext: kind.ext, status: "queued", error: null, createdAt: nowIso(), ...newProtectionIds(id) };
      await store.add(rec);
      await fs.writeFile(join(store.dir(id), `original.${kind.ext}`), body);
      const created = publicPhoto(rec, {}); // as created: processing may begin the moment it is queued
      queue.enqueue(id);
      log(`upload ${id} "${name}" ${body.length} bytes by ${sess.u}`);
      return json(res, 201, { photo: created });
    }
    let m;
    if ((m = /^\/api\/photos\/([0-9a-f]{8,64})$/.exec(path)) && req.method === "DELETE") {
      if (!apiWrite(req)) return json(res, 403, { error: "refused" });
      const ok = await store.remove(m[1]);
      if (ok) log(`deleted ${m[1]} by ${sess.u}`);
      res.writeHead(ok ? 204 : 404); return res.end();
    }
    if ((m = /^\/view\/([0-9a-f]{8,64})$/.exec(path)) && req.method === "GET") {
      const rec = store.get(m[1]);
      if (!rec) return html(res, n, 404, preparingPage({ nonce: n, name: "Not found", status: "failed", error: "there is no such picture (it may have been deleted)" }));
      if (rec.status !== "ready") return html(res, n, 200, preparingPage({ nonce: n, name: rec.name, status: rec.status, error: rec.error }));
      return html(res, n, 200, renderView({ id: rec.id, name: rec.name, prKidGuid: rec.prKidGuid, nonce: n }));
    }
    if ((m = /^\/media\/([0-9a-f]{8,64})\/([a-z-]+\.(?:mpd|mp4))$/.exec(path)) && (req.method === "GET" || req.method === "HEAD")) return serveMedia(req, res, m[1], m[2]);
    if (path === "/licence/widevine" && req.method === "POST") return forwardLicence(req, res, sess, "widevine");
    if (path === "/licence/playready" && req.method === "POST") return forwardLicence(req, res, sess, "playready");
    return json(res, 404, { error: "not found" });
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((e) => { log(`error on ${req.method} ${req.url}: ${e.stack || e}`); if (!res.headersSent) json(res, 500, { error: "something went wrong on the server" }); else res.end(); });
  });
  return { server, store, queue, tools, sessions, cfg, close: () => new Promise((r) => server.close(r)) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cfg = configFromEnv();
  createApp(cfg).then(({ server }) => {
    server.listen(cfg.port, () => console.log(`${nowIso()} test site listening on :${cfg.port}, data in ${cfg.dataDir}`));
  }).catch((e) => { console.error(`cannot start: ${e.message}`); process.exit(1); });
}
