// Test helpers: a mock licence upstream, an app on a free port with a throwaway data directory, and a
// tiny valid PNG, so the API tests need no network and no real licence server.
import { createServer } from "node:http";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { createApp } from "../server.mjs";

export const REPO = fileURLToPath(new URL("../../", import.meta.url));

export async function mockUpstream(reply = Buffer.from("LICENCE-OK"), contentType = "application/octet-stream") {
  const seen = [];
  const srv = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => { seen.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks) }); res.writeHead(200, { "content-type": contentType }); res.end(reply); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, seen, close: () => new Promise((r) => srv.close(r)) };
}

export async function startApp(over = {}) {
  const dataDir = await fs.mkdtemp(join(tmpdir(), "proof-test-"));
  const wv = await mockUpstream();
  const pr = await mockUpstream(Buffer.from("<soap>licence</soap>"), "text/xml");
  const cfg = {
    port: 0, dataDir, password: "correct horse battery", sessionSecret: "s".repeat(32),
    maxPhotos: 10, maxUploadBytes: 200000, trustProxy: false, secureCookies: false,
    tools: { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: process.env.PACKAGER_BIN || "packager" },
    upstream: { widevine: wv.url + "/wv", playready: pr.url + "/pr" },
    indexHtml: join(REPO, "web", "research", "drm", "index.html"),
    ...over,
  };
  let app;
  try { app = await createApp(cfg, () => {}); }
  catch (e) { await wv.close(); await pr.close(); await fs.rm(dataDir, { recursive: true, force: true }); throw e; } // nothing stays open when start-up is refused
  await new Promise((r) => app.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  return { base, app, cfg, wv, pr, dataDir, close: async () => { await app.close(); await wv.close(); await pr.close(); await fs.rm(dataDir, { recursive: true, force: true }); } };
}

// Signs in and returns the cookie pair "ps=…".
export async function login(base, password = "correct horse battery") {
  const r = await fetch(base + "/login", { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ password }).toString() });
  const sc = r.headers.get("set-cookie") || "";
  return { status: r.status, location: r.headers.get("location"), cookie: sc.split(";")[0] };
}

// A valid 1×1 PNG (red), built by hand.
export function tinyPng() {
  const crcTable = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[n] = c >>> 0; }
  const crc = (buf) => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type, "latin1"), data]); const c = Buffer.alloc(4); c.writeUInt32BE(crc(td)); return Buffer.concat([len, td, c]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(1, 0); ihdr.writeUInt32BE(1, 4); ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const idat = deflateSync(Buffer.from([0, 255, 0, 0]));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0))]);
}

export const upload = (base, cookie, body, name = "pic.png", type = "image/png", extraHeaders = {}) =>
  fetch(base + "/api/photos", { method: "PUT", headers: { cookie, "x-proof": "1", "x-filename": encodeURIComponent(name), "content-type": type, ...extraHeaders }, body });

export async function readyRecord(app, over = {}) {
  // a record marked ready by hand, with a known media file, for media/licence/view tests that need no packager
  const id = over.id || "abcdef0123456789abcdef01";
  const rec = { id, name: over.name || "known.png", bytes: 10, type: "image/png", ext: "png", status: "ready", error: null, createdAt: new Date().toISOString(),
    wvContentId: `ccs-proof-${id}`, prKid: "5cfcb567f2f19d08a30b20483d92e930".replace(/^5c/, "7a"), prKidGuid: "7AFCB567-F2F1-9D08-A30B-20483D92E930", ...over };
  await app.store.add(rec);
  const bytes = Buffer.alloc(1000); for (let i = 0; i < 1000; i++) bytes[i] = i & 0xff;
  await fs.writeFile(join(app.store.dir(id), "video-widevine.mp4"), bytes);
  await fs.writeFile(join(app.store.dir(id), "widevine.mpd"), "<MPD/>");
  return { rec, bytes };
}
