// Drives the test site's three pages in a real browser against a MOCKED GitHub API (route
// interception), with the real crypto in the browser: wrong and right password, the gallery, an
// upload (the mock receives an encrypted blob that decrypts to the chosen file), a delete, the set-up
// page (config.json written with a sealed access key), and the protected view (files decrypted in
// memory and served to a stand-in player through the mem:// scheme, byte ranges included).
// The sandbox's Chromium has no DRM module, so real playback is not exercised here.
//   node tools/drive-site.mjs      (needs Playwright + Chromium; CHROME=path to the browser)
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { deriveKey, exportKeyHex, seal, open, sealText, openText, toBase64, fromBase64 } from "../site/crypto.js";

const require = createRequire("/home/user/QUICLINKS/package.json");
const { chromium } = require("playwright");
const REPO_DIR = fileURLToPath(new URL("../", import.meta.url));
const REPO = "oneandroid-max/ccs-protected-still-proof";
const PASSWORD = "a test password, twelve+", TOKEN = "ghp_TESTTOKEN0123456789";
const ID = "0123456789abcdef01234567";
let failed = 0;
const check = (ok, what) => { console.log(`${ok ? "ok  " : "FAIL"}  ${what}`); if (!ok) failed++; };

// a served copy of site/ with a sealed access key and one prepared picture
const www = await fs.mkdtemp(join(tmpdir(), "site-www-"));
await fs.cp(join(REPO_DIR, "site"), join(www, "site"), { recursive: true });
await fs.mkdir(join(www, "web", "research", "drm"), { recursive: true });
const cfg = JSON.parse(await fs.readFile(join(www, "site", "config.json"), "utf8"));
const KEY = await deriveKey(PASSWORD, cfg.salt, cfg.iterations);
const KEY_HEX = await exportKeyHex(KEY);
cfg.tokenEnc = toBase64(await sealText(KEY, TOKEN));
await fs.writeFile(join(www, "site", "config.json"), JSON.stringify(cfg));
const photoDir = join(www, "site", "photos", ID);
await fs.mkdir(photoDir, { recursive: true });
const fileBytes = {};
for (const [f, size] of [["widevine.mpd", 700], ["video-widevine.mp4", 50000], ["playready.mpd", 710], ["video-playready.mp4", 50010]]) {
  const b = new Uint8Array(size); for (let i = 0; i < size; i++) b[i] = (i * 7 + size) & 255; fileBytes[f] = b;
  await fs.writeFile(join(photoDir, f + ".enc"), await seal(KEY, b));
}
await fs.writeFile(join(photoDir, "meta.json.enc"), await sealText(KEY, JSON.stringify({ id: ID, name: "Cotton <Bowl>.jpg", width: 720, height: 862, prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930" })));
const gallerySealed = await sealText(KEY, JSON.stringify({ photos: [{ id: ID, name: "Cotton <Bowl>.jpg", bytes: 288000, width: 720, height: 862, status: "ready", prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930" }] }));
const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==", "base64");
await fs.writeFile(join(www, "pic.png"), png);

const PORT = 8766;
const server = spawn("python3", ["-m", "http.server", String(PORT), "--bind", "127.0.0.1", "--directory", www], { stdio: "ignore" });
await new Promise((r) => setTimeout(r, 1200));
const BASE = `http://127.0.0.1:${PORT}/site/`;

const STUB = `
window.__manifests = []; window.__got = [];
window.shaka = { polyfill: { installAll(){} },
  net: { NetworkingEngine: { RequestType: { LICENSE: 2 }, registerScheme(s, fn) { window.__scheme = { s, fn }; } } },
  util: { AbortableOperation: { completed: (v) => ({ promise: Promise.resolve(v) }), failed: (e) => ({ promise: Promise.reject(e) }) },
          Error: class { constructor(...a) { this.args = a; } static get Severity() { return { CRITICAL: 2 }; } static get Category() { return { NETWORK: 1 }; } static get Code() { return { BAD_HTTP_STATUS: 1001 }; } } },
  Player: class extends EventTarget { static isBrowserSupported(){ return true; } async attach(v){ this.v = v; }
    configure(c){ this.cfg = c; } getNetworkingEngine(){ return { registerResponseFilter(){} }; }
    async load(m){ window.__manifests.push(m);
      if (m.startsWith("mem://")) { const r = await window.__scheme.fn(m, { headers: {} }).promise; window.__got.push([m, r.data.byteLength]);
        const seg = await window.__scheme.fn("mem://photo/video-widevine.mp4", { headers: { Range: "bytes=100-199" } }).promise; window.__got.push(["range", seg.data.byteLength, new Uint8Array(seg.data)[0]]);
        const nope = await window.__scheme.fn("mem://photo/missing.mp4", { headers: {} }).promise.then(() => "resolved", () => "rejected"); window.__got.push(["missing", nope]); }
      this.ks = Object.keys(this.cfg.drm.advanced)[0]; setTimeout(() => this.v.dispatchEvent(new Event("playing")), 50); }
    drmInfo(){ return { keySystem: this.ks }; } async destroy(){} } };`;

const api = { blobs: [], dispatches: [], puts: [] };
const b = await chromium.launch({ executablePath: process.env.CHROME || "/opt/pw-browsers/chromium-1194/chrome-linux/chrome", args: ["--no-sandbox"] });
const ctx = await b.newContext();
const errors = [];
ctx.on("page", (p) => p.on("pageerror", (e) => errors.push(e.message)));
await ctx.route("https://api.github.com/**", async (route) => {
  const req = route.request(); const u = new URL(req.url()); const auth = req.headers()["authorization"];
  if (auth !== `Bearer ${TOKEN}`) return route.fulfill({ status: 401, body: "{}" });
  if (req.method() === "GET" && u.pathname === `/repos/${REPO}`) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ permissions: { push: true } }) });
  if (req.method() === "GET" && u.pathname === `/repos/${REPO}/contents/site/gallery.json.enc`) return route.fulfill({ status: 200, contentType: "application/octet-stream", body: Buffer.from(gallerySealed) });
  if (req.method() === "GET" && u.pathname === `/repos/${REPO}/contents/site/config.json`) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ sha: "deadbeef" }) });
  if (req.method() === "POST" && u.pathname === `/repos/${REPO}/git/blobs`) { api.blobs.push(JSON.parse(req.postData())); return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ sha: "b".repeat(40) }) }); }
  if (req.method() === "POST" && u.pathname === `/repos/${REPO}/dispatches`) { api.dispatches.push(JSON.parse(req.postData())); return route.fulfill({ status: 204, body: "" }); }
  if (req.method() === "PUT" && u.pathname === `/repos/${REPO}/contents/site/config.json`) { api.puts.push(JSON.parse(req.postData())); return route.fulfill({ status: 200, contentType: "application/json", body: "{}" }); }
  return route.fulfill({ status: 404, body: "{}" });
});
await ctx.route("**/shaka-player.compiled.min.js", (r) => r.fulfill({ body: STUB, contentType: "application/javascript" }));

try {
  const page = await ctx.newPage();
  // 1. wrong password, then the right one
  await page.goto(BASE + "index.html");
  await page.fill("#pw", "not the password at all"); await page.click("#go");
  await page.waitForFunction(() => document.getElementById("lockmsg").textContent.length > 0 && document.getElementById("lockmsg").textContent !== "checking…");
  check((await page.textContent("#lockmsg")) === "wrong password", "a wrong password is refused: " + (await page.textContent("#lockmsg")));
  check(await page.isHidden("#app"), "the gallery stays hidden");
  await page.fill("#pw", PASSWORD); await page.click("#go");
  await page.waitForSelector("#app:not([hidden])", { timeout: 20000 });
  await page.waitForFunction(() => /ready|publishing/.test(document.getElementById("list").textContent));
  const list = await page.textContent("#list");
  check(/Cotton <Bowl>\.jpg/.test(list) && /720×862/.test(list), "the gallery lists the prepared picture with its name escaped");
  const hasLink = (await page.$('a[href="view.html?id=' + ID + '"]')) !== null;
  const status = await page.textContent("#list .ok").catch(() => "(no .ok status)");
  check(status === "ready" && hasLink, "a published picture reads ready and shows its protected-view link (status: " + status + ")");
  const st = await page.evaluate(() => JSON.parse(sessionStorage.getItem("ccs-site")));
  check(st && st.keyHex === KEY_HEX && st.token === TOKEN, "the session holds the derived key and the unsealed access key");
  // 2. upload
  await page.setInputFiles("#files", join(www, "pic.png"));
  await page.waitForFunction(() => /uploaded|refused/.test(document.getElementById("uploads").textContent), null, { timeout: 20000 });
  check(/uploaded/.test(await page.textContent("#uploads")), "the upload is accepted: " + (await page.textContent("#uploads")));
  check(api.blobs.length === 1 && api.blobs[0].encoding === "base64", "one encrypted blob reached GitHub");
  const sealed = fromBase64(api.blobs[0].content);
  const opened = await open(KEY, sealed).catch(() => null);
  check(opened && Buffer.from(opened).equals(png), "the blob decrypts, with the password's key, to the chosen file exactly");
  const d = api.dispatches[0] && api.dispatches[0].client_payload;
  check(api.dispatches.length === 1 && d.action === "add" && /^[0-9a-f]{24}$/.test(d.id) && d.key === KEY_HEX && d.blobSha === "b".repeat(40) && d.name === "pic.png" && d.type === "image/png", "the job was asked for with the id, the key and the blob");
  await page.waitForFunction(() => /being prepared by GitHub/.test(document.getElementById("list").textContent));
  check(/being prepared by GitHub/.test(await page.textContent("#list")), "the new picture shows as being prepared");
  // 3. delete
  page.once("dialog", (dlg) => dlg.accept());
  await page.click('button[data-del="' + ID + '"]');
  await page.waitForFunction(() => window.__d === undefined || true);
  await new Promise((r) => setTimeout(r, 500));
  const del = api.dispatches[1] && api.dispatches[1].client_payload;
  check(del && del.action === "delete" && del.id === ID && del.key === KEY_HEX, "delete asks the job to remove the picture");
  // 4. the protected view (same session)
  await page.goto(BASE + "view.html?id=" + ID);
  await page.waitForFunction(() => window.__photoShown, null, { timeout: 20000 });
  const got = await page.evaluate(() => window.__got);
  const title = await page.textContent("#title");
  check(title === "Protected view: Cotton <Bowl>.jpg", "the view names the picture: " + title);
  check(got[0] && got[0][0] === "mem://photo/widevine.mpd" && got[0][1] === 700, "the manifest came from memory, decrypted, 700 bytes");
  check(got[1] && got[1][0] === "range" && got[1][1] === 100 && got[1][2] === fileBytes["video-widevine.mp4"][100], "a byte-range request is sliced from the decrypted file");
  check(got[2] && got[2][1] === "rejected", "a file that is not there is refused");
  check((await page.textContent("#r-content")) === "your picture: Cotton <Bowl>.jpg", "the readout's Content line");
  check(/prepared|Playing|playing/.test(await page.textContent("#r-play")) , "the stand-in player reports playing");
  // 5. the view without a session goes to the password
  const fresh = await ctx.browser().newContext(); await fresh.route("**/shaka-player.compiled.min.js", (r) => r.fulfill({ body: STUB, contentType: "application/javascript" }));
  const p2 = await fresh.newPage(); await p2.goto(BASE + "view.html?id=" + ID); await p2.waitForURL(/index\.html\?then=/);
  check(/index\.html\?then=/.test(p2.url()), "the view without a session sends you to the password first");
  await fresh.close();
  // 6. set-up
  await page.goto(BASE + "setup.html");
  await page.fill("#t", TOKEN); await page.fill("#p", "short"); await page.fill("#p2", "short"); await page.click("#go");
  await page.waitForFunction(() => document.getElementById("msg").textContent.length > 0);
  check(/at least 12/.test(await page.textContent("#msg")), "set-up refuses a short password");
  await page.fill("#p", PASSWORD); await page.fill("#p2", PASSWORD); await page.click("#go");
  await page.waitForFunction(() => /Done|refused|differ|answered/.test(document.getElementById("msg").textContent), null, { timeout: 30000 });
  check(/Done/.test(await page.textContent("#msg")), "set-up completes: " + (await page.textContent("#msg")));
  const put = api.puts[0];
  const written = put && JSON.parse(Buffer.from(put.content, "base64").toString("utf8"));
  check(put && put.sha === "deadbeef" && written.salt === cfg.salt && written.iterations === cfg.iterations, "config.json is rewritten with the same salt and the file's sha");
  const tok = written && (await openText(await deriveKey(PASSWORD, written.salt, written.iterations), fromBase64(written.tokenEnc)).catch(() => null));
  check(tok === TOKEN, "the saved access key unseals with the password to the token");
  check(errors.length === 0, "no page errors" + (errors.length ? ": " + errors.join("; ") : ""));
} finally {
  await b.close(); server.kill();
}
console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
process.exit(failed ? 1 : 0);
