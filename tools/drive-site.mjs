// Drives the test site's three pages in a real browser against a MOCKED GitHub API (route
// interception), with the real crypto in the browser: wrong and right password, the gallery, an
// upload (the mock receives an encrypted blob that decrypts to the chosen file), a delete and its
// "being removed" state, a gallery written under another password, the set-up page (config.json
// rewritten with the repository's own salt and a sealed access key), and the protected view (files
// decrypted in memory and served to a stand-in player through the mem:// scheme, byte ranges included),
// and the combined view (asked for when none exists, offered once it is published, opened from its own
// files, a tap on a picture opening that picture alone, and the password first when signed out), and
// the Apple path as an iPhone and an iPad see it: the picture held back while Apple is unmeasured, the
// Apple test playing only the test card with Axinom's public token, and (with the switch flipped as it
// would be after a measurement) the picture's own Apple form by its address with its own sealed token;
// and the route-1 page, the one link for every device: each kind of device detected and named at the top,
// Apple's test (and only its public material) on an iPhone, iPad or Mac, and where to open it instead elsewhere.
// The sandbox's Chromium has no DRM module, so real playback is not exercised here.
//   node tools/drive-site.mjs   (Playwright from PLAYWRIGHT_PKG's package, Chromium at CHROME)
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { deriveKey, derivePhotoKey, exportKeyHex, seal, open, sealText, openText, toBase64, fromBase64 } from "../site/crypto.js";

const require = createRequire(process.env.PLAYWRIGHT_PKG || "/home/user/QUICLINKS/package.json");
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
// the route-1 page, with its own card's Apple form as card-fairplay.yml writes it (current.json naming a folder, its token)
const R1_HTML = await fs.readFile(join(REPO_DIR, "web", "research", "drm", "index.html"), "utf8");
await fs.writeFile(join(www, "web", "research", "drm", "index.html"), R1_HTML);
const R1_OWN_TOKEN = "OWN.CARD.TOKEN";
await fs.mkdir(join(www, "web", "research", "drm", "card-fairplay-own", "1a2b3c4d"), { recursive: true });
await fs.writeFile(join(www, "web", "research", "drm", "card-fairplay-own", "1a2b3c4d", "token.txt"), R1_OWN_TOKEN + "\n");
const cfg = JSON.parse(await fs.readFile(join(www, "site", "config.json"), "utf8"));
const KEY = await deriveKey(PASSWORD, cfg.salt, cfg.iterations);
const KEY_HEX = await exportKeyHex(KEY);
const PHOTO = await derivePhotoKey(KEY);
const PHOTO_HEX = await exportKeyHex(PHOTO);
cfg.tokenEnc = toBase64(await sealText(KEY, TOKEN));
await fs.writeFile(join(www, "site", "config.json"), JSON.stringify(cfg));
const photoDir = join(www, "site", "photos", ID);
await fs.mkdir(photoDir, { recursive: true });
const fileBytes = {};
for (const [f, size] of [["widevine.mpd", 700], ["video-widevine.mp4", 50000], ["playready.mpd", 710], ["video-playready.mp4", 50010]]) {
  const b = new Uint8Array(size); for (let i = 0; i < size; i++) b[i] = (i * 7 + size) & 255; fileBytes[f] = b;
  await fs.writeFile(join(photoDir, f + ".enc"), await seal(PHOTO, b));
}
// its Apple form: the files as the job writes them (not sealed), and the licence token, sealed
const FP_MASTER = "fp-0a1b2c3d/master.m3u8", PICTURE_TOKEN = "PICTURE.TOKEN.VALUE";
const OWN_LICENSE = "https://0a1b2c3d.drm-fairplay-licensing.axprod.net/AcquireLicense"; // an account's own licence address (a made-up prefix)
await fs.mkdir(join(photoDir, "fp-0a1b2c3d"), { recursive: true });
for (const f of ["master.m3u8", "video.m3u8", "video.mp4"]) await fs.writeFile(join(photoDir, "fp-0a1b2c3d", f), "#EXTM3U\n");
await fs.writeFile(join(photoDir, "fp-0a1b2c3d", "token.enc"), await sealText(PHOTO, PICTURE_TOKEN));
const writePhotoMeta = async (license = OWN_LICENSE, more = {}) => fs.writeFile(join(photoDir, "meta.json.enc"), await sealText(PHOTO, JSON.stringify({ id: ID, name: "Cotton <Bowl>.jpg", width: 720, height: 862, prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930", fairplay: { keyUri: "skd://00000000-0000-0000-0000-000000000000:00000000000000000000000000000000", master: FP_MASTER, license, ...more } })));
await writePhotoMeta();
// the combined view's files, written into the served copy only once the drive has seen the page ask for it
const mosaicBytes = {};
async function publishMosaic(builtAt = new Date().toISOString(), ids = [ID], skipped = [], fairplay = null, kept = null, answered = null) {
  const dir = join(www, "site", "mosaic");
  await fs.mkdir(dir, { recursive: true });
  for (const [f, size] of [["widevine.mpd", 640], ["video-widevine.mp4", 40000], ["playready.mpd", 650], ["video-playready.mp4", 40010]]) {
    const b = new Uint8Array(size); for (let i = 0; i < size; i++) b[i] = (i * 11 + size) & 255; mosaicBytes[f] = b;
    await fs.writeFile(join(dir, f + ".enc"), await seal(PHOTO, b));
  }
  await fs.writeFile(join(dir, "meta.json.enc"), await sealText(PHOTO, JSON.stringify({ kind: "mosaic", width: 1080, height: 1440, cols: 1, rows: 1, prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930", builtAt,
    ids, tiles: ids.map((id, i) => ({ id, name: i ? "picture " + i : "Cotton <Bowl>.jpg", x: 6, y: 8 + i * 10, w: 1068, h: i ? 8 : 1424 })), skipped, fairplay, ...(kept ? { kept } : {}), ...(answered ? { answered } : {}) })));
  if (fairplay) { const f = join(dir, fairplay.master.split("/")[0]); await fs.mkdir(f, { recursive: true }); await fs.writeFile(join(f, "token.enc"), await sealText(PHOTO, "MOSAIC.TOKEN.VALUE")); }
}
const REPO_SALT = toBase64(new Uint8Array(16).fill(0x5a)); // what the repository holds, deliberately not what the served copy holds
const HOUR_AGO = new Date(Date.now() - 3600 * 1000).toISOString();
const galleryJson = JSON.stringify({ photos: [{ id: ID, name: "Cotton <Bowl>.jpg", bytes: 288000, width: 720, height: 862, status: "ready", readyAt: HOUR_AGO, prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930" }] });
const gallerySealed = await sealText(PHOTO, galleryJson);
// a second ready picture the combined view does not hold yet (the stale path)
const ID2 = "fedcba9876543210fedcba98";
await fs.mkdir(join(www, "site", "photos", ID2), { recursive: true });
await fs.writeFile(join(www, "site", "photos", ID2, "widevine.mpd.enc"), await seal(PHOTO, new Uint8Array(10)));
const twoSealed = await sealText(PHOTO, JSON.stringify({ photos: [...JSON.parse(galleryJson).photos, { id: ID2, name: "second.jpg", bytes: 1000, width: 720, height: 960, status: "ready", readyAt: HOUR_AGO }] }));
// a third ready picture (the set changing while a page is open), and a gallery whose only picture was ready just now
const ID3 = "abcabcabcabcabcabcabcabc";
await fs.mkdir(join(www, "site", "photos", ID3), { recursive: true });
await fs.writeFile(join(www, "site", "photos", ID3, "widevine.mpd.enc"), await seal(PHOTO, new Uint8Array(10)));
const threeSealed = await sealText(PHOTO, JSON.stringify({ photos: [...JSON.parse(galleryJson).photos, { id: ID2, name: "second.jpg", status: "ready", readyAt: HOUR_AGO }, { id: ID3, name: "third.jpg", status: "ready", readyAt: HOUR_AGO }] }));
// a picture ready "just now": sealed again when the scenario that uses it starts (the scenarios before it take real time,
// and each page's clock starts at the real time; a stamp from the drive's start made that scenario depend on how long
// the others took)
const sealFresh = async () => { const now = new Date().toISOString(); return sealText(PHOTO, JSON.stringify({ updatedAt: now, photos: [{ ...JSON.parse(galleryJson).photos[0], readyAt: now }] })); };
let freshSealed = await sealFresh();
const foreignSealed = await sealText(await derivePhotoKey(await deriveKey("some other password here", cfg.salt, 1000)), galleryJson);
const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==", "base64");
await fs.writeFile(join(www, "pic.png"), png);

// the drive's own server on a free port, and proof that the server answering is this drive's own: a
// server left over from an earlier run on a fixed port once answered instead, and the drive judged the
// wrong copy of the site (2026-10-11)
const PORT = await new Promise((resolve, reject) => { const s = createServer(); s.on("error", reject); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const DRIVE_ID = randomBytes(16).toString("hex");
await fs.writeFile(join(www, "drive-id.txt"), DRIVE_ID);
const server = spawn("python3", ["-m", "http.server", String(PORT), "--bind", "127.0.0.1", "--directory", www], { stdio: "ignore" });
let ours = false;
for (let i = 0; i < 60 && !ours; i++) {
  try { const r = await fetch(`http://127.0.0.1:${PORT}/drive-id.txt`); ours = r.ok && (await r.text()) === DRIVE_ID; } catch {}
  if (!ours) await new Promise((r) => setTimeout(r, 100));
}
if (!ours) { server.kill(); console.error(`FAIL  the drive's own test server never answered on port ${PORT}`); process.exit(1); }
const BASE = `http://127.0.0.1:${PORT}/site/`;

const STUB = `
window.__manifests = []; window.__got = [];
window.shaka = { polyfill: { installAll(){} },
  net: { NetworkingEngine: { RequestType: { LICENSE: 2 }, registerScheme(s, fn) { window.__scheme = { s, fn }; } } },
  util: { AbortableOperation: { completed: (v) => ({ promise: Promise.resolve(v) }), failed: (e) => ({ promise: Promise.reject(e) }) },
          Error: class { constructor(...a) { this.args = a; } static get Severity() { return { CRITICAL: 2 }; } static get Category() { return { NETWORK: 1 }; } static get Code() { return { BAD_HTTP_STATUS: 1001 }; } } },
  Player: class extends EventTarget { static isBrowserSupported(){ return true; } async attach(v){ this.v = v; }
    configure(c){ this.cfg = c; } getNetworkingEngine(){ const self = this; return { registerResponseFilter(){}, registerRequestFilter(f){ (self.reqFilters = self.reqFilters || []).push(f); (window.__reqFilters = window.__reqFilters || []).push(f); } }; }
    async load(m){ window.__manifests.push(m); (window.__cfgs = window.__cfgs || []).push(JSON.parse(JSON.stringify(this.cfg || {}))); this.m = m; (window.__players = window.__players || []).push(this);
      if (window.__refuseAll) throw Object.assign(new Error("no such protection here (the drive)"), { code: 6001 });
      if (m.startsWith("mem://")) { const r = await window.__scheme.fn(m, { headers: {} }).promise; window.__got.push([m, r.data.byteLength]);
        const seg = await window.__scheme.fn("mem://photo/video-widevine.mp4", { headers: { Range: "bytes=100-199" } }).promise; window.__got.push(["range", seg.data.byteLength, new Uint8Array(seg.data)[0]]);
        const nope = await window.__scheme.fn("mem://photo/missing.mp4", { headers: {} }).promise.then(() => "resolved", () => "rejected"); window.__got.push(["missing", nope]); }
      this.ks = Object.keys((this.cfg && this.cfg.drm && this.cfg.drm.advanced) || {})[0];
      // a decoded 720x960 frame and moving time, as a real protected video reports them (the page needs both);
      // window.__noFrames: "playing" with no frame at all, as a Mac without a working FairPlay did
      const v = this.v, t0 = performance.now();
      if (window.__noFrames) { setTimeout(() => v.dispatchEvent(new Event("playing")), 50); return; }
      Object.defineProperty(v, "videoWidth", { configurable: true, get: () => 720 });
      Object.defineProperty(v, "videoHeight", { configurable: true, get: () => 960 });
      Object.defineProperty(v, "paused", { configurable: true, get: () => false });
      Object.defineProperty(v, "currentTime", { configurable: true, get: () => ((performance.now() - t0) / 1000) % 2, set: () => {} });
      setTimeout(() => v.dispatchEvent(new Event("playing")), 50); }
    drmInfo(){ return { keySystem: this.ks }; } async destroy(){} } };`;

const api = { blobs: [], dispatches: [], puts: [], galleryMode: "normal" };
const b = await chromium.launch({ executablePath: process.env.CHROME || "/opt/pw-browsers/chromium-1194/chrome-linux/chrome", args: ["--no-sandbox"] });
const errors = [];
async function mockedContext(opts = {}) {
  const ctx = await b.newContext(opts);
  ctx.on("page", (p) => p.on("pageerror", (e) => errors.push(e.message)));
  await ctx.route("https://api.github.com/**", async (route) => {
    const req = route.request(); const u = new URL(req.url()); const auth = req.headers()["authorization"];
    if (auth !== `Bearer ${TOKEN}`) return route.fulfill({ status: 401, body: "{}" });
    if (req.method() === "GET" && u.pathname === `/repos/${REPO}`) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ permissions: { push: true } }) });
    if (req.method() === "GET" && u.pathname === `/repos/${REPO}/contents/site/gallery.json.enc`) return route.fulfill({ status: 200, contentType: "application/octet-stream", body: Buffer.from({ foreign: foreignSealed, two: twoSealed, three: threeSealed, fresh: freshSealed }[api.galleryMode] || gallerySealed) });
    if (req.method() === "GET" && u.pathname === `/repos/${REPO}/contents/site/config.json`) return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ sha: "deadbeef", content: Buffer.from(JSON.stringify({ repo: REPO, salt: REPO_SALT, iterations: 1000, tokenEnc: "x" })).toString("base64") }) });
    if (req.method() === "POST" && u.pathname === `/repos/${REPO}/git/blobs`) { api.blobs.push(JSON.parse(req.postData())); return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ sha: "b".repeat(40) }) }); }
    if (req.method() === "POST" && u.pathname === `/repos/${REPO}/dispatches`) { api.dispatches.push(JSON.parse(req.postData())); return route.fulfill(api.refuseDispatch ? { status: 502, body: "{}" } : { status: 204, body: "" }); }
    if (req.method() === "PUT" && u.pathname === `/repos/${REPO}/contents/site/config.json`) { api.puts.push(JSON.parse(req.postData())); return route.fulfill({ status: 200, contentType: "application/json", body: "{}" }); }
    return route.fulfill({ status: 404, body: "{}" });
  });
  await ctx.route(/\/site\/mosaic\/meta\.json\.enc/, (r) => { api.metaReads = (api.metaReads || 0) + 1; return api.metaAbort ? r.abort() : api.noMosaic ? r.fulfill({ status: 404, body: "" }) : r.continue(); });
  await ctx.route("**/shaka-player.compiled.min.js", (r) => r.fulfill({ body: STUB, contentType: "application/javascript" }));
  // the real page pins the player library by hash; the stand-in cannot match it, so the drive serves
  // the page without the attribute (the hash itself is read from the CDN by live-check.yml)
  await ctx.route(/\/site\/(view|all)\.html/, async (r) => { const res = await r.fetch(); let body = (await res.text()).replace(/ integrity="[^"]+" crossorigin="anonymous"/, "");
    // the Apple switch as it would be after a measurement on an iPhone (only when the drive asks for it)
    if (api.appleMeasured) { const before = body; body = body.replace('const FAIRPLAY_MEASURED = { "iPhone/iPad": "", "Mac": "" };', 'const FAIRPLAY_MEASURED = { "iPhone/iPad": "2026-10-11", "Mac": "" };'); if (body === before) throw new Error("the Apple switch was not found in the page"); }
    r.fulfill({ response: res, body }); });
  await ctx.route(/\/web\/research\/drm\/(index\.html)?(\?[^/]*)?$/, async (r) => { const res = await r.fetch(); r.fulfill({ response: res, body: (await res.text()).replace(/ integrity="[^"]+" crossorigin="anonymous"/, "") }); });
  await ctx.route("https://media.axprod.net/**", (r) => r.fulfill({ status: 404, body: "" }));
  await ctx.route(/\/fp-[0-9a-f]{8}\/token\.enc/, (r) => { api.tokenReads = (api.tokenReads || 0) + 1; return api.noPictureToken ? r.fulfill({ status: 404, body: "" }) : r.continue(); });
  return ctx;
}

try {
  const ctx = await mockedContext();
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
  check(api.blobs.length === 1 && api.blobs[0].encoding === "utf-8", "signing in checked the access key with a harmless write");
  const list = await page.textContent("#list");
  check(/Cotton <Bowl>\.jpg/.test(list) && /720×862/.test(list), "the gallery lists the prepared picture with its name escaped");
  const status = await page.textContent("#list .ok").catch(() => "(no .ok status)");
  check(status === "ready" && (await page.$('a[href="view.html?id=' + ID + '"]')) !== null, "a published picture reads ready and shows its protected-view link (status: " + status + ")");
  const st = await page.evaluate(() => JSON.parse(sessionStorage.getItem("ccs-site")));
  check(st && st.keyHex === KEY_HEX && st.photoKeyHex === PHOTO_HEX && st.token === TOKEN && typeof st.at === "number", "the session holds the password key, the picture key and the unsealed access key");
  // 1b. no combined view yet: the page asks the job for one, once, and says what is happening
  await page.waitForFunction(() => /Combining your 1 picture/.test(document.getElementById("all").textContent), null, { timeout: 15000 });
  const askedFor = api.dispatches.filter((x) => x.client_payload.action === "mosaic");
  check(askedFor.length === 1 && askedFor[0].client_payload.key === PHOTO_HEX && Object.keys(askedFor[0].client_payload).sort().join() === "action,ask,key" && /^[0-9a-f]{16}$/.test(askedFor[0].client_payload.ask), "with no combined view the page asks the job for one (the action, the picture key and the request's own id only)");
  check((await page.$("#open-all")) === null, "nothing to open until it is published");
  await publishMosaic();
  await page.waitForSelector("#open-all", { timeout: 20000 });
  check((await page.textContent("#open-all")) === "Open all 1 at once" && /All 1 in one protected view/.test(await page.textContent("#all")), "once published, the gallery offers it: " + (await page.textContent("#all")));
  check(api.dispatches.filter((x) => x.client_payload.action === "mosaic").length === 1, "it does not ask again while the view is current");
  // the same with the eight-minute gap out of the way and a view made an hour ago (so only "it is current"
  // can hold the page back): a page that has never asked still does not ask while it is current
  await publishMosaic(HOUR_AGO);
  await page.evaluate(() => sessionStorage.removeItem("ccs-mosaic-asked"));
  await page.reload(); await page.waitForSelector("#open-all", { timeout: 20000 }); await page.waitForTimeout(1500);
  check(api.dispatches.filter((x) => x.client_payload.action === "mosaic").length === 1, "a current combined view is never asked for again, gap or no gap");
  // 2. upload
  await page.setInputFiles("#files", join(www, "pic.png"));
  await page.waitForFunction(() => /uploaded|refused/.test(document.getElementById("uploads").textContent), null, { timeout: 20000 });
  check(/uploaded/.test(await page.textContent("#uploads")), "the upload is accepted: " + (await page.textContent("#uploads")));
  const uploads = api.blobs.filter((x) => x.encoding === "base64");
  check(uploads.length === 1, "one encrypted blob reached GitHub");
  const sealed = fromBase64(uploads[0].content);
  check((await open(PHOTO, sealed).catch(() => null)) && Buffer.from(await open(PHOTO, sealed)).equals(png), "the blob decrypts with the PICTURE key to the chosen file exactly");
  check((await open(KEY, sealed).catch(() => null)) === null, "the password key does not open it");
  const jobs = () => api.dispatches.filter((x) => x.client_payload.action !== "mosaic");
  const d = jobs()[0] && jobs()[0].client_payload;
  check(jobs().length === 1 && d.action === "add" && /^[0-9a-f]{24}$/.test(d.id) && d.key === PHOTO_HEX && d.blobSha === "b".repeat(40) && d.name === "pic.png" && d.type === "image/png", "the job was asked for with the id, the PICTURE key and the blob; the password key never leaves");
  await page.waitForFunction(() => /being prepared by GitHub/.test(document.getElementById("list").textContent));
  check(/being prepared by GitHub/.test(await page.textContent("#list")), "the new picture shows as being prepared");
  const pend = await page.evaluate(() => JSON.parse(sessionStorage.getItem("ccs-pending")));
  check(pend.length === 1 && pend[0].blobSha === "b".repeat(40) && pend[0].type === "image/png", "the pending entry keeps what a retry needs");
  // 3. delete → "being removed", no Delete button, no view link
  page.once("dialog", (dlg) => dlg.accept());
  await page.click('button[data-del="' + ID + '"]');
  await page.waitForFunction(() => /being removed/.test(document.getElementById("list").textContent), null, { timeout: 10000 });
  const del = jobs()[1] && jobs()[1].client_payload;
  check(del && del.action === "delete" && del.id === ID && del.key === PHOTO_HEX, "delete asks the job to remove the picture");
  check((await page.$('button[data-del="' + ID + '"]')) === null && (await page.$('a[href="view.html?id=' + ID + '"]')) === null, "while the delete is pending the picture shows no Delete button and no view link");
  await page.evaluate(() => sessionStorage.removeItem("ccs-pending")); // forget the pending delete for the view test
  // 4. the protected view (same session)
  await page.goto(BASE + "view.html?id=" + ID);
  await page.waitForFunction(() => window.__photoShown || /held back|not opened/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }); // either way, the checks below name what happened
  const got = await page.evaluate(() => window.__got);
  const title = await page.textContent("#title");
  check(title === "Protected view: Cotton <Bowl>.jpg", "the view names the picture: " + title);
  check(got[0] && got[0][0] === "mem://photo/widevine.mpd" && got[0][1] === 700, "the manifest came from memory, decrypted with the picture key, 700 bytes");
  check(got[1] && got[1][0] === "range" && got[1][1] === 100 && got[1][2] === fileBytes["video-widevine.mp4"][100], "a byte-range request is sliced from the decrypted file");
  check(got[2] && got[2][1] === "rejected", "a file that is not there is refused");
  check((await page.textContent("#r-content")) === "your picture: Cotton <Bowl>.jpg", "the readout's Content line");
  // 4b. the combined view: its own files from memory, the list of pictures, and a tap opens one alone
  await page.goto(BASE + "all.html");
  await page.waitForFunction(() => window.__photoShown || /held back|not opened/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }); // either way, the checks below name what happened
  const gotAll = await page.evaluate(() => window.__got);
  check((await page.textContent("#title")) === "All your pictures, protected (1)", "the combined view says what it is: " + (await page.textContent("#title")));
  check((await page.textContent("#r-content")) === "your pictures: all 1, combined into one protected video", "its readout's Content line");
  check(gotAll[0] && gotAll[0][0] === "mem://photo/widevine.mpd" && gotAll[0][1] === 640 && gotAll[1] && gotAll[1][2] === mosaicBytes["video-widevine.mp4"][100], "its files are the combined view's own, decrypted in memory (640-byte manifest, its own bytes)");
  check((await page.textContent("#tiles")) === "Cotton <Bowl>.jpg" && (await page.$('#tiles a[href="view.html?id=' + ID + '"]')) !== null, "the list names each picture, escaped, with its own link");
  check(await page.evaluate(() => { const h = document.getElementById("title"), st = document.getElementById("stage"); return h.nextElementSibling === st && st.getBoundingClientRect().top < document.getElementById("readout").getBoundingClientRect().top; }), "the pictures come first, right under the title, above the readout");
  await page.locator("#v").scrollIntoViewIfNeeded();
  check(await page.evaluate(() => window.__ccsMosaic && window.__ccsMosaic.width === 1080 && window.__ccsMosaic.tiles.length === 1 && !("name" in window.__ccsMosaic.tiles[0])), "the layout a walker taps by is on the page (sizes and ids only)");
  const spot = await page.evaluate(() => { const r = document.getElementById("v").getBoundingClientRect(); const s = Math.min(r.width / 1080, r.height / 1440); return { x: r.left + (r.width - 1080 * s) / 2 + 540 * s, y: r.top + (r.height - 1440 * s) / 2 + 720 * s }; });
  await page.mouse.click(spot.x, spot.y);
  await page.waitForURL(/view\.html\?id=/, { timeout: 10000 });
  check(page.url().endsWith("view.html?id=" + ID), "a tap on the picture opens it on its own: " + page.url());
  // 4c. a combined view that falls out of date (a second picture is ready): it says so, offers the earlier
  // one, asks only after three minutes out of date, and gives up visibly after twenty (a fake clock)
  api.galleryMode = "two";
  await publishMosaic(); // made just now
  const sctx = await mockedContext();
  const p4 = await sctx.newPage();
  await p4.clock.install();
  await p4.goto(BASE + "index.html");
  await p4.evaluate((s) => sessionStorage.setItem("ccs-site", JSON.stringify({ ...s, at: Date.now() })), st);
  await p4.goto(BASE + "index.html");
  const allText = async () => (await p4.textContent("#all").catch(() => "")) || "";
  const until = async (re, ms) => { const end = Date.now() + ms; while (Date.now() < end) { if (re.test(await allText())) return true; await new Promise((r) => setTimeout(r, 250)); } return false; };
  const asks = () => api.dispatches.filter((x) => x.client_payload.action === "mosaic").length;
  const before = asks();
  check(await until(/made for an earlier set \(1 picture\); it is being remade with your 2/, 20000) && (await p4.textContent("#open-all")) === "Open the earlier one (1)", "out of date: it says so and offers the earlier one: " + (await allText()));
  check(asks() === before, "a freshly made view out of date for under three minutes is not asked for yet");
  api.refuseDispatch = true; // GitHub refuses this one
  await p4.clock.fastForward("03:30");
  const end1 = Date.now() + 15000; while (asks() === before && Date.now() < end1) await new Promise((r) => setTimeout(r, 250));
  check(asks() === before + 1, "after three minutes out of date the page asks once");
  check(await until(/did not take the request/, 15000), "a refused request is shown: " + (await allText()));
  await p4.clock.fastForward("00:30"); await new Promise((r) => setTimeout(r, 2500));
  check(asks() === before + 1, "a refused request is not repeated at the next refresh (it waits the full gap)");
  check(/did not take the request/.test(await allText()), "and the refusal stays on screen at that refresh");
  api.refuseDispatch = false;
  // the site cannot be reached for a refresh: the page keeps the view it knew instead of "Combining…"
  api.metaAbort = true;
  await p4.clock.fastForward("00:30"); await new Promise((r) => setTimeout(r, 2500));
  check(/made for an earlier set \(1 picture\)/.test(await allText()) && !/Combining/.test(await allText()), "a network error keeps the view it knew: " + (await allText()));
  api.metaAbort = false;
  // the job's own run makes it current: the page offers all of them, and the old refusal is gone
  await publishMosaic(undefined, [ID, ID2]);
  await p4.clock.fastForward("00:30");
  check(await until(/All 2 in one protected view/, 15000) && !/did not take the request/.test(await allText()), "once current, it offers all 2 and the refusal is gone: " + (await allText()));
  await sctx.close();
  // 4d. out of date for twenty minutes: it gives up visibly and stops asking; "Ask again" asks, says so,
  // and keeps the page refreshing until the remade view arrives
  await publishMosaic();
  api.galleryMode = "two";
  const dctx = await mockedContext(); const p5 = await dctx.newPage();
  await p5.clock.install(); await p5.goto(BASE + "index.html");
  await p5.evaluate((s) => sessionStorage.setItem("ccs-site", JSON.stringify({ ...s, at: Date.now() })), st);
  await p5.goto(BASE + "index.html");
  const t5 = async () => (await p5.textContent("#all").catch(() => "")) || "";
  const until5 = async (re, ms) => { const end = Date.now() + ms; while (Date.now() < end) { if (re.test(await t5())) return true; await new Promise((r) => setTimeout(r, 250)); } return false; };
  await until5(/made for an earlier set/, 20000);
  const b5 = asks();
  await p5.clock.fastForward("03:30"); await new Promise((r) => setTimeout(r, 2500));
  check(asks() === b5 + 1, "asked once after three minutes");
  await p5.clock.fastForward("20:00");
  check(await until5(/not caught up after twenty minutes/, 15000) && (await p5.$("#ask-all")) !== null, "after twenty minutes it says so, with the job link and Ask again: " + (await t5()));
  check(asks() === b5 + 1, "and it does not keep asking after giving up");
  await p5.click("#ask-all");
  check(await until5(/Asked again at/, 15000) && asks() === b5 + 2, "Ask again asks and says so: " + (await t5()));
  await publishMosaic(undefined, [ID, ID2]);
  await p5.clock.fastForward("00:30");
  check(await until5(/All 2 in one protected view/, 15000) && !/being remade/.test(await t5()), "and the page keeps refreshing until the remade view arrives, then no longer says it is being remade (its clock twenty minutes ahead of the job's): " + (await t5()));
  await dctx.close();
  // the three timing rules, each on its own fresh page and fake clock
  async function clockPage(mode, opts = {}) {
    api.galleryMode = mode;
    const c = await mockedContext(opts); const pg = await c.newPage();
    await pg.clock.install(); await pg.goto(BASE + "index.html");
    await pg.evaluate((s) => sessionStorage.setItem("ccs-site", JSON.stringify({ ...s, at: Date.now() })), st);
    await pg.goto(BASE + "index.html");
    await pg.waitForFunction(() => !document.getElementById("all").hidden && document.getElementById("all").textContent.length > 0, null, { timeout: 20000 });
    await new Promise((r) => setTimeout(r, 1500));
    return { c, pg };
  }
  const settle = async (pg, t) => { await pg.clock.fastForward(t); await new Promise((r) => setTimeout(r, 2500)); };
  // (0) the very first look at the combined view fails (the site cannot be reached): no request while
  // its state is unknown; once the site answers that there is none, the page asks
  api.metaAbort = true; api.noMosaic = true;
  const k0 = asks(); // counted BEFORE the page loads, so a request made at load is seen
  let { c: c0, pg: p0 } = await clockPage("normal");
  await settle(p0, "00:30");
  check(asks() === k0, "the combined view's state unknown (the site unreachable): no request");
  api.metaAbort = false;
  await settle(p0, "00:30");
  check(asks() === k0 + 1, "once the site answers that there is none, the page asks");
  await c0.close(); api.noMosaic = false;
  // (t) a view that left a picture out counts as current, so the page would stop refreshing: "Try again" asks, under
  // its own request id, says so, and keeps refreshing until the job's answer carries that id. The job may keep the view
  // as it is (a rebuild would remove its Apple form; the tenth review: the page then said "being remade" for ten minutes):
  // the page shows that answer with its reason, at this device's own time (America/Chicago here), and stops waiting.
  // Asked again, nothing else that changes the record counts as the answer (the eleventh review: another tab's answer,
  // or the weekly renewal of its Apple form, did): only the view that carries the new id
  const FORM = { keyUri: "skd://x", master: "fp-1a2b3c4d/master.m3u8", license: OWN_LICENSE, comKeyId: "0e2c58d1-7c4b-4f3e-9a51-3d1f0b7e6a42", verified: true, expires: new Date(Date.now() + 300 * 86400000).toISOString() };
  const builtT = new Date().toISOString(), leftOutT = [{ id: ID2, name: "second.jpg", reason: "test" }];
  const lastAsk = () => api.dispatches.filter((x) => x.client_payload.action === "mosaic").at(-1).client_payload.ask;
  const inChicago = (iso, o) => new Intl.DateTimeFormat("en-US", { timeZone: "America/Chicago", ...o }).format(new Date(iso));
  const chicagoTime = (iso) => inChicago(iso, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
  await publishMosaic(builtT, [ID], leftOutT, FORM);
  const kt = asks();
  const { c: ct, pg: pt } = await clockPage("two", { timezoneId: "America/Chicago" });
  const tt = async () => (await pt.textContent("#all")) || "";
  check(/Left out \(could not be read back\): second\.jpg/.test(await tt()) && asks() === kt, "a picture left out is named, with Try again, and nothing is asked on its own: " + (await tt()));
  await pt.click("#ask-all");
  await new Promise((r) => setTimeout(r, 1500));
  const ask1 = lastAsk();
  check(asks() === kt + 1 && /^[0-9a-f]{16}$/.test(ask1 || "") && /Asked again at/.test(await tt()), "Try again asks, under its own request id, and says so: " + ask1);
  const keptAt = new Date().toISOString(), WHY = "rebuilding it would remove its Apple form, and Axinom did not accept our key (Axinom: a test)";
  await publishMosaic(builtT, [ID], leftOutT, FORM, { at: keptAt, why: WHY }, [ask1]);
  await settle(pt, "00:30");
  const tk = await tt();
  check(new RegExp(`Last tried at (?:[A-Z][a-z]{2} \\d\\d )?${chicagoTime(keptAt)}: kept as it is — rebuilding it would remove its Apple form, and Axinom did not accept our key \\(Axinom: a test\\)`).test(tk) && !/being remade/.test(tk) && /Try again/.test(tk), `the job's answer, kept as it is, is shown with its reason at this device's own time (${chicagoTime(keptAt)} in Chicago); nothing says it is being remade; Try again stays: ` + tk);
  const reads = api.metaReads;
  await settle(pt, "00:30"); await settle(pt, "00:30");
  check(api.metaReads === reads, `and the page stops waiting for a remake that is not coming (${api.metaReads - reads} more reads of the view)`);
  await pt.click("#ask-all");
  await new Promise((r) => setTimeout(r, 1500));
  const ask2 = lastAsk();
  check(asks() === kt + 2 && ask2 !== ask1 && /Asked again at .*being remade/.test(await tt()), "asked again, under a new id: the earlier answer is not taken for this one: " + (await tt()));
  // another tab's answer lands in the record meanwhile (a new note, another id): not this request's answer
  await publishMosaic(builtT, [ID], leftOutT, FORM, { at: new Date().toISOString(), why: "another tab's answer (a test)" }, ["0123456789abcdef", ask1]);
  await settle(pt, "00:30");
  check(/Asked again at .*being remade/.test(await tt()), "another tab's answer in the record is not taken for this one: " + (await tt()));
  // the weekly run renews the view's Apple form meanwhile (a new form, the note gone, no id added): not the answer either
  const r0 = api.metaReads;
  await publishMosaic(builtT, [ID], leftOutT, { ...FORM, master: "fp-5e6f7a8b/master.m3u8" }, null, ["0123456789abcdef", ask1]);
  await settle(pt, "00:30");
  check(/Asked again at .*being remade/.test(await tt()) && api.metaReads > r0, "nor is a renewal of its Apple form: the page keeps waiting, and reading: " + (await tt()));
  // its own answer: a view remade with both pictures, carrying the new id
  await publishMosaic(new Date((await pt.evaluate(() => Date.now())) + 60000).toISOString(), [ID, ID2], [], FORM, null, [ask2, "0123456789abcdef", ask1]);
  await settle(pt, "00:30");
  check(/All 2 in one protected view/.test(await tt()) && !/Left out|being remade|kept as it is/.test(await tt()), "and the page keeps refreshing until its own answer arrives: " + (await tt()));
  await ct.close();
  // an answer from days ago reads with its day (Chicago time), never as if it were today
  const oldAt = new Date(Date.now() - 3 * 86400000).toISOString();
  await publishMosaic(builtT, [ID], leftOutT, FORM, { at: oldAt, why: WHY });
  const { c: co, pg: po } = await clockPage("two", { timezoneId: "America/Chicago" });
  const want = `Last tried at ${inChicago(oldAt, { month: "short", day: "2-digit" })} ${chicagoTime(oldAt)}: kept as it is`;
  check(((await po.textContent("#all")) || "").includes(want), `an answer from three days ago shows its day: "${want}" in: ` + (await po.textContent("#all")));
  await co.close();
  // Try again, then the left-out picture deleted before the job runs: its answer drops the stale entry and changes
  // nothing else (the same build time, no note); the view is then complete, so the page stops saying "being remade",
  // id or no id (the eleventh review: it said so for ten minutes)
  await publishMosaic(builtT, [ID], leftOutT, FORM);
  const { c: cd, pg: pd } = await clockPage("two");
  await pd.click("#ask-all"); await new Promise((r) => setTimeout(r, 1500));
  const askD = lastAsk();
  api.galleryMode = "normal";
  await publishMosaic(builtT, [ID], [], FORM, null, [askD]);
  await settle(pd, "00:30");
  const td = (await pd.textContent("#all")) || "";
  check(/All 1 in one protected view/.test(td) && !/being remade|Left out/.test(td), "Try again, then the left-out picture deleted: the answer (stale entry dropped, nothing else changed) leaves a complete view, and nothing says it is being remade: " + td);
  await cd.close();
  // an answer that never comes (the job failed, or GitHub replaced the waiting run with a newer request): after ten
  // minutes the page stops saying "being remade" and stops reading the view (the twelfth review: no test held this)
  await publishMosaic(builtT, [ID], leftOutT, FORM);
  const { c: cz, pg: pz } = await clockPage("two");
  await pz.click("#ask-all"); await new Promise((r) => setTimeout(r, 1500));
  await settle(pz, "05:00");
  check(/Asked again at .*being remade/.test((await pz.textContent("#all")) || ""), "no answer yet, five minutes on: still waiting");
  await settle(pz, "05:30");
  const tz = (await pz.textContent("#all")) || "", rz = api.metaReads;
  await settle(pz, "00:30"); await settle(pz, "00:30");
  check(!/being remade/.test(tz) && api.metaReads === rz, `no answer after ten minutes: it stops saying so, and stops reading the view (${api.metaReads - rz} more reads): ` + tz);
  await cz.close();
  // (a) a picture ready just now and no combined view yet: the job's own run gets three minutes first
  api.noMosaic = true;
  freshSealed = await sealFresh();
  let n0 = asks(), { c: ca, pg: pa } = await clockPage("fresh");
  check(asks() === n0 && /Combining your 1 picture/.test(await pa.textContent("#all")), "a picture ready just now, no combined view: no request at once (the job's own run is on its way)");
  await settle(pa, "02:00");
  check(asks() === n0, "still none two minutes later");
  await settle(pa, "01:30");
  check(asks() === n0 + 1, "three minutes after the last change, the page asks");
  await ca.close(); api.noMosaic = false;
  // (b) a view made BEFORE the last change (made two hours ago, pictures ready an hour ago): ask at once
  await publishMosaic(new Date(Date.now() - 2 * 3600 * 1000).toISOString());
  n0 = asks(); const { c: cb } = await clockPage("two");
  check(asks() === n0 + 1, "a view made before the last change is asked for at once");
  await cb.close();
  // (c) a view made after the last change but out of date here: the three-minute wait restarts when the set changes
  await publishMosaic();
  n0 = asks(); const { c: cc, pg: pc } = await clockPage("two");
  await settle(pc, "02:00");
  check(asks() === n0, "out of date for two minutes: no request yet");
  api.galleryMode = "three";
  await settle(pc, "02:00");
  check(asks() === n0 && /your 3/.test(await pc.textContent("#all")), "the set changed (a third picture): the wait starts again, still no request after four minutes in all");
  // the page saw the change at its refresh at four minutes, so its own three minutes run from there
  await settle(pc, "03:30");
  check(asks() === n0 + 1, "three minutes after the page saw the set change, it asks");
  await cc.close(); api.galleryMode = "normal";
  // 4e. APPLE, as an iPhone sees it (Safari's own engine; every iPhone browser is one)
  const IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
  const MAC_SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
  async function applePage(ua, path, init) {
    const c = await mockedContext({ userAgent: ua }); const pg = await c.newPage();
    if (init) await pg.addInitScript(init);
    await pg.goto(BASE + "index.html");
    await pg.evaluate((s) => sessionStorage.setItem("ccs-site", JSON.stringify({ ...s, at: Date.now() })), st);
    await pg.goto(BASE + path);
    return { c, pg };
  }
  const licenceHeaders = (pg) => pg.evaluate(() => { const r = { headers: {} }; for (const f of window.__reqFilters || []) f(2, r); return r.headers; });
  const jwtKid = (t) => { try { return JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()).message.content_keys_source.inline[0].id; } catch { return null; } };
  // (1) unmeasured: the picture is held back, and never reaches the player
  let { c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID);
  await ap.waitForFunction(() => /held back/.test(document.getElementById("r-ks").textContent) || window.__photoShown, null, { timeout: 20000 }); // either way, the checks below name what happened
  check(/held back — Apple FairPlay is not yet measured on iPhone\/iPad/.test(await ap.textContent("#r-ks")) && /Apple FairPlay is not yet measured here/.test(await ap.textContent("#r-rule")), "an iPhone, Apple unmeasured: the picture is held back, and the readout says why: " + (await ap.textContent("#r-ks")));
  check((await ap.evaluate(() => window.__manifests.length)) === 0 && !(await ap.evaluate(() => window.__photoShown)), "and nothing was given to the player");
  check(/Apple devices aren't confirmed yet/.test(await ap.textContent("#msg")), "the picture's box says so");
  await ac.close();
  // (2) the Apple test: only the test card, through FairPlay, with Axinom's licence service, certificate and PUBLIC token
  ({ c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID + "&levels=fairplay"));
  await ap.waitForFunction(() => window.__photoShown || /held back/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }); // either way, the checks below name what happened
  const tc = (await ap.evaluate(() => window.__cfgs)).at(-1);
  check((await ap.evaluate(() => window.__photoShown)) === "fairplay-apple" && (await ap.evaluate(() => window.__manifests)).join() === "../web/research/drm/card-fairplay/master.m3u8", "the Apple test plays the test card's Apple form, and only that: " + (await ap.evaluate(() => window.__manifests)).join());
  check(tc.drm.servers["com.apple.fps"] === "https://drm-fairplay-licensing.axprod.net/AcquireLicense" && tc.drm.advanced["com.apple.fps"].serverCertificateUri === "https://tools.axinom.com/FPScert/fairplay.cer", "with Axinom's licence service and evaluation certificate");
  check(jwtKid((await licenceHeaders(ap))["X-AxDRM-Message"]) === "4060a865-8878-4267-9cbf-91ae5bae1e72", "and Axinom's public token for its public test key (the card's), never the picture's");
  check((await ap.textContent("#r-content")) === "the test card (not the photo)" && /APPLE TEST MODE/.test(await ap.textContent("body")), "the readout and the banner say it is the test card");
  await ac.close();
  // (3) the switch flipped (as after a measurement on an iPhone): the picture's own Apple form, by its address, with its own token
  api.appleMeasured = true;
  ({ c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID));
  await ap.waitForFunction(() => window.__photoShown || /held back/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }); // either way, the checks below name what happened
  check((await ap.evaluate(() => window.__photoShown)) === "fairplay-apple" && (await ap.evaluate(() => window.__manifests)).join() === BASE + "photos/" + ID + "/" + FP_MASTER, "measured: the picture plays through its own Apple form, by its full address: " + (await ap.evaluate(() => window.__manifests)).join());
  check((await licenceHeaders(ap))["X-AxDRM-Message"] === PICTURE_TOKEN, "with the picture's own licence token, unsealed in memory");
  const pcfg = (await ap.evaluate(() => window.__cfgs)).at(-1);
  check(pcfg.drm.servers["com.apple.fps"] === OWN_LICENSE, "sent to the licence address its form records (the account's own): " + pcfg.drm.servers["com.apple.fps"]);
  check(/measured black on iPhone\/iPad \(2026-10-11\)/.test(await ap.textContent("#r-expect")), "and the readout names the measurement: " + (await ap.textContent("#r-expect")));
  await ac.close();
  // (4) the combined view, measured: its own Apple form and token
  await publishMosaic(undefined, [ID], [], { keyUri: "skd://x", master: "fp-1a2b3c4d/master.m3u8", license: OWN_LICENSE });
  ({ c: ac, pg: ap } = await applePage(IPHONE, "all.html"));
  await ap.waitForFunction(() => window.__photoShown || /held back/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }); // either way, the checks below name what happened
  check((await ap.evaluate(() => window.__manifests)).join() === BASE + "mosaic/fp-1a2b3c4d/master.m3u8" && (await licenceHeaders(ap))["X-AxDRM-Message"] === "MOSAIC.TOKEN.VALUE" && (await ap.evaluate(() => window.__cfgs)).at(-1).drm.servers["com.apple.fps"] === OWN_LICENSE, "the combined view plays through its own Apple form and token, at its licence address");
  await ac.close(); await publishMosaic();
  // (4b) a picture whose form names a licence address that is not Axinom's: its token is sent nowhere
  await writePhotoMeta("https://licence.example.com/AcquireLicense");
  ({ c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID));
  await ap.waitForFunction(() => /licence address that is not Axinom's/.test(document.getElementById("log").textContent) || window.__photoShown, null, { timeout: 30000 }); // either way, the checks below name what happened
  check(/this clip's Apple form names a licence address that is not Axinom's: refused/.test(await ap.textContent("#log")) && !(await ap.evaluate(() => window.__manifests)).length && !(await ap.evaluate(() => window.__photoShown)), "a form naming another licence address is refused, its token sent nowhere: " + (await ap.textContent("#log")).split("\n")[0]);
  await ac.close();
  // (4c) a picture whose form's token has expired (the date its job recorded): not offered, its token never fetched
  await writePhotoMeta(OWN_LICENSE, { expires: "2026-01-02T03:04:05.000Z" });
  api.tokenReads = 0;
  ({ c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID));
  await ap.waitForFunction(() => /Apple form could not be opened/.test(document.getElementById("log").textContent) || window.__photoShown, null, { timeout: 30000 }); // either way, the checks below name what happened
  check(/this clip's Apple form could not be opened: its licence token expired on 2026-01-02/.test(await ap.textContent("#log")) && !(await ap.evaluate(() => window.__manifests)).length && !(await ap.evaluate(() => window.__photoShown)) && api.tokenReads === 0, `an expired form is not offered, and its token is never fetched (${api.tokenReads} reads): ` + (await ap.textContent("#log")).split("\n")[0]);
  await ac.close(); await writePhotoMeta();
  // (5) a picture whose token cannot be fetched: the Apple attempt says why, instead of failing silently
  api.noPictureToken = true;
  ({ c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID));
  await ap.waitForFunction(() => /Apple form could not be opened/.test(document.getElementById("log").textContent), null, { timeout: 20000 });
  check(/this clip's Apple form could not be opened: its licence token is not on the site yet/.test(await ap.textContent("#log")), "a missing token is named in the attempts: " + (await ap.textContent("#log")).split("\n")[0]);
  await ac.close(); api.noPictureToken = false; api.appleMeasured = false;
  // (6) an iPad asks for desktop sites (it reports itself as a Mac); its touch screen gives it away
  ({ c: ac, pg: ap } = await applePage(MAC_SAFARI, "view.html?id=" + ID, () => Object.defineProperty(Navigator.prototype, "maxTouchPoints", { get: () => 5 })));
  await ap.waitForFunction(() => /held back/.test(document.getElementById("r-ks").textContent) || window.__photoShown, null, { timeout: 20000 }); // either way, the checks below name what happened
  check(/on iPhone\/iPad/.test(await ap.textContent("#r-rule")), "an iPad reporting itself as a Mac is treated as an iPad: " + (await ap.textContent("#r-rule")));
  await ac.close();
  // (7) a Mac in Safari: Apple's path too (held back while unmeasured); Chrome on a Mac keeps its old rule
  ({ c: ac, pg: ap } = await applePage(MAC_SAFARI, "view.html?id=" + ID));
  await ap.waitForFunction(() => /held back/.test(document.getElementById("r-ks").textContent) || window.__photoShown, null, { timeout: 20000 }); // either way, the checks below name what happened
  check(/held back — Apple FairPlay is not yet measured on Mac/.test(await ap.textContent("#r-ks")), "a Mac in Safari: held back until Apple is measured on a Mac: " + (await ap.textContent("#r-ks")));
  await ac.close();

  // (8) a player that says "playing" but shows no frame: never counted as shown (a black capture of nothing measures nothing)
  ({ c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID + "&levels=fairplay", () => { window.__noFrames = true; }));
  await ap.waitForFunction(() => /held back/.test(document.getElementById("r-ks").textContent) || window.__photoShown, null, { timeout: 30000 });
  check(!(await ap.evaluate(() => window.__photoShown)) && /no licence or no decoded frame \(size 0x0\)/.test(await ap.textContent("#log")), "\"playing\" with no frame is not counted as shown: " + (await ap.textContent("#r-ks")));
  await ac.close();

  // 4f. THE ONE LINK (the route-1 page), every device its own way, told at the top what the page detected. Apple's
  // engine is shown FairPlay (the drive's stand-in for Safari's key system) and Safari's own HLS; Axinom's media host
  // is answered here, so nothing leaves the drive.
  const R1 = `http://127.0.0.1:${PORT}/web/research/drm/`, OWN_DIR = join(www, "web", "research", "drm", "card-fairplay-own");
  const R1C = (re) => R1_HTML.match(re)[1];
  const FILM = R1C(/const APPLE_FILM = "([^"]+)"/), FILM_CLEAR = R1C(/const APPLE_FILM_CLEAR = "([^"]+)"/), PUBLIC_TOKEN = R1C(/const AXINOM_PUBLIC_TOKEN = "([^"]+)"/);
  const SHARED_LICENSE = R1C(/const AXINOM_LICENSE = "([^"]+)"/), CERT = R1C(/const AXINOM_CERT = "([^"]+)"/);
  const ownCard = (more = {}) => fs.writeFile(join(OWN_DIR, "current.json"), JSON.stringify({ folder: "1a2b3c4d", license: OWN_LICENSE, expires: new Date(Date.now() + 30 * 86400000).toISOString(), ...more }));
  await ownCard();
  const SAFARI_PARTS = (fps) => `(() => { Object.defineProperty(Navigator.prototype, "requestMediaKeySystemAccess", { configurable: true, value: (ks) => ${fps} && ks === "com.apple.fps" ? Promise.resolve({ keySystem: ks }) : Promise.reject(new DOMException("not in this browser", "NotSupportedError")) });
    const cpt = HTMLMediaElement.prototype.canPlayType; HTMLMediaElement.prototype.canPlayType = function (t) { return /mpegurl/i.test(t) ? "maybe" : cpt.call(this, t); }; })()`;
  async function oneLink(ua, query = "", init = "") {
    const c = await mockedContext(ua ? { userAgent: ua } : {}); const pg = await c.newPage();
    if (init) await pg.addInitScript(init);
    await pg.goto(R1 + query);
    return { c, pg };
  }
  const shown = (pg, id) => pg.evaluate((i) => { const e = document.getElementById(i); return !!e && !e.closest("[hidden]"); }, id);
  const players = (pg) => pg.evaluate(() => (window.__players || []).map((p) => { const r = { headers: {} }; for (const f of p.reqFilters || []) f(2, r);
    const d = (p.cfg && p.cfg.drm) || {}; return { m: p.m, server: (d.servers || {})["com.apple.fps"] || null, cert: ((d.advanced || {})["com.apple.fps"] || {}).serverCertificateUri || null, token: r.headers["X-AxDRM-Message"] || null }; }));
  // (1) an iPhone and a Mac in Safari: Apple's test, and nothing of the photo's
  for (const [ua, device, platform] of [[IPHONE, "an iPhone or iPad", "iPhone\\/iPad"], [MAC_SAFARI, "a Mac", "Mac"]]) {
    let { c: rc, pg: rp } = await oneLink(ua, "", SAFARI_PARTS(true));
    await rp.waitForFunction(() => document.getElementById("o-play").textContent !== "—", null, { timeout: 30000 }).catch(() => {}); // either way, the checks below name what happened
    const det = await rp.textContent("#detected");
    check(new RegExp(`^Detected: Safari on ${device} \\(as the browser reports itself\\)\\. On Apple devices the photo is held back until a screenshot there is measured black, so Apple's test plays below instead\\.$`).test(det), `${device}: the top line names Safari on ${device} and what the page does: ` + det);
    check(await shown(rp, "apple") && !(await shown(rp, "stage")) && !(await shown(rp, "buttons")) && !(await shown(rp, "attempts")), `${device}: Apple's test is shown in the photo's place (the photo's box, its buttons and its attempts hidden)`);
    check((await rp.textContent("#r-fps")) === "available in this browser", `${device}: FairPlay found: ` + (await rp.textContent("#r-fps")));
    const ps = await players(rp);
    check(JSON.stringify(ps.map((p) => p.m)) === JSON.stringify([FILM, "card-fairplay/master.m3u8", "card-fairplay-own/1a2b3c4d/master.m3u8"]), `${device}: the film, the card and our account's card are played, in that order, and nothing else: ` + ps.map((p) => p.m).join(", "));
    check(ps.length === 3 && ps.slice(0, 2).every((p) => p.server === SHARED_LICENSE && p.token === PUBLIC_TOKEN) && ps[2].server === OWN_LICENSE && ps[2].token === R1_OWN_TOKEN && ps.every((p) => p.cert === CERT),
      `${device}: the film and the card with Axinom's public token at its shared address; our card with its folder's own token at the account's own address; Axinom's certificate for each`);
    check((await rp.evaluate(() => document.getElementById("vc").src)) === FILM_CLEAR, `${device}: the control is the film unprotected, by Safari's own HLS`);
    check(!(await rp.evaluate(() => window.__photoShown)) && !(await rp.evaluate(() => window.__manifests)).some((m) => /\.mpd$|widevine|playready/.test(m)), `${device}: the photo is never given to a player`);
    check(new RegExp(`held back — Apple FairPlay is not yet measured on ${platform}`).test(await rp.textContent("#r-ks")) && /Apple's test on this page measures that/.test(await rp.textContent("#r-rule")) && /take the screenshot of Apple's test above instead/.test(await rp.textContent("#r-expect")), `${device}: the readout says the photo is held back, and what to capture instead`);
    await rc.close();
  }
  // (2) our card's folder expired, or at another host: not played, and the tile says why; the other two still are
  for (const [more, why] of [[{ expires: "2026-01-02T03:04:05.000Z" }, /its token expired on 2026-01-02/], [{ license: "https://licence.example.com/AcquireLicense" }, /refused: its licence address is not Axinom's/]]) {
    await ownCard(more);
    let { c: rc, pg: rp } = await oneLink(IPHONE, "", SAFARI_PARTS(true));
    await rp.waitForFunction(() => document.getElementById("o-play").textContent !== "—", null, { timeout: 30000 }).catch(() => {});
    const ps = await players(rp);
    check(why.test(await rp.textContent("#o-play")) && JSON.stringify(ps.map((p) => p.m)) === JSON.stringify([FILM, "card-fairplay/master.m3u8"]), "our card, " + JSON.stringify(more) + ": not played, and its tile says why: " + (await rp.textContent("#o-play")));
    await rc.close();
  }
  await ownCard();
  // (3) an iPhone browser without FairPlay (an app's built-in browser): the tiles say so, the control still plays
  ({ c: ac, pg: ap } = await oneLink(IPHONE.replace(" Version/17.5 Mobile/15E148 Safari/604.1", " Mobile/15E148 [FBAN/FBIOS;FBAV/470.0]"), "", SAFARI_PARTS(false)));
  await ap.waitForFunction(() => /not available/.test(document.getElementById("r-fps").textContent), null, { timeout: 20000 }).catch(() => {});
  check(/^not available here/.test(await ap.textContent("#r-fps")) && /not attempted/.test(await ap.textContent("#p-play")) && (await ap.evaluate(() => (window.__players || []).length)) === 0 && (await ap.evaluate(() => document.getElementById("vc").src)) === FILM_CLEAR,
    "an iPhone browser with no FairPlay: the protected tiles say not attempted, none is played, the control still is: " + (await ap.textContent("#r-fps")));
  check(/^Detected: an app's built-in browser on an iPhone or iPad/.test(await ap.textContent("#detected")), "and the top line names an app's built-in browser: " + (await ap.textContent("#detected")));
  await ac.close();
  // (4) the Apple test mode on an iPhone: only its own test (the card in the photo's box), not Apple's test beside it
  ({ c: ac, pg: ap } = await oneLink(IPHONE, "?levels=fairplay", SAFARI_PARTS(true)));
  await ap.waitForFunction(() => window.__photoShown || /held back/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }).catch(() => {});
  check(!(await shown(ap, "apple")) && (await ap.evaluate(() => window.__photoShown)) === "fairplay-apple" && (await ap.evaluate(() => window.__manifests)).join() === "card-fairplay/master.m3u8", "?levels=fairplay on an iPhone: the card in the photo's box, and Apple's test not run beside it: " + (await ap.evaluate(() => window.__manifests)).join());
  check(/^Detected: Safari on an iPhone or iPad \(as the browser reports itself\)\. This link runs a test, on the test card/.test(await ap.textContent("#detected")), "and the top line says it is a test: " + (await ap.textContent("#detected")));
  await ac.close();
  // (5) the other devices: the photo their own way, Apple's test never run, and the top line naming each
  const WIN_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
  const ANDROID_CHROME = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36";
  const MAC_CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
  const LINUX_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
  for (const [ua, name, says] of [[WIN_CHROME, "Chrome on Windows", /through the browser's protected path \(the readout below says which kind was granted\)\. On an iPhone, iPad or Mac, this same link runs Apple's own test in Safari\.$/],
    [ANDROID_CHROME, "Chrome on Android", /through the browser's protected path \(the readout below says which kind was granted\)\. On an iPhone, iPad or Mac, this same link runs Apple's own test in Safari\.$/],
    [MAC_CHROME, "Chrome on a Mac", /only with hardware protection; if this browser has none, it is held back and the box below says where to open it instead\. In Safari on this Mac, this same link runs Apple's own test\.$/],
    [LINUX_FIREFOX, "Firefox on Linux", /only with hardware protection; if this browser has none, it is held back and the box below says where to open it instead\. On an iPhone, iPad or Mac, this same link runs Apple's own test in Safari\.$/]]) {
    ({ c: ac, pg: ap } = await oneLink(ua));
    await ap.waitForFunction(() => window.__photoShown || /held back/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }).catch(() => {});
    const det = await ap.textContent("#detected");
    check(det.startsWith(`Detected: ${name} (as the browser reports itself). The photo is shown here `) && says.test(det), `${name}: the top line: ` + det);
    check(!(await shown(ap, "apple")) && (await shown(ap, "stage")) && !(await ap.evaluate(() => window.__manifests)).some((m) => /axprod|card-fairplay/.test(m)), `${name}: Apple's test is not run; the photo's own box is there`);
    await ac.close();
  }
  // (6) where nothing this page accepts is offered, the box says where to open the link instead, by what was detected
  for (const [ua, where] of [[MAC_CHROME, /On this Mac, open this link in Safari: Apple's test runs there\. The photo shows on an Android phone, or on a Windows PC in Chrome or Edge\.$/],
    [LINUX_FIREFOX, /On Linux no browser keeps protected video out of a screenshot \(measured on a test machine\)\. The photo shows on an Android phone, or on a Windows PC in Chrome or Edge\.$/],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", /On this PC, open this link in Chrome or Edge \(screenshots measured black there\)\.$/]]) {
    ({ c: ac, pg: ap } = await oneLink(ua, "", "window.__refuseAll = true;"));
    await ap.waitForFunction(() => /held back/.test(document.getElementById("r-ks").textContent), null, { timeout: 30000 }).catch(() => {});
    check(/^This browser hasn't been confirmed to keep the photo out of screenshots, so it isn't shown here\. /.test(await ap.textContent("#msg")) && where.test(await ap.textContent("#msg")), "nothing accepted, the box says where instead: " + (await ap.textContent("#msg")));
    await ac.close();
  }
  // (7) the site's own pages keep the picture held back on an iPhone, with no Apple's test of their own
  ({ c: ac, pg: ap } = await applePage(IPHONE, "view.html?id=" + ID));
  await ap.waitForFunction(() => /held back/.test(document.getElementById("r-ks").textContent), null, { timeout: 20000 }).catch(() => {});
  check(!(await shown(ap, "apple")) && (await ap.evaluate(() => (window.__players || []).length)) === 0 && /^Detected: Safari on an iPhone or iPad \(as the browser reports itself\)\. On Apple devices the photo is held back until a screenshot there is measured black\.$/.test(await ap.textContent("#detected")),
    "a site page on an iPhone: the picture held back, no Apple's test there, and the top line says so: " + (await ap.textContent("#detected")));
  await ac.close();

  // 5. the view without a session goes to the password; an expired session too
  const fresh = await mockedContext();
  const p2 = await fresh.newPage(); await p2.goto(BASE + "view.html?id=" + ID); await p2.waitForURL(/index\.html\?then=/);
  check(/index\.html\?then=/.test(p2.url()), "the view without a session sends you to the password first");
  await p2.goto(BASE + "all.html"); await p2.waitForURL(/index\.html\?then=all/);
  await p2.fill("#pw", PASSWORD); await p2.click("#go");
  await p2.waitForURL(/all\.html/, { timeout: 20000 });
  check(/\/all\.html$/.test(p2.url()), "the combined view without a session asks for the password, then opens: " + p2.url());
  await p2.evaluate((s) => sessionStorage.setItem("ccs-site", JSON.stringify({ ...s, at: Date.now() - 5 * 3600 * 1000 })), st);
  await p2.goto(BASE + "index.html");
  check(await p2.isVisible("#lock"), "a session older than four hours asks for the password again");
  await fresh.close();
  // 6. a gallery written under another password: warning shown, uploads still possible
  api.galleryMode = "foreign";
  const fctx = await mockedContext();
  const p3 = await fctx.newPage(); await p3.goto(BASE + "index.html");
  await p3.evaluate((s) => sessionStorage.setItem("ccs-site", JSON.stringify(s)), st);
  await p3.goto(BASE + "index.html");
  await p3.waitForFunction(() => !document.getElementById("foreign").hidden, null, { timeout: 10000 });
  check(await p3.isVisible("#foreign") && !(await p3.isDisabled("#files")), "another password's gallery: the warning shows and uploading stays possible");
  await fctx.close(); api.galleryMode = "normal";
  // 7. set-up
  await page.goto(BASE + "setup.html");
  await page.fill("#t", TOKEN); await page.fill("#p", "short"); await page.fill("#p2", "short"); await page.click("#go");
  await page.waitForFunction(() => document.getElementById("msg").textContent.length > 0);
  check(/at least 12/.test(await page.textContent("#msg")), "set-up refuses a short password");
  await page.fill("#p", PASSWORD); await page.fill("#p2", PASSWORD); await page.click("#go");
  await page.waitForFunction(() => /Done|refused|differ|answered|cannot/.test(document.getElementById("msg").textContent), null, { timeout: 30000 });
  check(/Done/.test(await page.textContent("#msg")), "set-up completes: " + (await page.textContent("#msg")));
  const put = api.puts[0];
  const written = put && JSON.parse(Buffer.from(put.content, "base64").toString("utf8"));
  check(put && put.sha === "deadbeef" && written.salt === REPO_SALT && written.iterations === 1000, "config.json is rewritten with the salt the REPOSITORY holds (not the served copy) and the file's sha");
  const tok = written && (await openText(await deriveKey(PASSWORD, written.salt, written.iterations), fromBase64(written.tokenEnc)).catch(() => null));
  check(tok === TOKEN, "the saved access key unseals with the password to the token");
  check(errors.length === 0, "no page errors" + (errors.length ? ": " + errors.join("; ") : ""));
} finally {
  await b.close(); server.kill();
}
console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
process.exit(failed ? 1 : 0);
