// Drives the test site's three pages in a real browser against a MOCKED GitHub API (route
// interception), with the real crypto in the browser: wrong and right password, the gallery, an
// upload (the mock receives an encrypted blob that decrypts to the chosen file), a delete and its
// "being removed" state, a gallery written under another password, the set-up page (config.json
// rewritten with the repository's own salt and a sealed access key), and the protected view (files
// decrypted in memory and served to a stand-in player through the mem:// scheme, byte ranges included),
// and the combined view (asked for when none exists, offered once it is published, opened from its own
// files, a tap on a picture opening that picture alone, and the password first when signed out).
// The sandbox's Chromium has no DRM module, so real playback is not exercised here.
//   node tools/drive-site.mjs   (Playwright from PLAYWRIGHT_PKG's package, Chromium at CHROME)
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
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
await fs.writeFile(join(photoDir, "meta.json.enc"), await sealText(PHOTO, JSON.stringify({ id: ID, name: "Cotton <Bowl>.jpg", width: 720, height: 862, prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930" })));
// the combined view's files, written into the served copy only once the drive has seen the page ask for it
const mosaicBytes = {};
async function publishMosaic(builtAt = new Date().toISOString()) {
  const dir = join(www, "site", "mosaic");
  await fs.mkdir(dir, { recursive: true });
  for (const [f, size] of [["widevine.mpd", 640], ["video-widevine.mp4", 40000], ["playready.mpd", 650], ["video-playready.mp4", 40010]]) {
    const b = new Uint8Array(size); for (let i = 0; i < size; i++) b[i] = (i * 11 + size) & 255; mosaicBytes[f] = b;
    await fs.writeFile(join(dir, f + ".enc"), await seal(PHOTO, b));
  }
  await fs.writeFile(join(dir, "meta.json.enc"), await sealText(PHOTO, JSON.stringify({ kind: "mosaic", width: 1080, height: 1440, cols: 1, rows: 1, prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930", builtAt,
    ids: [ID], tiles: [{ id: ID, name: "Cotton <Bowl>.jpg", x: 6, y: 8, w: 1068, h: 1424 }], skipped: [] })));
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
const JUST_NOW = new Date().toISOString();
const freshSealed = await sealText(PHOTO, JSON.stringify({ updatedAt: JUST_NOW, photos: [{ ...JSON.parse(galleryJson).photos[0], readyAt: JUST_NOW }] }));
const foreignSealed = await sealText(await derivePhotoKey(await deriveKey("some other password here", cfg.salt, 1000)), galleryJson);
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

const api = { blobs: [], dispatches: [], puts: [], galleryMode: "normal" };
const b = await chromium.launch({ executablePath: process.env.CHROME || "/opt/pw-browsers/chromium-1194/chrome-linux/chrome", args: ["--no-sandbox"] });
const errors = [];
async function mockedContext() {
  const ctx = await b.newContext();
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
  await ctx.route(/\/site\/mosaic\/meta\.json\.enc/, (r) => api.noMosaic ? r.fulfill({ status: 404, body: "" }) : r.continue());
  await ctx.route("**/shaka-player.compiled.min.js", (r) => r.fulfill({ body: STUB, contentType: "application/javascript" }));
  // the real page pins the player library by hash; the stand-in cannot match it, so the drive serves
  // the page without the attribute (the hash itself is read from the CDN by live-check.yml)
  await ctx.route(/\/site\/(view|all)\.html/, async (r) => { const res = await r.fetch(); r.fulfill({ response: res, body: (await res.text()).replace(/ integrity="[^"]+" crossorigin="anonymous"/, "") }); });
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
  check(askedFor.length === 1 && askedFor[0].client_payload.key === PHOTO_HEX && Object.keys(askedFor[0].client_payload).sort().join() === "action,key", "with no combined view the page asks the job for one (action and picture key only)");
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
  await page.waitForFunction(() => window.__photoShown, null, { timeout: 20000 });
  const got = await page.evaluate(() => window.__got);
  const title = await page.textContent("#title");
  check(title === "Protected view: Cotton <Bowl>.jpg", "the view names the picture: " + title);
  check(got[0] && got[0][0] === "mem://photo/widevine.mpd" && got[0][1] === 700, "the manifest came from memory, decrypted with the picture key, 700 bytes");
  check(got[1] && got[1][0] === "range" && got[1][1] === 100 && got[1][2] === fileBytes["video-widevine.mp4"][100], "a byte-range request is sliced from the decrypted file");
  check(got[2] && got[2][1] === "rejected", "a file that is not there is refused");
  check((await page.textContent("#r-content")) === "your picture: Cotton <Bowl>.jpg", "the readout's Content line");
  // 4b. the combined view: its own files from memory, the list of pictures, and a tap opens one alone
  await page.goto(BASE + "all.html");
  await page.waitForFunction(() => window.__photoShown, null, { timeout: 20000 });
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
  api.refuseDispatch = false;
  await p4.clock.fastForward("20:00");
  check(await until(/not caught up after twenty minutes/, 15000) && (await p4.$("#ask-all")) !== null, "after twenty minutes it says so, with the job link and Ask again: " + (await allText()));
  check(asks() === before + 1, "and it does not keep asking after giving up");
  await sctx.close();
  // the three timing rules, each on its own fresh page and fake clock
  async function clockPage(mode) {
    api.galleryMode = mode;
    const c = await mockedContext(); const pg = await c.newPage();
    await pg.clock.install(); await pg.goto(BASE + "index.html");
    await pg.evaluate((s) => sessionStorage.setItem("ccs-site", JSON.stringify({ ...s, at: Date.now() })), st);
    await pg.goto(BASE + "index.html");
    await pg.waitForFunction(() => !document.getElementById("all").hidden && document.getElementById("all").textContent.length > 0, null, { timeout: 20000 });
    await new Promise((r) => setTimeout(r, 1500));
    return { c, pg };
  }
  const settle = async (pg, t) => { await pg.clock.fastForward(t); await new Promise((r) => setTimeout(r, 2500)); };
  // (a) a picture ready just now and no combined view yet: the job's own run gets three minutes first
  api.noMosaic = true;
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
