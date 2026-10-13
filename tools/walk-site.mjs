// Walks the LIVE test site the way a person does, in a real browser already running on this machine
// (Chrome or Edge on a GitHub Windows runner, reached through its debugging port): open THE ONE PAGE, type
// the password, read the gallery, wait for the combined view to play INLINE above the gallery, watch it
// play, go full screen, tap a picture (opening it on its own), go back to the one page where the combined
// view plays again. Each step is timed and its screen is captured from
// the operating system (what a person would see), and every capture is SEALED at once to a public key
// whose private half never leaves the reader's machine, because these captures show the owner's
// pictures (a runner has no protected video path, so its captures are not black). The clear capture
// is written OUTSIDE the workspace (the system's temporary folder, which no upload step names) and
// deleted the moment it has been read, before it is sealed. The log prints statuses and counts only: no names, no password.
//   node tools/walk-site.mjs   env: WALK_CDP, WALK_NAME, WALK_OUT, WALK_PUBKEY (base64 DER SPKI),
//                                   SITE_PASSWORD, PLAYWRIGHT_DIR (a folder with playwright-core)
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { createPublicKey, publicEncrypt, randomBytes, createCipheriv, constants } from "node:crypto";

const SITE = "https://oneandroid-max.github.io/ccs-protected-still-proof/site/";
const NAME = process.env.WALK_NAME || "browser", OUT = process.env.WALK_OUT || "walk";
const PASSWORD = process.env.SITE_PASSWORD || "";
const t0 = Date.now();
const stamp = () => `${new Date().toISOString().slice(11, 19)}Z +${((Date.now() - t0) / 1000).toFixed(1)}s`;
const say = (m) => console.log(`${stamp()}  ${m}`);
const results = [];
const step = (ok, what) => { results.push({ ok, what }); say(`${ok ? "ok  " : "FAIL"}  ${what}`); };

if (!PASSWORD) { console.error("SITE_PASSWORD is not set"); process.exit(2); }
const pub = createPublicKey({ key: Buffer.from(process.env.WALK_PUBKEY || "", "base64"), format: "der", type: "spki" });
if (pub.asymmetricKeyType !== "rsa" || pub.asymmetricKeyDetails.modulusLength < 3072) { console.error("the sealing key must be RSA of at least 3072 bits"); process.exit(2); }
await fs.mkdir(OUT, { recursive: true });

// The whole screen, as the operating system draws it, sealed: AES-256-GCM under a fresh key, the key
// wrapped with RSA-OAEP-SHA256 to the reader's public key.
let shot = 0;
async function capture(label) {
  const png = join(tmpdir(), `clear-${NAME}-${++shot}.png`);
  // the path reaches PowerShell through the environment, never quoted into the command
  const ps = "Add-Type -AssemblyName System.Windows.Forms, System.Drawing; $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height; $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size); $bmp.Save($env:CAPTURE_PNG, [System.Drawing.Imaging.ImageFormat]::Png)";
  // a capture that fails is a FAILED step: a walk with no evidence never passes
  try { execFileSync("powershell", ["-NoProfile", "-Command", ps], { stdio: "pipe", env: { ...process.env, CAPTURE_PNG: png } }); }
  catch (e) { step(false, `capture ${label} failed: ${String(e.stderr || e.message).slice(0, 200)}`); return; }
  const clear = await fs.readFile(png);
  await fs.rm(png, { force: true });
  const key = randomBytes(32), iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([c.update(clear), c.final()]);
  const wrapped = publicEncrypt({ key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, key);
  const file = `${NAME}-${String(shot).padStart(2, "0")}-${label}.png.sealed.json`;
  await fs.writeFile(join(OUT, file), JSON.stringify({ wrapped: wrapped.toString("base64"), iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") }));
  say(`captured ${label} (${clear.length} bytes, sealed as ${file})`);
}

const require = createRequire(join(process.env.PLAYWRIGHT_DIR || ".", "package.json"));
const { chromium } = require("playwright-core");
const browser = await chromium.connectOverCDP(process.env.WALK_CDP || "http://127.0.0.1:9222");
const ctx = browser.contexts()[0];
const page = ctx.pages()[0] || await ctx.newPage();
await page.bringToFront();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
const text = (sel) => page.textContent(sel).catch(() => "");
const readout = async () => Object.fromEntries(await Promise.all(["r-rule", "r-ks", "r-granted", "r-expect", "r-lic", "r-play"].map(async (k) => [k, (await text("#" + k)).trim()])));
// The video element itself, not the readout's text (a page handed back from memory brings its old text
// with it): not paused, a decoded frame, and its time moving over a second and a half.
async function videoAdvancing() {
  for (let i = 0; ; i++) {
    try { return await videoOnce(); }
    catch (e) { if (i >= 3 || !/context was destroyed|navigation/i.test(String(e.message))) throw e; await page.waitForTimeout(1000); }
  }
}
async function videoOnce() {
  return page.evaluate(async () => {
    const v = document.getElementById("v"); if (!v) return { ok: false, why: "no video element" };
    const t0 = v.currentTime; await new Promise((r) => setTimeout(r, 1500));
    const r = { paused: v.paused, width: v.videoWidth, height: v.videoHeight, from: +t0.toFixed(2), to: +v.currentTime.toFixed(2), visible: getComputedStyle(v).visibility };
    r.ok = !v.paused && v.videoWidth > 0 && v.currentTime !== t0 && r.visible === "visible";
    return r;
  });
}
async function waitPlaying(label) {
  const until = Date.now() + 90000;
  while (Date.now() < until) {
    const r = await readout();
    if (/playing/.test(r["r-play"]) && !/paused/.test(r["r-play"])) return r;
    if (/held back|not opened|could not/.test(r["r-ks"] + r["r-expect"])) return r;
    await page.waitForTimeout(1000);
  }
  return readout();
}

try {
  say(`${NAME}: ${await browser.version()}`);
  // 1. the site, as a person opens it
  await page.goto(SITE + "index.html", { waitUntil: "load" });
  await page.waitForSelector("#pw", { timeout: 30000 });
  // precondition, not part of the walk: the browser's protected-video module has arrived (a fresh
  // profile fetches it in the first minute); without it the pages rightly hold the pictures back
  let cdm = "";
  for (let i = 0; i < 60 && !cdm.startsWith("yes"); i++) {
    cdm = await page.evaluate(async () => { try { await navigator.requestMediaKeySystemAccess("com.widevine.alpha", [{ initDataTypes: ["cenc"], videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.4d4028"', robustness: "SW_SECURE_DECODE" }] }]); return "yes"; } catch (e) { return "no: " + e.message; } });
    if (!cdm.startsWith("yes")) await page.waitForTimeout(2000);
  }
  say(`the browser's Widevine module: ${cdm}`);
  await page.reload({ waitUntil: "load" });
  await page.waitForSelector("#pw", { timeout: 30000 });
  await capture("sign-in");
  // 2. the password, typed
  await page.click("#pw");
  await page.keyboard.type(PASSWORD, { delay: 35 });
  await page.click("#go");
  await page.waitForSelector("#app:not([hidden])", { timeout: 60000 });
  await page.waitForFunction(() => !/Loading…/.test(document.getElementById("list").textContent), null, { timeout: 60000 });
  const ready = await page.$$eval("#list .ok", (els) => els.filter((e) => e.textContent === "ready").length);
  const cards = await page.$$eval("#list > .card", (els) => els.length);
  step(ready > 0, `signed in; the gallery shows ${cards} picture card(s), ${ready} ready (slots: ${(await text("#slots")).trim()})`);
  await capture("gallery");
  // 3. the combined view plays INLINE on the one page, above the gallery (the owner, 2026-10-12: "one page with all the
  // images"): wait until it is current (the page asks GitHub to (re)make it if needed), playing one "Play the new view"
  // tap if a newer one became ready while we waited
  let last = "", n = 0;
  const until = Date.now() + 15 * 60 * 1000;
  while (Date.now() < until) {
    const all = (await text("#all")).replace(/\s+/g, " ").trim();
    if (all !== last) { say(`gallery, all-at-once card: ${all.replace(/\(could not be read back\):.*$/, "(names withheld)")}`); last = all; }
    const m = /All (\d+) in one protected view above/.exec(all);
    if (m) { n = Number(m[1]); break; }
    if (await page.$("#replay")) { say("a newer combined view is ready; playing it"); await page.click("#replay"); await page.waitForSelector("#app:not([hidden])", { timeout: 60000 }); await page.waitForTimeout(3000); continue; }
    await page.waitForTimeout(5000);
  }
  step(n === ready, `the combined view holds all ${n} ready picture(s), playing inline above the gallery (ready pictures: ${ready})`);
  // 4. it plays, right above the gallery
  const r1 = await waitPlaying("all");
  say(`combined view readout: ${JSON.stringify(r1)}`);
  step(/playing/.test(r1["r-play"]), `the combined view plays: ${r1["r-play"]}`);
  const a1 = await videoAdvancing();
  step(a1.ok, `its video element: ${JSON.stringify(a1)}`);
  step((await text("#title")).trim() === `Your pictures, protected (${n})`, `its title: ${(await text("#title")).trim()}`);
  step(await page.evaluate(() => { const g = document.getElementById("gallery"), st = document.getElementById("stage"); return !!g && !!st && !!(st.compareDocumentPosition(g) & Node.DOCUMENT_POSITION_FOLLOWING) && st.getBoundingClientRect().top < g.getBoundingClientRect().top; }), "the pictures play above the gallery");
  const mosaicN = await page.evaluate(() => (window.__ccsMosaic && window.__ccsMosaic.tiles.length) || 0);
  step(mosaicN === n, `the combined view holds ${mosaicN} tappable picture(s)`);
  await page.locator("#v").scrollIntoViewIfNeeded();
  await page.waitForTimeout(1500);
  await capture("all-playing");
  await page.waitForTimeout(3000);
  const r2 = await readout();
  step(/playing/.test(r2["r-play"]), `still playing three seconds later: ${r2["r-play"]}`);
  // full screen, as a person would press it to see the pictures larger
  await page.click("#fullscreen");
  await page.waitForTimeout(2000);
  const fsOn = await page.evaluate(() => document.fullscreenElement && document.fullscreenElement.id);
  const r2b = await readout();
  step(fsOn === "stage" && /playing/.test(r2b["r-play"]), `full screen: ${fsOn || "not entered"}, ${r2b["r-play"]}`);
  await capture("all-fullscreen");
  // leaving it through the page (a key sent by the walker may not reach the browser's own full-screen handling)
  await page.evaluate(() => document.exitFullscreen && document.exitFullscreen()).catch(() => {});
  await page.waitForTimeout(1000);
  step(await page.evaluate(() => !document.fullscreenElement), "full screen left again");
  await page.locator("#all").scrollIntoViewIfNeeded();
  await capture("all-card");
  // 5. tap a picture (the second, or the first if there is one), on the inline view; first note, in this tab, how the page
  // comes back later (handed back from the browser's memory, or loaded afresh)
  await page.evaluate(() => { window.__walkMark = 1; addEventListener("pageshow", (e) => sessionStorage.setItem("walk-pageshow", e.persisted ? "from memory" : "loaded")); });
  await page.locator("#v").scrollIntoViewIfNeeded();
  const pick = n > 1 ? 1 : 0;
  const spot = await page.evaluate((i) => {
    const m = window.__ccsMosaic, r = document.getElementById("v").getBoundingClientRect(), t = m.tiles[i];
    const s = Math.min(r.width / m.width, r.height / m.height);
    return { x: r.left + (r.width - m.width * s) / 2 + (t.x + t.w / 2) * s, y: r.top + (r.height - m.height * s) / 2 + (t.y + t.h / 2) * s, id: t.id };
  }, pick);
  await page.mouse.click(spot.x, spot.y);
  await page.waitForURL(/view\.html\?id=/, { timeout: 15000 });
  step(page.url().endsWith("view.html?id=" + spot.id), `tapping picture ${pick + 1} opened that picture on its own`);
  const r3 = await waitPlaying("one");
  step(/playing/.test(r3["r-play"]), `the single view plays: ${r3["r-play"]}`);
  const a3 = await videoAdvancing();
  step(a3.ok, `its video element: ${JSON.stringify(a3)}`);
  await page.locator("#v").scrollIntoViewIfNeeded();
  await page.waitForTimeout(1500);
  await capture("one-picture");
  // 6. back, the way a person goes back: to the one page, where the combined view plays again, above the gallery
  // a real browser may restore the page from memory on Back, which fires no "load" event: wait for the
  // address, then for the readout, and record which kind of return it was
  await page.goBack({ waitUntil: "commit", timeout: 15000 });
  // the address alone, polled (waitForURL also waits for a "load" event, which a page handed back from memory never fires)
  for (let i = 0; i < 60 && !/\/site\/(index\.html)?(\?|#|$)/.test(page.url()); i++) await page.waitForTimeout(250);
  // then a FRESH document (the marked one, handed back from memory, reloads itself): never judge the old one
  let fresh = false;
  for (let i = 0; i < 80 && !fresh; i++) { fresh = await page.evaluate(() => !window.__walkMark).catch(() => false); if (!fresh) await page.waitForTimeout(250); }
  step(fresh, "after Back the one page is a freshly loaded page (not the one held in memory)");
  await page.waitForSelector("#app:not([hidden])", { timeout: 30000 });
  const r4 = await waitPlaying("all again");
  const how = await page.evaluate(() => `${sessionStorage.getItem("walk-pageshow")}, then ${(performance.getEntriesByType("navigation")[0] || {}).type}`).catch(() => "?");
  step(/\/site\/(index\.html)?(\?|#|$)/.test(page.url()), `back returns to the one page, still signed in (${how})`);
  step(/playing/.test(r4["r-play"]), `and the combined view plays again, above the gallery: ${r4["r-play"]}`);
  const a4 = await videoAdvancing();
  step(a4.ok, `its video element after Back: ${JSON.stringify(a4)}`);
  await page.locator("#v").scrollIntoViewIfNeeded();
  await page.waitForTimeout(1500);
  await capture("back-to-one-page");
  step(errors.length === 0, `no page errors${errors.length ? ": " + errors.join("; ").slice(0, 400) : ""}`);
} catch (e) {
  step(false, `the walk stopped: ${String(e.message || e).split("\n")[0].slice(0, 300)}`);
  await capture("stopped");
} finally {
  await fs.writeFile(join(OUT, `${NAME}-steps.json`), JSON.stringify({ browser: NAME, at: new Date().toISOString(), results }, null, 1));
  await browser.close().catch(() => {});
}
const failed = results.filter((r) => !r.ok).length;
console.log(failed ? `\n${failed} step(s) FAILED` : "\nevery step passed");
process.exit(failed ? 1 : 0);
