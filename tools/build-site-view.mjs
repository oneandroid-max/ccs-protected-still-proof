// Generates the test site's two protected pages from the proof's route-1 page, so they never drift
// from it: the same rule, readout and player, with the files served from memory after decryption
// (site/view-prelude.js). site/view.html shows one picture; site/all.html shows the combined view of
// every ready picture (one protected video, built by the site's job). A picture's Apple (FairPlay) form
// is not sealed (Safari plays it from its address, not from memory): the prelude hands the page its
// address and its licence token, which IS sealed. Every substitution must match exactly once or this fails.
// It also STAMPS the site's module URLs with a hash of each file's content (crypto.js inside app.js,
// view-prelude.js and setup.html; app.js inside index.html and setup.html; view-prelude.js inside the two pages), so a
// browser holding an older copy in its cache (Pages caches for ten minutes) never pairs it with a newer
// page, and nobody has to remember to bump a version by hand.
//   node tools/build-site-view.mjs            writes the stamped files and both pages
//   node tools/build-site-view.mjs --check    exits 1 if any of them is stale
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../", import.meta.url));
const SRC = REPO + "web/research/drm/index.html";
const OUTS = { one: "site/view.html", all: "site/all.html" };
const STAMPED = ["site/crypto.js", "site/app.js", "site/view-prelude.js", "site/index.html", "site/setup.html"];

const short = (t) => createHash("sha256").update(t).digest("hex").slice(0, 12);
const stamp = (text, file, version) => text.replace(new RegExp(`"\\./${file.replace(".", "\\.")}(\\?v=[0-9a-z.-]+)?"`, "g"), `"./${file}?v=${version}"`);
// files: { path: text } for STAMPED. Returns the stamped texts and the prelude's version.
export function stampVersions(files) {
  const out = { ...files };
  const c = short(out["site/crypto.js"]);
  for (const f of ["site/app.js", "site/view-prelude.js", "site/setup.html"]) out[f] = stamp(out[f], "crypto.js", c);
  const a = short(out["site/app.js"]);
  for (const f of ["site/index.html", "site/setup.html"]) out[f] = stamp(out[f], "app.js", a);
  return { files: out, preludeVersion: short(out["site/view-prelude.js"]) };
}

function once(html, from, to, label) {
  const i = html.indexOf(from);
  if (i < 0 || html.indexOf(from, i + 1) >= 0) throw new Error(`the route-1 page no longer matches the view template at: ${label}`);
  return html.slice(0, i) + to + html.slice(i + from.length);
}

export function buildView(indexHtml, mode = "one", preludeVersion = "0") {
  if (mode !== "one" && mode !== "all") throw new Error(`unknown view mode ${mode}`);
  const ALL = mode === "all";
  let t = indexHtml;
  t = once(t, "<title>Route 1: the browser's protected video path</title>", ALL ? "<title>All pictures, protected — CCS proof test site</title>" : "<title>Protected view — CCS proof test site</title>", "title");
  t = once(t, "<h1>Route 1: the browser's own protected video path</h1>", '<h1 id="title">Protected view</h1>', "heading");
  // the player library's tag carries its integrity hash (read from the CDN on a runner, live-check.yml)
  const PLAYER = '<script src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/5.2.10/shaka-player.compiled.min.js" integrity="sha384-ZWp1oeFexKioXrhPcPdQ6INqt3fK8DsBJbWzlRdMokbapQn4fKqwPVPox7JNY7wJ" crossorigin="anonymous"></script>';
  t = once(t, PLAYER,
    '<script>' + (ALL ? 'window.__ccsMode = "all"; ' : "") + 'window.__ccsReady = new Promise((r) => { window.__ccsResolve = r; });</script>\n' + PLAYER + '\n<script type="module" src="view-prelude.js?v=' + preludeVersion + '"></script>', "player script");
  t = once(t, "<script>\n(async () => {", '<script>\n(async () => {\n  const CTX = await window.__ccsReady; // decrypted in memory by view-prelude.js\n  document.getElementById("title").textContent = CTX.title;', "page script");
  t = once(t, 'name: "the photo", widevine: "widevine.mpd", playready: "playready.mpd", prKid: "9E0FFABA-46A8-1DEC-DC6F-CE6F0CAFA51A", fairplay: null',
    'name: CTX.content, widevine: "mem://photo/widevine.mpd", playready: "mem://photo/playready.mpd", prKid: CTX.prKidGuid, fairplay: CTX.fairplay', "photo clip");
  t = once(t, 'widevine: "card-widevine.mpd", playready: "card-playready.mpd"',
    'widevine: "../web/research/drm/card-widevine.mpd", playready: "../web/research/drm/card-playready.mpd"', "card clip");
  t = once(t, 'manifest: "card-fairplay/master.m3u8"', 'manifest: "../web/research/drm/card-fairplay/master.m3u8"', "card's Apple form");
  // Apple's test runs on the route-1 page only (the one link for every device); a site page on an iPhone, iPad or Mac
  // holds the picture back and says so. Its own card's folder is still given its address from here, so the lines stay true.
  t = once(t, "const APPLE_TEST_HERE = true;", "const APPLE_TEST_HERE = false; // the site's pages: Apple's test is on the route-1 page", "Apple's test, off");
  t = once(t, 'const CARD_FAIRPLAY_OWN = "card-fairplay-own/";', 'const CARD_FAIRPLAY_OWN = "../web/research/drm/card-fairplay-own/";', "own card's Apple form");
  // what the top line calls what is shown: the combined view's page shows every picture at once
  t = once(t, 'const SHOWN = CARD ? "The test card" : "The photo";', `const SHOWN = CARD ? "The test card" : ${ALL ? '"The combined view"' : '"The photo"'};`, "what is shown");
  t = once(t, '<p><a href="../">Back to the list of candidates</a> · <a href="../../../widevine/">the first Widevine proof (2026-10-09)</a></p>',
    '<p><a href="index.html">Back to your pictures</a></p>', "footer");
  return "<!-- GENERATED by tools/build-site-view.mjs from web/research/drm/index.html — edit those, not this file -->\n" + t;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const src = readFileSync(SRC, "utf8");
  const before = Object.fromEntries(STAMPED.map((f) => [f, readFileSync(REPO + f, "utf8")]));
  const { files, preludeVersion } = stampVersions(before);
  const outputs = { ...files, ...Object.fromEntries(Object.entries(OUTS).map(([mode, file]) => [file, buildView(src, mode, preludeVersion)])) };
  let stale = 0;
  for (const [rel, out] of Object.entries(outputs)) {
    const file = REPO + rel;
    if (process.argv.includes("--check")) {
      let cur = ""; try { cur = readFileSync(file, "utf8"); } catch {}
      if (cur !== out) { console.error(`${file} is stale: run node tools/build-site-view.mjs`); stale++; }
      else console.log(`${file} is up to date`);
    } else { writeFileSync(file, out); console.log(`wrote ${file} (${out.length} bytes)`); }
  }
  if (stale) process.exit(1);
}
