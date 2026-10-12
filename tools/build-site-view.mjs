// Generates the test site's two protected pages from the proof's route-1 page, so they never drift
// from it: the same rule, readout and player, with the files served from memory after decryption
// (site/view-prelude.js). site/index.html is THE ONE PAGE (the owner, 2026-10-12: "I think we should just have one
// page with all the images"): the sign-in, the combined view of every ready picture (one protected video, built by the
// site's job), adding and deleting pictures (site/gallery.js), and Apple's test on an iPhone, iPad or Mac, as on the
// route-1 page. site/view.html shows one picture. (site/all.html, until then the combined view's own page, now only
// forwards to the one page; it is no longer generated.) A picture's Apple (FairPlay) form
// is not sealed (Safari plays it from its address, not from memory): the prelude hands the page its
// address and its licence token, which IS sealed. Every substitution must match exactly once or this fails.
// It also STAMPS the site's module URLs with a hash of each file's content (crypto.js inside app.js,
// view-prelude.js and setup.html; app.js inside gallery.js and setup.html; view-prelude.js inside the two pages and
// gallery.js inside the one page), so a
// browser holding an older copy in its cache (Pages caches for ten minutes) never pairs it with a newer
// page, and nobody has to remember to bump a version by hand.
//   node tools/build-site-view.mjs            writes the stamped files and both pages
//   node tools/build-site-view.mjs --check    exits 1 if any of them is stale
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../", import.meta.url));
const SRC = REPO + "web/research/drm/index.html";
const OUTS = { one: "site/view.html", home: "site/index.html" };
const STAMPED = ["site/crypto.js", "site/app.js", "site/view-prelude.js", "site/gallery.js", "site/setup.html"];

const short = (t) => createHash("sha256").update(t).digest("hex").slice(0, 12);
const stamp = (text, file, version) => text.replace(new RegExp(`"\\./${file.replace(".", "\\.")}(\\?v=[0-9a-z.-]+)?"`, "g"), `"./${file}?v=${version}"`);
// files: { path: text } for STAMPED. Returns the stamped texts and the versions of the prelude and the gallery.
export function stampVersions(files) {
  const out = { ...files };
  const c = short(out["site/crypto.js"]);
  for (const f of ["site/app.js", "site/view-prelude.js", "site/setup.html"]) out[f] = stamp(out[f], "crypto.js", c);
  const a = short(out["site/app.js"]);
  for (const f of ["site/gallery.js", "site/setup.html"]) out[f] = stamp(out[f], "app.js", a);
  return { files: out, preludeVersion: short(out["site/view-prelude.js"]), galleryVersion: short(out["site/gallery.js"]) };
}

// the route-1 page's first script: its address with no parameter opens the one page (a generated page never forwards)
export const FORWARD = '<script>/* THE ONE PAGE (the owner, 2026-10-12: "I think we should just have one page with all the images"): this address with no parameter opens the one page, the test site\'s own (sign in, your pictures, adding them, this same player). Any parameter keeps this page: the test links measure (?clip=card, ?levels=), ?photo shows the test photo (the checks of the rule use it). */ if (!location.search) location.replace("../../../site/" + location.hash);</script>\n';

// the one page's own parts: the sign-in, shown alone until it succeeds (gallery.js), and the gallery under the view
const HOME_STYLE = `<style>
  /* the one page's sign-in and gallery (until 2026-10-12 the test site's page of its own) */
  .muted { color: #6b665c; } .warn { color: #8a5a00; } .small { font-size: 0.85rem; }
  .lockhead { font-size: 1.2rem; font-weight: 700; }
  input[type=password] { font: inherit; padding: 10px 12px; border: 1px solid #d9d4c8; border-radius: 8px; width: 100%; max-width: 360px; box-sizing: border-box; background: #fff; }
  label { display: block; margin: 12px 0 4px; font-size: 0.9rem; color: #6b665c; }
  .btn { font: inherit; padding: 8px 14px; border-radius: 999px; border: 1px solid #d9d4c8; background: #fff; cursor: pointer; text-decoration: none; color: inherit; display: inline-block; }
  .btn.primary { background: #1f4e8c; color: #fff; border-color: #1f4e8c; font-weight: 600; } button.danger { color: #a83a2b; }
  button:disabled { opacity: 0.5; cursor: default; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; } [hidden] { display: none !important; }
  .card { background: #fff; border: 1px solid #d9d4c8; border-radius: 10px; padding: 12px 14px; margin: 10px 0; }
</style>
</head>`;
const LOCK = `<section id="lock">
  <p class="lockhead">CCS proof test site</p>
  <p class="muted">Enter the password to see your pictures, add new ones, and test the protected view on this device.</p>
  <form id="unlock">
    <label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" required autofocus>
    <p><button class="primary" type="submit" id="go">Enter</button> <span id="lockmsg" class="muted"></span></p>
  </form>
</section>
<div id="app" hidden>
`;
const GALLERY = `
<section id="gallery">
  <div id="all" class="card" hidden></div>
  <div class="card">
    <div class="row"><strong>Add pictures</strong> <input id="files" type="file" accept="image/jpeg,image/png,image/webp" multiple> <span id="slots" class="muted"></span></div>
    <p class="muted small">Up to 10 pictures (JPEG, PNG or WebP, 25 MB each). Each one is encrypted in this browser before it leaves and prepared by a GitHub job for the browser's protected path (about two minutes); then it joins the others in the view above. Nothing on this page draws a picture except that protected view.</p>
    <div id="uploads"></div>
  </div>
  <p id="foreign" class="warn" hidden>The pictures already on the site were written under another password, so they cannot be opened or listed here. Upload again; the old files are cleared by the next job.</p>
  <div class="row" style="justify-content:space-between"><h2>Pictures</h2><button id="out">Sign out</button></div>
  <div id="list"><p class="muted">Loading…</p></div>
  <p class="muted small">The jobs that prepare pictures run here: <a href="https://github.com/oneandroid-max/ccs-protected-still-proof/actions/workflows/site-photos.yml">GitHub Actions</a>. This page refreshes itself while a picture is being prepared. Signing in lasts four hours in this tab.</p>
</section>`;

function once(html, from, to, label) {
  const i = html.indexOf(from);
  if (i < 0 || html.indexOf(from, i + 1) >= 0) throw new Error(`the route-1 page no longer matches the view template at: ${label}`);
  return html.slice(0, i) + to + html.slice(i + from.length);
}

export function buildView(indexHtml, mode = "one", preludeVersion = "0", galleryVersion = "0") {
  if (mode !== "one" && mode !== "home") throw new Error(`unknown view mode ${mode}`);
  const HOME = mode === "home";
  let t = indexHtml;
  t = once(t, FORWARD, "", "the one link's forward");
  t = once(t, "<title>Route 1: the browser's protected video path</title>", HOME ? "<title>Your pictures, protected — CCS proof test site</title>" : "<title>Protected view — CCS proof test site</title>", "title");
  if (HOME) t = once(t, "</style>\n</head>", "</style>\n" + HOME_STYLE, "the one page's style");
  t = once(t, "<h1>Route 1: the browser's own protected video path</h1>", HOME ? LOCK + '<h1 id="title">Your pictures, protected</h1>' : '<h1 id="title">Protected view</h1>', "heading");
  if (HOME) t = once(t, '<p class="detected" id="detected" hidden></p>', '<p class="detected" id="detected" hidden></p>' + GALLERY, "the gallery");
  // the player library's tag carries its integrity hash (read from the CDN on a runner, live-check.yml)
  const PLAYER = '<script src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/5.2.10/shaka-player.compiled.min.js" integrity="sha384-ZWp1oeFexKioXrhPcPdQ6INqt3fK8DsBJbWzlRdMokbapQn4fKqwPVPox7JNY7wJ" crossorigin="anonymous"></script>';
  t = once(t, PLAYER,
    '<script>' + (HOME ? 'window.__ccsMode = "home"; window.__ccsSession = new Promise((r) => { window.__ccsSignIn = r; }); ' : "") + 'window.__ccsReady = new Promise((r) => { window.__ccsResolve = r; });</script>\n'
    + PLAYER + '\n<script type="module" src="view-prelude.js?v=' + preludeVersion + '"></script>' + (HOME ? '\n<script type="module" src="gallery.js?v=' + galleryVersion + '"></script>' : ""), "player script");
  t = once(t, "<script>\n(async () => {", '<script>\n(async () => {\n  const CTX = await window.__ccsReady; // decrypted in memory by view-prelude.js\n  document.getElementById("title").textContent = CTX.title;', "page script");
  t = once(t, 'name: "the photo", widevine: "widevine.mpd", playready: "playready.mpd", prKid: "9E0FFABA-46A8-1DEC-DC6F-CE6F0CAFA51A", fairplay: null, none: null',
    'name: CTX.content, widevine: "mem://photo/widevine.mpd", playready: "mem://photo/playready.mpd", prKid: CTX.prKidGuid, fairplay: CTX.fairplay, none: CTX.none || null', "photo clip");
  t = once(t, 'widevine: "card-widevine.mpd", playready: "card-playready.mpd"',
    'widevine: "../web/research/drm/card-widevine.mpd", playready: "../web/research/drm/card-playready.mpd"', "card clip");
  t = once(t, 'manifest: "card-fairplay/master.m3u8"', 'manifest: "../web/research/drm/card-fairplay/master.m3u8"', "card's Apple form");
  // Apple's test runs on the route-1 page and on the one page (each picture's own page, on an iPhone, iPad or Mac, holds
  // the picture back and says so). Its own card's folder is given its address from here, so the lines stay true.
  if (!HOME) t = once(t, "const APPLE_TEST_HERE = true;", "const APPLE_TEST_HERE = false; // a picture's own page: Apple's test is on the one page", "Apple's test, off");
  t = once(t, 'const CARD_FAIRPLAY_OWN = "card-fairplay-own/";', 'const CARD_FAIRPLAY_OWN = "../web/research/drm/card-fairplay-own/";', "own card's Apple form");
  // what the top line calls what is shown: the one page shows every picture at once, in the combined view
  t = once(t, 'const SHOWN = CARD ? "The test card" : "The photo";', `const SHOWN = CARD ? "The test card" : ${HOME ? '"The combined view"' : '"The photo"'};`, "what is shown");
  if (HOME) {
    // under Apple's test it is the combined view of your pictures that waits, not the route-1 page's photo
    t = once(t, 'const held = APPLE_TEST ? "the photo" : shown; // under Apple\'s test the card plays in the test, so the photo is what waits',
      "const held = shown; // under Apple's test the combined view of your pictures is what waits", "what waits");
    t = once(t, '<p><strong>Apple\'s test, on this iPhone, iPad or Mac.</strong> The photo is held back here until a screenshot on this kind of device is measured black.',
      '<p><strong>Apple\'s test, on this iPhone, iPad or Mac.</strong> Your pictures are held back here until a screenshot on this kind of device is measured black.', "Apple's test box");
  }
  t = once(t, '<p><a href="../">Back to the list of candidates</a> · <a href="../../../widevine/">the first Widevine proof (2026-10-09)</a></p>',
    HOME ? "</div>" : '<p><a href="index.html">Back to your pictures</a></p>', "footer");
  return "<!-- GENERATED by tools/build-site-view.mjs from web/research/drm/index.html — edit those, not this file -->\n" + t;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const src = readFileSync(SRC, "utf8");
  const before = Object.fromEntries(STAMPED.map((f) => [f, readFileSync(REPO + f, "utf8")]));
  const { files, preludeVersion, galleryVersion } = stampVersions(before);
  const outputs = { ...files, ...Object.fromEntries(Object.entries(OUTS).map(([mode, file]) => [file, buildView(src, mode, preludeVersion, galleryVersion)])) };
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
