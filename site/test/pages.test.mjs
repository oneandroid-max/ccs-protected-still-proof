// The protected pages' own decision lines, READ FROM THE HTML (never copied), run for many kinds of
// device and every kind of link: which protection is tried, and whether it would play the test card or a
// picture. The rules checked, on the route-1 page and on the two pages generated from it:
//   - every test link (each value the workflow guard accepts) plays the TEST CARD, and Apple's test the
//     card's form with Axinom's PUBLIC token, never a picture's;
//   - on Apple's engine (every iPhone or iPad browser, Safari on a Mac) nothing at all is tried for the
//     picture until FAIRPLAY_MEASURED holds a date for that platform, and then only Apple's own form,
//     with the picture's own form and token;
//   - nowhere else is the Apple form tried outside its test, and the switch changes nothing there;
//   - Apple's test (the one link for every device) runs on the route-1 page exactly where the picture is held back on
//     Apple's engine, outside a test mode; never on the site's pages, never elsewhere.
// Also: the workflow guard refuses a link whose first parameter is not the safe one, or that names a
// second levels= or clip= (the page reads the first; the bypass a review found on 2026-10-11).
import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const read = (f) => fs.readFile(join(REPO, f), "utf8");
const START = "  const ua = navigator.userAgent;", END = "  // The platform and browser come from what the browser says about itself";

// the page's lines from the user agent to the order of attempts, as a function of the device and the link
function decide(html, measured) {
  const a = html.indexOf(START), b = html.indexOf(END);
  assert.ok(a > 0 && b > a && html.indexOf(START, a + 1) < 0 && html.indexOf(END, b + 1) < 0, "the page's decision block is found exactly once");
  let body = html.slice(a, b);
  if (measured) {
    const before = body;
    body = body.replace(/const FAIRPLAY_MEASURED = \{[^}]*\};/, `const FAIRPLAY_MEASURED = ${JSON.stringify(measured)};`);
    assert.notEqual(body, before, "the Apple switch is found");
  }
  return new Function("navigator", "location", "set", "CTX", body + "\nreturn { PLATFORM, APPLE, TEST, CARD, ORDER, CLIP, FAIRPLAY_OK, APPLE_TEST, TIERS };");
}

// the page's name for the browser, from its user agent (what the page says; the rule reads BROWSER)
const NAME_START = "  const BROWSER_NAME = ", NAME_END = "  // Samsung Internet on a phone or tablet exists only on Android";
function nameOf(html) {
  const a = html.indexOf(NAME_START), b = html.indexOf(NAME_END);
  assert.ok(a > 0 && b > a && html.indexOf(NAME_START, a + 1) < 0 && html.indexOf(NAME_END, b + 1) < 0, "the browser's name is found exactly once");
  return new Function("ua", html.slice(a, b) + "\nreturn BROWSER_NAME;");
}

const IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)";
const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)";
const CR = "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0";
// name: [user agent, touch points, Apple's engine?, platform, the order of attempts outside a test]
const DEVICES = {
  "iPhone Safari": [`${IOS} Version/17.5 Mobile/15E148 Safari/604.1`, 5, true, "iPhone/iPad"],
  "iPhone Chrome": [`${IOS} CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1`, 5, true, "iPhone/iPad"],
  "iPhone in-app (Facebook)": [`${IOS} Mobile/15E148 [FBAN/FBIOS;FBAV/470.0]`, 5, true, "iPhone/iPad"],
  "iPad Safari": ["Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", 5, true, "iPhone/iPad"],
  "iPad asking for desktop sites": [`${MAC} Version/17.5 Safari/605.1.15`, 5, true, "iPhone/iPad"],
  "Mac Safari": [`${MAC} Version/17.5 Safari/605.1.15`, 0, true, "Mac"],
  "Mac app web view (no Safari/)": [MAC, 0, false, "Mac"],
  "Mac Chrome": [`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ${CR} Safari/537.36`, 0, false, "Mac"],
  "Mac Edge": [`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ${CR} Safari/537.36 Edg/126.0.0.0`, 0, false, "Mac"],
  "Mac Firefox": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0", 0, false, "Mac"],
  "Windows Chrome": [`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${CR} Safari/537.36`, 0, false, "Windows"],
  "Windows Chrome, touch screen": [`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${CR} Safari/537.36`, 10, false, "Windows"],
  "Windows Edge": [`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${CR} Safari/537.36 Edg/126.0.0.0`, 0, false, "Windows"],
  "Windows Firefox": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", 0, false, "Windows"],
  "Android Chrome": [`Mozilla/5.0 (Linux; Android 14; Pixel 8) ${CR} Mobile Safari/537.36`, 5, false, "Android"],
  "Android Samsung Internet": [`Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36`, 5, false, "Android"],
  "Android Edge": [`Mozilla/5.0 (Linux; Android 14; Pixel 8) ${CR} Mobile Safari/537.36 EdgA/126.0.0.0`, 5, false, "Android"],
  "Linux Chrome": [`Mozilla/5.0 (X11; Linux x86_64) ${CR} Safari/537.36`, 0, false, "Linux"],
  "Linux Firefox": ["Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", 0, false, "Linux"],
  "ChromeOS": [`Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) ${CR} Safari/537.36`, 0, false, "ChromeOS"],
};
const SOFTWARE_OK = ["Windows Chrome", "Windows Chrome, touch screen", "Windows Edge", "Android Chrome", "Android Edge"];
const TESTS = { "?levels=software": ["widevine-software", "playready-software"], "?levels=clearkey": ["clearkey-card"], "?levels=fairplay": ["fairplay-apple"], "?levels=fairplay&v=9": ["fairplay-apple"] };
const OTHER = ["", "?clip=card", "?v=3", "?levels=x&levels=fairplay", "?clip=photo", "?levels=FAIRPLAY"];
const PICTURE = { manifest: "https://example.test/site/photos/ID/fp-0a1b2c3d/master.m3u8", token: "THE.PICTURES.OWN.TOKEN" };
const CTX = { content: "your picture: P", prKidGuid: "0", fairplay: PICTURE };

test("the pages' own lines, for 20 kinds of device and every kind of link: tests play only the card; Apple holds the picture back until measured and, on the route-1 page only, runs Apple's test there; nothing else changes", async () => {
  const route1 = await read("web/research/drm/index.html");
  const publicToken = route1.match(/const AXINOM_PUBLIC_TOKEN = "([^"]+)"/)[1];
  const pages = { "route-1 page": route1, "site/view.html": await read("site/view.html"), "site/all.html": await read("site/all.html") };
  // the Apple switch as built: iPhones and iPads switched on, on the owner's word after the measurement on his iPhone
  // (2026-10-12); a Mac still waits. Every page holds the same switch.
  const BUILT = JSON.parse(route1.match(/const FAIRPLAY_MEASURED = (\{[^}]*\});/)[1]);
  assert.deepEqual(BUILT, { "iPhone/iPad": "2026-10-12", "Mac": "" });
  for (const html of Object.values(pages)) assert.deepEqual(JSON.parse(html.match(/const FAIRPLAY_MEASURED = (\{[^}]*\});/)[1]), BUILT);
  let runs = 0;
  for (const [pageName, html] of Object.entries(pages)) {
    const cardPath = pageName === "route-1 page" ? "card-fairplay/master.m3u8" : "../web/research/drm/card-fairplay/master.m3u8";
    // the page as built (null), and the switch off, on for iPhones and iPads only, and on for a Mac only
    for (const measured of [null, { "iPhone/iPad": "", "Mac": "" }, { "iPhone/iPad": "2026-10-11", "Mac": "" }, { "iPhone/iPad": "", "Mac": "2026-10-11" }]) {
      const fn = decide(html, measured), on = measured || BUILT;
      for (const [dev, [ua, touch, apple, platform]] of Object.entries(DEVICES)) {
        const what = (q) => `${pageName}, ${dev}, "${q}", Apple switch ${JSON.stringify(measured)}`;
        // Apple's test: on the route-1 page only, on Apple's engine where the switch holds no date, outside a test mode
        const at = (q) => { runs++; const r = fn({ userAgent: ua, maxTouchPoints: touch }, { search: q }, () => {}, CTX);
          assert.equal(r.APPLE_TEST, pageName === "route-1 page" && apple && !on[platform] && !r.TEST, what(q) + ": Apple's test where the picture is held back on Apple's engine, on the route-1 page only");
          return r; };
        const plain = (q) => { // a link that is not a test
          const r = at(q);
          assert.equal(r.PLATFORM, platform, what(q)); assert.equal(r.APPLE, apple, what(q)); assert.equal(r.TEST, false, what(q));
          const ok = apple && !!on[platform];
          const want = apple ? (ok ? ["fairplay-apple"] : []) : SOFTWARE_OK.includes(dev) ? ["widevine-hardware", "widevine-software", "playready-hardware"] : ["widevine-hardware", "playready-hardware"];
          assert.deepEqual(r.ORDER, want, what(q));
          return r;
        };
        for (const [q, order] of Object.entries(TESTS)) {
          const r = at(q);
          assert.equal(r.TEST, true, what(q)); assert.equal(r.CARD, true, what(q)); assert.deepEqual(r.ORDER, order, what(q));
          assert.equal(r.CLIP.name, "the test card (not the photo)", what(q));
          assert.deepEqual(r.CLIP.fairplay, { manifest: cardPath, token: publicToken }, what(q) + ": the card's Apple form with Axinom's public token");
        }
        for (const q of OTHER) {
          const r = plain(q);
          const card = q === "?clip=card";
          assert.equal(r.CARD, card, what(q));
          if (card) assert.deepEqual(r.CLIP.fairplay, { manifest: cardPath, token: publicToken }, what(q));
          else assert.deepEqual(r.CLIP.fairplay, pageName === "route-1 page" ? null : PICTURE, what(q) + ": the picture's own Apple form");
          if (r.ORDER.includes("fairplay-apple")) assert.ok(apple && on[platform], what(q) + ": Apple's form only where measured");
        }
      }
    }
  }
  assert.ok(runs > 1500, `${runs} combinations run`);
});

// The route-1 page's own words, as every visitor reads them before its script runs, held to what was measured (the
// seventeenth and eighteenth reviews: the lede said screenshots were known to be black where software protection was
// never measured): no such claim, and the places where it was measured named. And the words are pinned by a
// fingerprint (the nineteenth review: other over-claiming words passed the list of banned phrases), so any change to
// them fails here until they are read again against the measurements and the fingerprint is brought up to date.
// The script is pinned the same way (the twentieth review: a sentence the script writes was changed to an over-claim, and
// every test passed), with the page version left out (it changes with every edit). And each file is pinned whole (the
// twenty-second review: an over-claim in the style block or in an attribute reached the lede with both fingerprints
// unchanged), with only the page version's date and time left out.
const PAGE_FILE = { "site/view-prelude.js": "11efdf94299173bc", "web/research/drm/index.html": "1c81f325c31904cd", "site/view.html": "35d3240f118d6093", "site/all.html": "8b30ee3dcac0a79e" };
const wholeOf = (text) => text.replace(/(const PAGE_VERSION = ")\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC/, "$1(date and time)");
const PAGE_SCRIPT = { "site/view-prelude.js": "11efdf94299173bc", "web/research/drm/index.html": "6f52010e76a94717", "site/view.html": "159fad59a01cc0ea", "site/all.html": "05801227c6fadb3b" };
// every script tag, with its attributes (a module script too), and only the page version's date and time left out (the
// twenty-first review: a sentence in a module script or in the rest of the page version passed)
const scriptOf = (html) => [...html.matchAll(/<script\b[^>]*>[\s\S]*?<\/script>/g)].map((m) => m[0]).join("\n").replace(/(const PAGE_VERSION = ")\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC/, "$1(date and time)");
const PAGE_WORDS = { "web/research/drm/index.html": "214c808231479b90", "site/view.html": "107f676dd45a86da", "site/all.html": "bb6941fbff23a001" };
test("the route-1 page's own words claim no measurement that was not made, and name where software protection was measured", async () => {
  for (const f of ["web/research/drm/index.html", "site/view.html", "site/all.html"]) {
    const html = await read(f);
    const words = html.replace(/<script[\s\S]*?<\/script>/g, " ").replace(/<style[\s\S]*?<\/style>/g, " ").replace(/<!--[\s\S]*?-->/g, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    for (const re of [/known to come out black/i, /measured black there/i, /where screenshots were measured black/i, /screenshots are known/i]) assert.ok(!re.test(words), `${f}: no claim beyond the measurements (${re})`);
    assert.match(words, /software protection in Chrome and Edge on Windows and in Chrome on Android \(screenshots under it were measured black in Chrome and Edge on a Windows PC and in Chrome on an Android phone, 2026-10-11\)/, `${f}: the lede names where software protection was measured`);
    const print = createHash("sha256").update(words).digest("hex").slice(0, 16);
    assert.equal(print, PAGE_WORDS[f], `${f}: its words changed; read them against the measurements, then update the fingerprint (${print}):\n${words}`);
    const said = createHash("sha256").update(scriptOf(html)).digest("hex").slice(0, 16);
    assert.equal(said, PAGE_SCRIPT[f], `${f}: its script changed; read every sentence it writes against the measurements, then update the fingerprint (${said})`);
    const whole = createHash("sha256").update(wholeOf(html)).digest("hex").slice(0, 16);
    assert.equal(whole, PAGE_FILE[f], `${f}: the file changed (its style, an attribute, anything); read what a visitor sees against the measurements, then update the fingerprint (${whole})`);
  }
  const preludeWhole = createHash("sha256").update(wholeOf(await read("site/view-prelude.js"))).digest("hex").slice(0, 16);
  assert.equal(preludeWhole, PAGE_FILE["site/view-prelude.js"], `site/view-prelude.js changed; read every sentence it writes, then update the fingerprint (${preludeWhole})`);
  // the site pages' prelude, which writes the box on those pages before their script runs
  const prelude = createHash("sha256").update(await read("site/view-prelude.js")).digest("hex").slice(0, 16);
  assert.equal(prelude, PAGE_SCRIPT["site/view-prelude.js"], `site/view-prelude.js changed; read every sentence it writes, then update the fingerprint (${prelude})`);
});

// The lede's account of where software protection is accepted, held to the page's own decision (the twentieth review:
// a lede stating a stricter rule than the one built passed every test): software protection in the order of attempts
// for exactly the browsers the lede says accept it, measured or not yet measured, and for none of those it says refuse it
test("the lede says where software protection is accepted, as the page's own decision block decides it", async () => {
  const W = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ", A = "Mozilla/5.0 (Linux; Android 14; Pixel 8) ";
  const GROUPS = {
    "accepted, measured: Chrome and Edge on Windows, Chrome on Android": [`${W}${CR} Safari/537.36`, `${W}${CR} Safari/537.36 Edg/126.0.0.0`, `${A}${CR} Mobile Safari/537.36`],
    "accepted, not yet measured: Edge on Android, and the other browsers on Windows and Android the page reads as Chrome": [`${A}${CR} Mobile Safari/537.36 EdgA/126.0.0.0`,
      `Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.0.0 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/470.0.0.0;]`,
      `Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.0.0 Mobile Safari/537.36 LinkedInApp/9.30`,
      `${A}AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.0.0 Mobile DuckDuckGo/5 Safari/537.36`, `${A}${CR} HuaweiBrowser/15.0.4.312 Mobile Safari/537.36`,
      `${A}${CR} Mobile Safari/537.36 XiaoMi/MiuiBrowser/14.3.0-gn`, `${A}${CR} UCBrowser/13.6.0.1315 Mobile Safari/537.36`, `${W}${CR} YaBrowser/24.6.0.0 Safari/537.36`, `${W}${CR} Safari/537.36 Vivaldi/6.8`,
      `${W}${CR} Whale/3.27.254.15 Safari/537.36`, `${A}${CR} Mobile Safari/537.36 SomeBrowserNoOneNamed/1.0`,
      // each named one on both platforms where it exists on both (the twenty-second review: Whale held to hardware on
      // Android only passed)
      `${A}${CR} Mobile Safari/537.36 Whale/3.27.254.15`, `${A}${CR} YaBrowser/24.6.0.0 Mobile Safari/537.36`, `${A}${CR} Mobile Safari/537.36 Vivaldi/6.8`,
      `${W}${CR} Safari/537.36 DuckDuckGo/1.0`, `${W}${CR} Safari/537.36 SomeBrowserNoOneNamed/1.0`],
    "not accepted: anywhere else, Samsung Internet, Opera and Firefox included (Macs, Linux and Chromebooks too)": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
      "Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0", DEVICES["Android Samsung Internet"][0], `${W}${CR} Safari/537.36 OPR/112.0.0.0`, `${A}${CR} Mobile Safari/537.36 OPR/83.0.0.0`,
      DEVICES["Mac Chrome"][0], DEVICES["Mac Edge"][0], DEVICES["Mac Firefox"][0], DEVICES["Linux Chrome"][0], DEVICES["Linux Firefox"][0], DEVICES.ChromeOS[0],
      `Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Safari/537.36`,
      // a web view carrying Opera's mark (the twenty-third review: the page named it an app's built-in browser)
      `Mozilla/5.0 (Linux; U; Android 14; Pixel 8 Build/AP2A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.0.0 Mobile Safari/537.36 OPR/80.0.2254.70224`],
  };
  // the names under which the lede says software protection is accepted on Windows and Android
  const SOFTWARE_NAMES = ["Chrome", "Edge", "an app's built-in browser", "DuckDuckGo", "Huawei Browser", "Mi Browser", "Yandex Browser", "Vivaldi", "UC Browser", "Naver Whale"];
  for (const f of ["web/research/drm/index.html", "site/view.html", "site/all.html"]) {
    const html = await read(f), fn = decide(html), name = nameOf(html);
    const lede = html.match(/<p class="lede">([\s\S]*?)<\/p>/)[1].replace(/<[^>]+>/g, "").replace(/\s+/g, " ");
    assert.match(lede, /hardware protection \(Widevine or PlayReady\) on any device; and software protection in Chrome and Edge on Windows and in Chrome on Android \(screenshots under it were measured black in Chrome and Edge on a Windows PC and in Chrome on an Android phone, 2026-10-11\) and, not yet measured, in Edge on Android and in the other browsers on Windows and Android that this page reads as Chrome \(apps' built-in browsers, DuckDuckGo, Yandex, Vivaldi and others\)\./, f);
    assert.match(lede, /Software protection anywhere else is not accepted, Samsung Internet, Opera and Firefox included: a screenshot on a test machine showed the test card in Firefox on a Mac and in Chrome on Linux; other browsers and platforms are not yet measured on a real device\./, f);
    assert.match(lede, /On an iPhone or iPad it is shown only through Apple's FairPlay \(screenshots of FairPlay video were measured black on an iPhone, 2026-10-12; a screen recording, an iPad and other iOS versions are not yet measured, and a clip licensed by our own Axinom account, as the pictures are, is not yet seen playing on a real device\); on a Mac it is held back until a screenshot there is measured black\./, f);
    // the levels each tier asks for, as the lede's words mean them (the twenty-first review: a software level added to
    // the hardware tier passed), on every browser below (the twenty-second review: changed on Linux only, it passed);
    // what a request actually carries is checked by the drive
    const TIERS_AS_BUILT = {
      "widevine-hardware": { system: "widevine", word: "hardware", levels: ["HW_SECURE_ALL", "HW_SECURE_DECODE"] },
      "widevine-software": { system: "widevine", word: "software", levels: ["SW_SECURE_DECODE", "SW_SECURE_CRYPTO"] },
      "playready-hardware": { system: "playready", word: "hardware", levels: ["3000"], sl: 3000 },
      "playready-software": { system: "playready", word: "software", levels: ["2000"], sl: 2000 },
      "clearkey-card": { system: "clearkey", word: "no protection", levels: ["ClearKey, decrypted in the browser's own code"] },
      "fairplay-apple": { system: "fairplay", word: "Apple FairPlay", levels: ["FairPlay Streaming"] },
    };
    for (const [group, uas] of Object.entries(GROUPS)) for (const ua of uas) {
      const r = fn({ userAgent: ua, maxTouchPoints: 0 }, { search: "" }, () => {}, CTX);
      // any tier that asks for software protection counts (Widevine or PlayReady), not one name
      const soft = r.ORDER.some((t) => r.TIERS[t].word === "software");
      assert.equal(soft, !group.startsWith("not accepted"), `${f}: ${group}: ${ua}: ${r.ORDER.join(", ")}`);
      // and the name the page gives it never contradicts the rule (the twenty-third review: a web view carrying Opera's
      // mark was named an app's built-in browser, which the lede says gets software protection, while the rule refused it)
      if (r.PLATFORM === "Windows" || r.PLATFORM === "Android") assert.equal(SOFTWARE_NAMES.includes(name(ua)), soft, `${f}: ${ua}: named "${name(ua)}", and the rule ${soft ? "accepts" : "refuses"} software protection`);
      assert.ok(r.ORDER.includes("widevine-hardware") && !r.APPLE, `${f}: ${ua}: hardware protection is accepted there too`);
      assert.deepEqual(r.TIERS, TIERS_AS_BUILT, `${f}: ${ua}: the tiers and the levels each asks for`);
    }
  }
});

// The Apple check's old address (sent before its test moved onto the route-1 page) forwards there, to the test card:
// never a picture; and it holds no player, token or key system of its own that could drift from the page's
test("the Apple check's old address forwards to the one test page, on the test card, and holds nothing of its own", async () => {
  const old = await read("web/research/apple/index.html");
  assert.match(old, /<meta http-equiv="refresh" content="0; url=\.\.\/drm\/\?clip=card">/);
  assert.match(old, /<script>location\.replace\("\.\.\/drm\/\?clip=card"\);<\/script>/);
  const targets = [...old.matchAll(/(?:url=|href="|replace\(")([^"]+)/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(targets)], ["../drm/?clip=card"], "every way out goes to the test card: " + targets.join(", "));
  assert.equal(targets.length, 3, "the refresh, the script and the link");
  // and no other way out (the seventeenth review: a second script before this one sent the page to the photo): one
  // script, one location, one link, one refresh, and nothing else that loads or navigates
  for (const [re, n, what] of [[/<script/g, 1, "script"], [/location/g, 1, "location"], [/href=/g, 1, "link"], [/http-equiv/g, 1, "refresh"]]) assert.equal((old.match(re) || []).length, n, `exactly one ${what}`);
  assert.ok(!/\bsrc=|action=|<iframe|<form|<link|<object|<embed|<base|window\.|document\.|open\(|assign\(|onload|onerror/i.test(old), "nothing else that loads or navigates");
  assert.ok(!/shaka|AxDRM|eyJhbGci|requestMediaKeySystemAccess|<video/.test(old), "no player, token, key system or video of its own");
});

// The guard, run in a copy of the repository's workflows and tools with one extra workflow, or with one
// file changed (edit: [relative path, function from its text to the new text])
async function guardWith(extra, edit, files = {}) {
  const d = await fs.mkdtemp(join(tmpdir(), "guard-"));
  await fs.cp(join(REPO, ".github"), join(d, ".github"), { recursive: true });
  await fs.cp(join(REPO, "tools"), join(d, "tools"), { recursive: true, filter: (src) => !src.includes("node_modules") });
  await fs.mkdir(join(d, "service"), { recursive: true }); await fs.copyFile(join(REPO, "service", "Dockerfile"), join(d, "service", "Dockerfile"));
  if (extra) await fs.writeFile(join(d, ".github", "workflows", "zz-extra.yml"), `name: x\non: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -sS "${extra}"\n`);
  if (edit) { const f = join(d, edit[0]); const before = await fs.readFile(f, "utf8"); const after = edit[1](before); assert.notEqual(after, before, "the edit changes " + edit[0]); await fs.writeFile(f, after); }
  for (const [rel, text] of Object.entries(files)) { await fs.mkdir(join(d, rel, ".."), { recursive: true }); await fs.writeFile(join(d, rel), text); }
  const r = spawnSync(process.execPath, [join(d, "tools", "check-workflow-links.mjs")], { cwd: d, encoding: "utf8" });
  await fs.rm(d, { recursive: true, force: true });
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}
// THE GUARD'S THIRD RULE (the sixth to eleventh reviews): a packager is brought in only by the pinned download, in a
// workflow or a Dockerfile, checked against its SHA-256 by the exact line after it; a workflow that downloads it lets
// no failure pass; every known download is counted. Every way around an earlier version that a review found is here,
// but those the guard is not meant to see (named in its comment; the run-time check in service/lib/packager-pin.mjs
// refuses what they bring wherever our programs run the packager: site/test/fairplay.test.mjs).
test("the guard refuses the obvious ways of bringing in a packager other than the pinned, checked download", async () => {
  const PIN = "https://github.com/shaka-project/shaka-packager/releases/download/v3.9.3/packager-linux-x64";
  const LATEST = "https://github.com/shaka-project/shaka-packager/releases/latest/download/packager-linux-x64";
  const MIRROR = "https://mirror.example.com/packager-linux-x64";
  const base = await guardWith(null);
  assert.equal(base.code, 0, base.out); assert.match(base.out, /all 9 shaka-packager downloads are the pinned release, checked by its SHA-256, and all 12 runs of it go through tools\/run-packager\.mjs/);
  const ST = ".github/workflows/site-test.yml", DF = "service/Dockerfile", AT = "      - name: The generated view page is current";
  const step = (run) => (t) => t.replace(AT, `      - run: ${run}\n${AT}`);
  const uses = (action, more = "") => (t) => t.replace(AT, `      - uses: ${action}\n${more ? more + "\n" : ""}${AT}`);
  const afterRun = (text) => (t) => t.replace(/(\/usr\/local\/bin\/packager --version)\n/, `$1\n${text}\n`);
  const NAMED = /brings in a packager other than by the pinned download/, UNCHECKED = /the downloaded packager must be checked against its SHA-256 on the very next line, exactly/;
  const AFTER = /service\/Dockerfile:\d+: after the packager's check, this instruction may go on only with '&& …' lines/, LETS = /downloads shaka-packager and lets a failure pass/;
  const UNCHECKED_RUN = (w) => new RegExp(`site-test\\.yml:\\d+: names the packager file \\(${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\) where it could run unchecked`);
  const refused = [
    // another source or version, an image, an action, a container, a package
    [[".github/workflows/card-fairplay.yml", (t) => t.replace(PIN, LATEST)], NAMED],
    [[ST, step("gh release download v3.9.3 -R shaka-project/shaka-packager -p packager-linux-x64")], NAMED],
    [[ST, step("docker run --rm google/shaka-packager packager --version")], NAMED],
    [[ST, step("docker container run --rm google/shaka-packager packager --version")], NAMED],
    [[ST, step("podman run --rm google/shaka-packager packager --version")], NAMED],
    [[ST, step("docker run --rm ghcr.io/shaka-project/shaka-packager packager --version")], NAMED],
    [[ST, step("docker run --rm someone/shaka-packager packager --version")], NAMED],
    [[ST, step("npm install -g shaka-packager")], NAMED],
    [[ST, uses("some-org/setup-shaka-packager@v1")], NAMED],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    container: someone/shaka-packager:v3.9.3")], NAMED],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    container:\n      image: google/shaka-packager:v3.9.3")], NAMED],
    [[DF, (t) => t.replace(/RUN curl -sSL -o \/usr\/local\/bin\/packager [^\n]*\n  && echo [^\n]*\n  && chmod \+x \/usr\/local\/bin\/packager && \/usr\/local\/bin\/packager --version/, "COPY --from=google/shaka-packager:v3.9.3 /usr/bin/packager /usr/local/bin/packager")], NAMED],
    // the tenth review: what c4cc277 refused and the next two versions let through (no "shaka-packager" on the line)
    [[ST, step(`curl -sSL -o /usr/local/bin/packager ${MIRROR}`)], NAMED],
    [[ST, step("docker run --rm someorg/packager:v3 --version")], NAMED],
    [[ST, uses("someorg/setup-packager@v1")], NAMED],
    [[DF, afterRun(`RUN curl -sSL -o /usr/local/bin/packager ${MIRROR}`)], NAMED],
    // ... and what every version let through: an artifact or a cache of it, a copy, an archive, a package, a clone,
    // another fetcher, a Dockerfile ADD, a COPY from an image or from the build context
    [[ST, uses("actions/download-artifact@v4", "        with:\n          name: shaka-packager\n          path: /usr/local/bin")], NAMED],
    [[ST, uses("actions/cache@v4", "        with:\n          path: /usr/local/bin/packager\n          key: v3.9.3")], NAMED],
    [[ST, uses("actions/download-artifact@v4", "        with: { name: shaka-packager, path: /usr/local/bin }")], NAMED],
    [[ST, step("sudo cp /opt/tools/packager /usr/local/bin/packager")], NAMED],
    [[ST, step("tar -xzf tools.tgz -C /usr/local/bin packager")], NAMED],
    [[ST, step("pip install shaka-packager")], NAMED],
    [[ST, step("git clone --depth 1 https://github.com/shaka-project/shaka-packager")], NAMED],
    [[ST, step(`wget -q -O /usr/local/bin/packager ${PIN}`)], NAMED],
    [[DF, afterRun(`ADD ${PIN} /usr/local/bin/packager`)], NAMED],
    [[DF, afterRun("COPY --from=someorg/packager /usr/bin/packager /usr/local/bin/packager")], NAMED],
    [[DF, afterRun("COPY --from=someorg/tools:1 /usr/bin/packager /usr/local/bin/packager")], NAMED],
    [[DF, afterRun("COPY bin/packager /usr/local/bin/packager")], NAMED],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "FROM someorg/packager:v3 AS base")], NAMED],
    [[DF, afterRun("RUN --mount=type=bind,from=someorg/packager,target=/p /p/packager --version")], NAMED],
    // the eleventh review: a line that names shaka-packager itself, wherever it stands (an image on a continuation line,
    // in a variable, a build argument, a heredoc); a packager named in capitals
    [[ST, (t) => t.replace(AT, `      - run: |\n          docker run --rm \\\n            google/shaka-packager:latest packager --version\n${AT}`)], NAMED],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    env:\n      TOOL_IMAGE: google/shaka-packager:latest")], NAMED],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "ARG BASE=google/shaka-packager:latest\nFROM $1")], NAMED],
    [[ST, (t) => t.replace(AT, `      - run: |\n          docker build -t tools - <<'EOF'\n          FROM google/shaka-packager:latest\n          EOF\n${AT}`)], NAMED],
    [[ST, step("curl -sSL -o /usr/local/bin/PACKAGER https://mirror.example.com/bin/x64")], NAMED], // the name only in capitals, nowhere else on the line
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    env:\n      TOOL_IMAGE: SOMEORG/SHAKA-PACKAGER:LATEST")], NAMED], // shaka-packager named in capitals
    // (E), the thirteenth review: a workflow runs the packager only through tools/run-packager.mjs (it checks the file at
    // that moment, then runs exactly that file); any other word naming the file is refused, in the ordinary shapes
    [[".github/workflows/drm-package.yml", (t) => t.replace("node tools/run-packager.mjs /tmp/packager in=/tmp/src/source.mp4,stream=video,output=web/research/drm/video-playready.mp4", "/tmp/packager in=/tmp/src/source.mp4,stream=video,output=web/research/drm/video-playready.mp4")], /drm-package\.yml:\d+: names the packager file \(\/tmp\/packager\) where it could run unchecked/],
    [[ST, (t) => t.replace("sudo chmod +x /usr/local/bin/packager && node tools/run-packager.mjs /usr/local/bin/packager --version", "sudo chmod +x /usr/local/bin/packager && packager --version")], UNCHECKED_RUN("packager")],
    [[ST, step("/usr/local/bin/packager --version")], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, (t) => t.replace(AT, '      - env: { PACKAGER_BIN: /usr/local/bin/packager }\n        run: "$PACKAGER_BIN" --version\n' + AT)], UNCHECKED_RUN("$PACKAGER_BIN")],
    [[ST, step('echo "built with $(/usr/local/bin/packager --version)"')], UNCHECKED_RUN("/usr/local/bin/packager")],
    // a check line, made harmless or exact, on the same line or the one before, makes no run acceptable: only the runner
    // checks the file at the moment it runs it
    [[ST, step('echo "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6  /usr/local/bin/packager" | sha256sum -c - || true; /usr/local/bin/packager --version')], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, (t) => t.replace(AT, '      - run: |\n          echo "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6  /usr/local/bin/packager" | sha256sum -c - || true\n          /usr/local/bin/packager --version\n' + AT)], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, (t) => t.replace(AT, '      - run: |\n          echo "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6  /usr/local/bin/packager" | sha256sum -c - || exit 1\n          /usr/local/bin/packager --version\n' + AT)], UNCHECKED_RUN("/usr/local/bin/packager")],
    // the shapes the thirteenth review ran past the step rule: in quotes, after `if` or `timeout`, a bare name in an `if`,
    // PACKAGER_BIN at the job's level; and a variable, `sh -c`, a one-line step, an expression, a comment after `steps:`,
    // a second run beside the runner's
    [[ST, step('"/usr/local/bin/packager" --version')], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, step("if /usr/local/bin/packager --version; then echo ok; fi")], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, step("timeout 60 /usr/local/bin/packager --version")], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, step("if packager --version; then echo ok; fi")], UNCHECKED_RUN("packager")],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    env:\n      PACKAGER_BIN: /usr/local/bin/packager").replace(AT, '      - run: "$PACKAGER_BIN" --version\n' + AT)], UNCHECKED_RUN("$PACKAGER_BIN")],
    [[ST, step('P=/usr/local/bin/packager; "$P" --version')], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, step("sh -c '/usr/local/bin/packager --version'")], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, (t) => t.replace(AT, "      - { name: v, run: /usr/local/bin/packager --version }\n" + AT)], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, (t) => t.replace(AT, "      - { env: { PACKAGER_BIN: /usr/local/bin/packager }, run: /usr/local/bin/packager --version }\n" + AT)], UNCHECKED_RUN("/usr/local/bin/packager")], // only PACKAGER_BIN's own value passes (in the ordinary shapes)
    [[ST, step("${{ env.PACKAGER_BIN }} --version")], UNCHECKED_RUN("env.PACKAGER_BIN")],
    [[ST, (t) => t.replace("    steps:\n", "    steps: # the job's steps\n").replace(AT, "      - run: /usr/local/bin/packager --version\n" + AT)], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, (t) => t.replace("node tools/run-packager.mjs /usr/local/bin/packager --version", "node tools/run-packager.mjs /usr/local/bin/packager --version; /usr/local/bin/packager --version")], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, (t) => t.replace("node tools/run-packager.mjs /usr/local/bin/packager --version", "node ./tools/run-packager.mjs /usr/local/bin/packager --version")], UNCHECKED_RUN("/usr/local/bin/packager")], // the runner, exactly as named
    // the fourteenth review: a download saved under another name was invisible to (E), the second here a regression of the
    // thirteenth round's narrower names; the pinned download must be saved as <folder>/packager
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o /usr/local/bin/pk ${PIN}`).replace(/(echo "7a3cf35a[0-9a-f]+  )\/usr\/local\/bin\/packager(" \| sha256sum)/, "$1/usr/local/bin/pk$2").replace("sudo chmod +x /usr/local/bin/packager && node tools/run-packager.mjs /usr/local/bin/packager --version", "sudo chmod +x /usr/local/bin/pk").replace(AT, "      - run: /usr/local/bin/pk --version\n" + AT)], /site-test\.yml:\d+: the pinned download must be saved as <folder>\/packager, so that every later use of the file is seen \(rule E\); \/usr\/local\/bin\/pk is not/],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o /usr/local/bin/pk ${PIN}`).replace(/(echo "7a3cf35a[0-9a-f]+  )\/usr\/local\/bin\/packager(" \| sha256sum)/, "$1/usr/local/bin/pk$2").replace("sudo chmod +x /usr/local/bin/packager && node tools/run-packager.mjs /usr/local/bin/packager --version", "sudo chmod +x /usr/local/bin/pk").replace(AT, "      - run: cp /bin/true /usr/local/bin/pk && /usr/local/bin/pk --version\n" + AT)], /site-test\.yml:\d+: the pinned download must be saved as <folder>\/packager/],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o /usr/local/bin/packager-v3.9.3 ${PIN}`).replace(/(echo "7a3cf35a[0-9a-f]+  )\/usr\/local\/bin\/packager(" \| sha256sum)/, "$1/usr/local/bin/packager-v3.9.3$2").replace("sudo chmod +x /usr/local/bin/packager && node tools/run-packager.mjs /usr/local/bin/packager --version", "sudo chmod +x /usr/local/bin/packager-v3.9.3").replace(AT, "      - run: /usr/local/bin/packager-v3.9.3 --version\n" + AT)], /site-test\.yml:\d+: the pinned download must be saved as <folder>\/packager, so that every later use of the file is seen \(rule E\); \/usr\/local\/bin\/packager-v3\.9\.3 is not/],
    // the fifteenth review: ordinary shapes that touched a bracket or a backslash (a flow sequence in a job's matrix, run
    // as ${{ matrix.tool }}; a backslash before a name, the shell's way past an alias; no space before a line's continuation)
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        tool: [ffmpeg, packager]").replace(AT, "      - run: ${{ matrix.tool }} --version\n" + AT)], UNCHECKED_RUN("packager")],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        tool: [/usr/local/bin/packager]").replace(AT, "      - run: ${{ matrix.tool }} --version\n" + AT)], UNCHECKED_RUN("/usr/local/bin/packager")],
    [[ST, step("\\packager --version")], UNCHECKED_RUN("packager")],
    [[ST, (t) => t.replace(AT, "      - run: |\n          /usr/local/bin/packager\\\n            --version\n" + AT)], UNCHECKED_RUN("/usr/local/bin/packager")],
    // every run through the runner counted: one gone (or a guard that stops reading a workflow) fails
    [[".github/workflows/site-photos.yml", (t) => t.replace(" && node tools/run-packager.mjs /usr/local/bin/packager --version", "")], /site-photos\.yml: expected 2 runs of the packager through tools\/run-packager\.mjs, read 1/],
    // a link after a quoted '#' on a code line (comments inside quotes are not comments)
    [[ST, step(`echo "a # b" && curl -sSL -o /tmp/p ${LATEST}`)], NAMED],
    // a curl that is not only the pinned download: another address beside it, another option, an output built by a command
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o /usr/local/bin/packager ${PIN} ${MIRROR}`)], NAMED],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -K /tmp/more -o /usr/local/bin/packager ${PIN}`)], NAMED],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o $(echo /usr/local/bin/packager) ${PIN}`)], NAMED],
    // ... and an output built by a command even with a check line to match it (only the plain-path rule refuses this)
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o $(pwd)/p ${PIN}`).replace(/(echo "7a3cf35a[0-9a-f]+  )\/usr\/local\/bin\/packager(" \| sha256sum -c - \|\| exit 1)/, "$1$(pwd)/p$2")], NAMED],
    // the check missing, changed, commented out, made harmless
    [[ST, (t) => t.replace(/\n\s+echo "7a3cf35a[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -[^\n]*/, "")], UNCHECKED],
    [[".github/workflows/drm-package.yml", (t) => t.replace("7a3cf35ad146fd78", "0000000000000000")], UNCHECKED],
    [[ST, (t) => t.replace(/(\n\s+)(echo "7a3cf35a[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -)/, "$1# $2")], UNCHECKED],
    [[".github/workflows/site-fairplay.yml", (t) => t.replace(/sha256sum -c - \|\| exit 1/, "sha256sum -c - || true")], UNCHECKED],
    [[".github/workflows/card-fairplay.yml", (t) => t.replace(/(\n\s+)(echo "7a3cf35a[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c - \|\| exit 1)/, "$1if false; then $2; fi")], UNCHECKED],
    [[DF, (t) => t.replace(/ \\\n  && echo "[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -/, "")], UNCHECKED],
    [[DF, (t) => t.replace(/\n  && echo ("[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -) \\/, "\n#  && echo $1 \\")], UNCHECKED],
    // after the Dockerfile's check, only '&& …' lines with no ';', '||' or lone '&' (the tenth review: '&& … || true')
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  ; chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  | cat && chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  || chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  &amp;&amp; chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("/usr/local/bin/packager --version", "/usr/local/bin/packager --version || true")], AFTER],
    [[DF, (t) => t.replace("/usr/local/bin/packager --version", "/usr/local/bin/packager --version; true")], AFTER],
    [[DF, (t) => t.replace("/usr/local/bin/packager --version", "/usr/local/bin/packager --version &")], AFTER],
    // a workflow that downloads it letting a failure pass, however written (the tenth review: the key quoted)
    [[".github/workflows/service-test.yml", (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    continue-on-error: true")], /service-test\.yml:\d+: downloads shaka-packager and lets a failure pass/],
    [[ST, (t) => t.replace(AT, `      - continue-on-error: true\n        run: echo x\n${AT}`)], /site-test\.yml:\d+: downloads shaka-packager and lets a failure pass/],
    [[ST, (t) => t.replace(AT, `      - { name: x, run: echo x, continue-on-error: true }\n${AT}`)], /site-test\.yml:\d+: downloads shaka-packager and lets a failure pass/],
    [[ST, (t) => t.replace(AT, `      - "continue-on-error": true\n        run: echo x\n${AT}`)], LETS],
    [[ST, (t) => t.replace(AT, `      - 'continue-on-error': yes\n        run: echo x\n${AT}`)], LETS],
  ];
  for (const [edit, re] of refused) { const g = await guardWith(null, edit); assert.equal(g.code, 1, `${edit[0]} refused: ${g.out}`); assert.match(g.out, re); }
  // a new workflow fetching it another way; a download in an action, a script of any kind, another Dockerfile, a
  // Containerfile, a compose file anywhere, a Makefile, a package's own scripts
  const extra = await guardWith(LATEST);
  assert.equal(extra.code, 1, extra.out); assert.match(extra.out, /zz-extra\.yml:\d+: brings in a packager other than by the pinned download/);
  const down = (out) => `curl -sSL -o ${out} ${PIN}\nchmod +x ${out}\n`, OUTSIDE = (f) => new RegExp(`${f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\d+: downloads shaka-packager outside a workflow or a Dockerfile`);
  for (const [file, text, re] of [
    [".github/actions/get-packager/action.yml", `name: get packager\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n        ${down("/usr/local/bin/packager").split("\n").join("\n        ")}`, OUTSIDE(".github/actions/get-packager/action.yml")],
    ["tools/get-packager.sh", `#!/bin/sh\n${down("/tmp/packager")}`, OUTSIDE("tools/get-packager.sh")],
    ["docker/Containerfile", `FROM debian:bookworm-slim\nRUN curl -sSL -o /usr/local/bin/packager ${PIN} \\\n  && chmod +x /usr/local/bin/packager\n`, /docker\/Containerfile:\d+: the downloaded packager must be checked/],
    ["docker/packager.dockerfile", `FROM debian:bookworm-slim\nRUN curl -sSL -o /usr/local/bin/packager ${PIN}\n`, /docker\/packager\.dockerfile:\d+: the downloaded packager must be checked/],
    ["tools/get-packager.bash", `#!/bin/bash\n${down("/tmp/packager")}`, OUTSIDE("tools/get-packager.bash")],
    ["tools/get-packager.ps1", "Invoke-WebRequest -Uri https://example.com/packager-win-x64.exe -OutFile packager.exe\n", /tools\/get-packager\.ps1:1: brings in a packager other than by the pinned download/],
    ["deploy/docker-compose.yml", "services:\n  pack:\n    image: someorg/packager:v3\n", /deploy\/docker-compose\.yml:3: brings in a packager other than by the pinned download/],
    ["Makefile", `packager:\n\t${down("bin/packager").split("\n")[0]}\n`, OUTSIDE("Makefile")],
    ["scripts/package.json", `{ "scripts": { "postinstall": "curl -sSL -o bin/packager ${PIN}" } }\n`, /scripts\/package\.json:1: brings in a packager other than by the pinned download/],
    // the eleventh review: every kind it claims to read, in either case (batch, module and Makefile names were not tested)
    ...["tools/get.bat", "tools/GET.BAT", "tools/get.cmd", "tools/get.psm1", "makefile", "GNUmakefile", "build/tools.mk", "MAKEFILE"].map((f) => [f, `${down("/tmp/packager").split("\n")[0]}\n`, OUTSIDE(f)]),
    // the twelfth review: the other kinds it claims to read, each tested (zsh, YAML outside the workflows in either case,
    // a Dockerfile of another name or folder, a .containerfile)
    ...["tools/get.zsh", "deploy/tools.yaml", "deploy/compose.YML"].map((f) => [f, `${down("/tmp/packager").split("\n")[0]}\n`, OUTSIDE(f)]),
    ...["docker/Dockerfile.ci", "docker/Dockerfile", "docker/tools.containerfile"].map((f) => [f, `FROM debian:bookworm-slim\nRUN curl -sSL -o /usr/local/bin/packager ${PIN}\n`, new RegExp(`${f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\d+: the downloaded packager must be checked`)]),
  ]) { const g = await guardWith(null, null, { [file]: text }); assert.equal(g.code, 1, `${file}: ${g.out}`); assert.match(g.out, re); }
  // a pinned, checked download in a workflow that DOWNLOADERS does not list: refused until it is listed
  const unlisted = await guardWith(null, null, { ".github/workflows/zz-new.yml": `name: x\non: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          curl -sSL -o /tmp/packager ${PIN}\n          echo "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6  /tmp/packager" | sha256sum -c - || exit 1\n` });
  assert.equal(unlisted.code, 1, unlisted.out); assert.match(unlisted.out, /zz-new\.yml: a pinned download of shaka-packager that DOWNLOADERS in tools\/check-workflow-links\.mjs does not list/);
  // lock files are not read (a package named "packager" in one is not a download: the eleventh review)
  const lock = await guardWith(null, null, { "package-lock.json": `{ "packages": { "node_modules/@electron/packager": { "resolved": "https://registry.npmjs.org/@electron/packager/-/packager-18.3.6.tgz" } } }\n` });
  assert.equal(lock.code, 0, lock.out);
  // legitimate text: accepted (the tenth review: the version before refused the last five)
  const accepted = [
    [[ST, (t) => t.replace(AT, `      - name: Show which shaka-packager build (packager-linux-x64) is used\n        run: echo the build is named in the log above\n${AT}`)]], // a name line (a run of the packager on it would be refused: rule E)
    [[ST, (t) => t.replace(AT, `      # https://github.com/shaka-project/shaka-packager/releases/tag/v3.9.3\n${AT}`)]],
    [[ST, (t) => t.replace(AT, `      - name: x\n        continue-on-error: false\n        run: echo x\n${AT}`)]],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "FROM $1 AS packager")]],
    [[DF, (t) => t.replace(/ \\\n  && chmod \+x \/usr\/local\/bin\/packager && \/usr\/local\/bin\/packager --version/, "\nRUN chmod +x /usr/local/bin/packager && /usr/local/bin/packager --version")]],
    [[ST, step("echo hi # shaka-packager runs below; see https://github.com/shaka-project/shaka-packager")]],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -fsSL -o /usr/local/bin/packager ${PIN}`)]],
    [[ST, step('echo "built with shaka-packager v3.9.3"')]], // a print line (one that RUNS the packager, $(packager --version), is refused: rule E)
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, 'FROM $1\nLABEL description="ffmpeg and shaka-packager v3.9.3"')]],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, 'FROM $1\nRUN echo "built with shaka-packager v3.9.3"')]], // a print line in a Dockerfile (the twelfth review)
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o /usr/local/bin/packager "${PIN}"`)]],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "FROM $1 AS packager") + "FROM node:22-bookworm-slim\nCOPY --from=packager /usr/local/bin/packager /usr/local/bin/packager\n"]],
  ];
  accepted.push(
    // (E): the runner given the path in quotes; PACKAGER_BIN set for the whole job (the tests check that file themselves:
    // site/test/fairplay.test.mjs runs them with another file and sees it refused, never run)
    [[ST, (t) => t.replace("node tools/run-packager.mjs /usr/local/bin/packager --version", 'node tools/run-packager.mjs "/usr/local/bin/packager" --version')]],
    [[ST, (t) => t.replace('env: { REQUIRE_PACKAGER: "1", PACKAGER_BIN: /usr/local/bin/packager }', 'env: { REQUIRE_PACKAGER: "1" }').replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    env:\n      PACKAGER_BIN: /usr/local/bin/packager")]],
  );
  for (const [edit] of accepted) { const g = await guardWith(null, edit); assert.equal(g.code, 0, `${edit[0]} accepted: ${g.out}`); assert.match(g.out, /all 9 shaka-packager downloads/); }
  // a new workflow that runs it through the runner: refused until CHECKED_RUNS lists it
  const runner = await guardWith(null, null, { ".github/workflows/zz-run.yml": "name: x\non: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: node tools/run-packager.mjs /usr/local/bin/packager --version\n" });
  assert.equal(runner.code, 1, runner.out); assert.match(runner.out, /zz-run\.yml: runs the packager through tools\/run-packager\.mjs, and CHECKED_RUNS in tools\/check-workflow-links\.mjs does not list it/);
  // a workflow that does NOT download it may let a step fail on (a measurement that goes on past one browser)
  assert.equal((await guardWith(null, [".github/workflows/live-check.yml", (t) => t.replace("    timeout-minutes: 5", "    timeout-minutes: 5\n    continue-on-error: true")])).code, 0);
  // a dangling Dockerfile link is no reason to fail
  const dangling = await (async () => { const d = await fs.mkdtemp(join(tmpdir(), "guard-")); try { await fs.cp(join(REPO, ".github"), join(d, ".github"), { recursive: true }); await fs.cp(join(REPO, "tools"), join(d, "tools"), { recursive: true }); await fs.mkdir(join(d, "service")); await fs.copyFile(join(REPO, "service", "Dockerfile"), join(d, "service", "Dockerfile")); await fs.symlink(join(d, "nowhere"), join(d, "Dockerfile.old")); const r = spawnSync(process.execPath, [join(d, "tools", "check-workflow-links.mjs")], { cwd: d, encoding: "utf8" }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; } finally { await fs.rm(d, { recursive: true, force: true }); } })();
  assert.equal(dangling.code, 0, dangling.out);
});

// The guard as CI runs it, in a git checkout (the tenth review: every test above runs it in a copy without .git, so a
// change that made it read nothing in a checkout passed them all)
test("the guard in a git checkout: what git ignores is left out, everything else read; a known download gone fails", async () => {
  const d = await fs.mkdtemp(join(tmpdir(), "guard-git-"));
  try {
    await fs.cp(join(REPO, ".github"), join(d, ".github"), { recursive: true });
    await fs.cp(join(REPO, "tools"), join(d, "tools"), { recursive: true, filter: (src) => !src.includes("node_modules") });
    await fs.mkdir(join(d, "service"), { recursive: true }); await fs.copyFile(join(REPO, "service", "Dockerfile"), join(d, "service", "Dockerfile"));
    await fs.writeFile(join(d, ".gitignore"), "ignored/\n");
    const git = (...a) => { const r = spawnSync("git", a, { cwd: d, encoding: "utf8" }); assert.equal(r.status, 0, r.stderr); };
    git("init", "-q"); git("add", "-A"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "x");
    const run = () => { const r = spawnSync(process.execPath, [join(d, "tools", "check-workflow-links.mjs")], { cwd: d, encoding: "utf8" }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; };
    const base = run(); assert.equal(base.code, 0, base.out); assert.match(base.out, /all 9 shaka-packager downloads/);
    const bad = "curl -sSL -o p https://mirror.example.com/packager-linux-x64\n";
    // in a folder git ignores: never committed, left out
    await fs.mkdir(join(d, "ignored"), { recursive: true }); await fs.writeFile(join(d, "ignored", "get.sh"), bad);
    const skipped = run(); assert.equal(skipped.code, 0, skipped.out);
    // ... unless it is committed there all the same (added by force): then it is the repository's, read, refused
    git("add", "-f", "ignored/get.sh"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "forced");
    const forced = run(); assert.equal(forced.code, 1, forced.out); assert.match(forced.out, /ignored\/get\.sh:1: brings in a packager other than by the pinned download/);
    git("rm", "-q", "--cached", "ignored/get.sh"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "unforced");
    assert.equal(run().code, 0, "taken out of the repository again: left out");
    // the same in a new file git does not ignore (not added yet), and once committed: read, refused
    await fs.mkdir(join(d, "scripts"), { recursive: true }); await fs.writeFile(join(d, "scripts", "get.sh"), bad);
    const fresh = run(); assert.equal(fresh.code, 1, fresh.out); assert.match(fresh.out, /scripts\/get\.sh:1: brings in a packager other than by the pinned download/);
    git("add", "-A"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "y");
    const committed = run(); assert.equal(committed.code, 1, committed.out); assert.match(committed.out, /scripts\/get\.sh:1:/);
    await fs.rm(join(d, "scripts"), { recursive: true });
    // a known download gone (the workflow changed, or the guard reading less than it should): refused
    const st = join(d, ".github", "workflows", "site-test.yml");
    await fs.writeFile(st, (await fs.readFile(st, "utf8")).replace(/\n\s+curl -sSL -o \/usr\/local\/bin\/packager [^\n]+\n\s+echo "[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c - \|\| exit 1[^\n]*/, ""));
    const less = run(); assert.equal(less.code, 1, less.out); assert.match(less.out, /\.github\/workflows\/site-test\.yml: expected 1 pinned download of shaka-packager, read 0/);
  } finally { await fs.rm(d, { recursive: true, force: true }); }
});

test("the guard accepts a link only when its FIRST parameter is a safe value and it names no other levels= or clip=", async () => {
  const B = "https://oneandroid-max.github.io/ccs-protected-still-proof/web/research/drm/";
  assert.equal((await guardWith(null)).code, 0, "the repository as it is passes");
  for (const ok of ["?levels=fairplay", "?levels=fairplay&v=3", "?clip=card&v=1", "?levels=clearkey"]) {
    const r = await guardWith(B + ok); assert.equal(r.code, 0, `${ok} is accepted: ${r.out}`);
  }
  for (const bad of ["?levels=x&levels=fairplay", "?levels=x&amp;levels=fairplay", "?v=1&clip=card", "?clip=card&levels=x", "?levels=fairplay&clip=photo", "?levels=FAIRPLAY", "", "?clip=cards"]) {
    const r = await guardWith(B + bad); assert.equal(r.code, 1, `${bad || "(no query)"} is refused`); assert.match(r.out, /does not ask for the test card/);
  }
});

test("the guard keeps the CI drive to a local copy: no secret, no write access, no capture, no other tool, and the drive pinned", async () => {
  const W = ".github/workflows/site-drive.yml";
  const cases = [
    [[W, (t) => t.replace("PLAYWRIGHT_PKG=", "SITE_PASSWORD=${{ secrets.SITE_PASSWORD }} PLAYWRIGHT_PKG=")], /the drive lost a safeguard: no secret at all/],
    [[W, (t) => t.replace("  contents: read", "  contents: write")], /the drive lost a safeguard: (read-only|no write access anywhere)/],
    [[W, (t) => t.replace("      - name: The drive", "      - uses: actions/upload-artifact@v4\n        with: { name: x, path: walk }\n      - name: The drive")], /the drive lost a safeguard: nothing uploaded and no screen capture/],
    [[W, (t) => t.replace("node tools/drive-site.mjs 2>&1", "node tools/walk-site.mjs 2>&1")], /the drive lost a safeguard: it runs no tool but the drive and this guard/],
    [[W, (t) => t.replace("        with: { persist-credentials: false }\n", "")], /the drive lost a safeguard: checkout leaves no token behind/],
    [["tools/drive-site.mjs", (t) => t + "\n// a change\n"], /tools\/drive-site\.mjs changed .* update PINNED/],
    // the rules read as they claim, not only through the pin (the third review's cases): a secret read with
    // brackets, a command or an action before the guard, a tool named with ./
    [[W, (t) => t.replace("PLAYWRIGHT_PKG=", "X=${{ secrets['A'] }} PLAYWRIGHT_PKG=")], /the drive lost a safeguard: no secret at all/],
    [[W, (t) => t.replace("      - name: The guard first", "      - run: echo first\n      - name: The guard first")], /the drive lost a safeguard: this guard runs first/],
    [[W, (t) => t.replace("      - name: The guard first", "      - uses: someone/action@v1\n      - name: The guard first")], /the drive lost a safeguard: this guard runs first/],
    [[W, (t) => t.replace("node tools/drive-site.mjs 2>&1", "node ./tools/walk-site.mjs 2>&1")], /the drive lost a safeguard: it runs no tool but the drive and this guard/],
    [[".github/workflows/site-walk.yml", (t) => t.replace("      - uses: actions/checkout@v4", "      - run: echo first\n      - uses: actions/checkout@v4")], /the walk lost a safeguard: the walk job runs this guard before anything else/],
  ];
  for (const [edit, re] of cases) { const r = await guardWith(null, edit); assert.equal(r.code, 1, `${edit[0]} edited: refused`); assert.match(r.out, re, r.out); }
});
