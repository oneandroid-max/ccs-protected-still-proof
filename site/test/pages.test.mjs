// The protected pages' own decision lines, READ FROM THE HTML (never copied), run for many kinds of
// device and every kind of link: which protection is tried, and whether it would play the test card or a
// picture. The rules checked, on the route-1 page and on the two pages generated from it:
//   - every test link (each value the workflow guard accepts) plays the TEST CARD, and Apple's test the
//     card's form with Axinom's PUBLIC token, never a picture's;
//   - on Apple's engine (every iPhone or iPad browser, Safari on a Mac) nothing at all is tried for the
//     picture until FAIRPLAY_MEASURED holds a date for that platform, and then only Apple's own form,
//     with the picture's own form and token;
//   - nowhere else is the Apple form tried outside its test, and the switch changes nothing there.
// Also: the workflow guard refuses a link whose first parameter is not the safe one, or that names a
// second levels= or clip= (the page reads the first; the bypass a review found on 2026-10-11).
import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

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
  return new Function("navigator", "location", "set", "CTX", body + "\nreturn { PLATFORM, APPLE, TEST, CARD, ORDER, CLIP, FAIRPLAY_OK };");
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

test("the pages' own lines, for 20 kinds of device and every kind of link: tests play only the card; Apple holds the picture back until measured; nothing else changes", async () => {
  const route1 = await read("web/research/drm/index.html");
  const publicToken = route1.match(/const AXINOM_PUBLIC_TOKEN = "([^"]+)"/)[1];
  const pages = { "route-1 page": route1, "site/view.html": await read("site/view.html"), "site/all.html": await read("site/all.html") };
  let runs = 0;
  for (const [pageName, html] of Object.entries(pages)) {
    const cardPath = pageName === "route-1 page" ? "card-fairplay/master.m3u8" : "../web/research/drm/card-fairplay/master.m3u8";
    for (const measured of [null, { "iPhone/iPad": "2026-10-11", "Mac": "" }, { "iPhone/iPad": "", "Mac": "2026-10-11" }]) {
      const fn = decide(html, measured);
      for (const [dev, [ua, touch, apple, platform]] of Object.entries(DEVICES)) {
        const at = (q) => { runs++; return fn({ userAgent: ua, maxTouchPoints: touch }, { search: q }, () => {}, CTX); };
        const what = (q) => `${pageName}, ${dev}, "${q}", Apple switch ${JSON.stringify(measured)}`;
        const plain = (q) => { // a link that is not a test
          const r = at(q);
          assert.equal(r.PLATFORM, platform, what(q)); assert.equal(r.APPLE, apple, what(q)); assert.equal(r.TEST, false, what(q));
          const ok = apple && !!(measured && measured[platform]);
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
          if (r.ORDER.includes("fairplay-apple")) assert.ok(apple && measured && measured[platform], what(q) + ": Apple's form only where measured");
        }
      }
    }
  }
  assert.ok(runs > 1500, `${runs} combinations run`);
});

// The guard, run in a copy of the repository's workflows and tools with one extra workflow
async function guardWith(extra) {
  const d = await fs.mkdtemp(join(tmpdir(), "guard-"));
  await fs.cp(join(REPO, ".github"), join(d, ".github"), { recursive: true });
  await fs.cp(join(REPO, "tools"), join(d, "tools"), { recursive: true, filter: (src) => !src.includes("node_modules") });
  if (extra) await fs.writeFile(join(d, ".github", "workflows", "zz-extra.yml"), `name: x\non: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -sS "${extra}"\n`);
  const r = spawnSync(process.execPath, [join(d, "tools", "check-workflow-links.mjs")], { cwd: d, encoding: "utf8" });
  await fs.rm(d, { recursive: true, force: true });
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}
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
