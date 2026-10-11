// Every workflow that opens the route-1 page must ask for the TEST CARD, never the owner's photo:
// the link has to carry ?clip=card (normal mode, card), ?levels=software (test mode) or ?levels=clearkey
// (the unprotected control); both test values always play the card.
// Born 2026-10-11: a runner screenshot of the page in test mode showed the photo in clear (software
// protection does not hide it on Linux), and the workflow committed it to the public repository.
// Checks every https URL ending in /research/drm/ and every use of $PAGE / ${PAGE} / $env:PAGE, in
// every file under .github/workflows/. Two kinds of line are skipped because they open nothing: the env
// line that defines PAGE, and a line that only prints a link (`echo …`).
//
// SECOND RULE (2026-10-11, from the independent review of the all-at-once view): the password-protected
// test site shows the owner's OWN pictures, and a runner has no protected path, so a runner that opens
// it in a browser captures them in clear. Every workflow that touches the site (a `site/` path or page,
// SITE_PASSWORD, or the walker) must be named below with its reason. A named one that is not the walk
// must start no browser and take no screen capture. The walk may, only while it keeps every safeguard
// that seals its captures; and the walker itself must delete each clear capture before sealing it.
//
//   node tools/check-workflow-links.mjs        exit 0 when every link asks for the card, 1 otherwise
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const DIR = ".github/workflows";
const SAFE = /(^|[?&])(clip=card|levels=software|levels=clearkey)(&|$)/;
const LINK = /(https:\/\/[^\s"'`]*\/research\/drm\/|\$\{PAGE\}|\$env:PAGE|\$PAGE\b)/g;
let checked = 0;
const bad = [];
for (const file of readdirSync(DIR).filter((f) => /\.ya?ml$/.test(f))) {
  readFileSync(join(DIR, file), "utf8").split("\n").forEach((line, i) => {
    if (/^\s*#/.test(line) || /^\s*PAGE:\s/.test(line) || /^\s*echo\s/.test(line)) return;
    for (const m of line.matchAll(LINK)) {
      checked++;
      const rest = line.slice(m.index + m[0].length).replace(/^`/, "");
      const query = rest.startsWith("?") ? rest.slice(1).split(/[\s"'#]/)[0] : null;
      if (!query || !SAFE.test(query)) bad.push(`${DIR}/${file}:${i + 1}: ${m[0]}${query ? "?" + query : ""} does not ask for the test card`);
    }
  });
}
// the second rule
const SITE = /(^|[^\w-])site\/|SITE_PASSWORD|walk-site/;
const BROWSER = /chrome|msedge|firefox|safari|screencapture|CopyFromScreen|import -window|playwright|puppeteer|simctl io/i;
const SITE_ALLOWED = {
  "site-photos.yml": "prepares pictures on the runner; opens no page",
  "site-test.yml": "tests the site's code; opens no page",
  "live-check.yml": "fetches pages with curl; every picture file it can fetch is encrypted",
  "site-walk.yml": "THE WALK: a real browser on the live site; every capture sealed (safeguards required below)",
};
const WALK_SAFEGUARDS = [
  [/^permissions:\s*\n\s+contents: read/m, "read-only by default (only the keep job may write)"],
  [/persist-credentials: false/, "checkout leaves no token behind"],
  [/ls walk\/clear-\*.*rm -rf walk; exit 1/, "a clear capture left behind deletes everything and fails"],
  [/find dl -type f ! -name '\*\.sealed\.json' ! -name '\*-steps\.json'/, "the keep job refuses any file that is not sealed or a step record"],
  [/HEAD:walk-evidence/, "kept only on the walk-evidence branch"],
];
let siteFiles = 0;
for (const file of readdirSync(DIR).filter((f) => /\.ya?ml$/.test(f))) {
  const text = readFileSync(join(DIR, file), "utf8");
  const live = text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  if (!SITE.test(live)) continue;
  siteFiles++;
  if (!SITE_ALLOWED[file]) { bad.push(`${DIR}/${file}: touches the test site (the owner's own pictures) but is not in SITE_ALLOWED in tools/check-workflow-links.mjs`); continue; }
  if (file === "site-walk.yml") {
    for (const [re, what] of WALK_SAFEGUARDS) if (!re.test(live)) bad.push(`${DIR}/${file}: the walk lost a safeguard: ${what}`);
  } else if (BROWSER.test(live)) bad.push(`${DIR}/${file}: touches the test site and starts a browser or a screen capture (${live.match(BROWSER)[0]}); only the sealed walk may`);
}
const walker = readFileSync("tools/walk-site.mjs", "utf8");
const rmAt = walker.indexOf("await fs.rm(png"), sealAt = walker.indexOf("publicEncrypt(");
if (rmAt < 0 || sealAt < 0 || rmAt > sealAt) bad.push("tools/walk-site.mjs: each clear capture must be deleted (await fs.rm(png ...)) before it is sealed (publicEncrypt)");

if (bad.length) {
  console.error(`FAIL: ${bad.length} problem(s); ${checked} workflow links to the route-1 page checked, ${siteFiles} workflows touching the test site:`);
  for (const b of bad) console.error("  " + b);
  if (bad.some((b) => /does not ask for the test card/.test(b))) console.error("Add clip=card, levels=software or levels=clearkey as the FIRST parameter of each link's query.");
  process.exit(1);
}
console.log(`ok: all ${checked} workflow links to the route-1 page ask for the test card; ${siteFiles} workflows touch the test site, each named, and the walk keeps its sealing safeguards`);
