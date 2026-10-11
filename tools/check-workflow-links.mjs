// Every workflow that opens the route-1 page must ask for the TEST CARD, never the owner's photo:
// the link has to carry ?clip=card (normal mode, card), ?levels=software (test mode), ?levels=fairplay
// (Apple test mode) or ?levels=clearkey (the unprotected control); every test value always plays the card
// (site/test/pages.test.mjs runs the page's own lines for each value named in SAFE_VALUES). The safe value
// must be the link's FIRST parameter and the only levels= or clip= in it: the page reads the first one, so
// "?levels=x&levels=fairplay" would play the photo while still containing a safe value (2026-10-11 review).
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
// that seals its captures; and the walker itself must delete each clear capture before sealing it. THE
// DRIVE (site-drive.yml) may start a browser too, only on a LOCAL copy with synthetic pictures: read-only,
// no secret, nothing uploaded, no capture, running no tool but itself and this guard, and the drive file
// pinned by content below (2026-10-11: the second review asked for the drive's checks in CI).
//
// THIRD RULE (2026-10-11, the sixth to ninth reviews): outside comments and step names, shaka-packager is named
// only by the pinned download, checked against its SHA-256 by the exact line that follows it; nothing under
// .github/ lets a failure pass.
//
//   node tools/check-workflow-links.mjs        exit 0 when every link asks for the card, 1 otherwise
import { readdirSync, readFileSync, lstatSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { createHash } from "node:crypto";

// every file is read with Windows line endings removed, so a Windows checkout judges exactly as Linux CI
const read = (f) => readFileSync(f, "utf8").replace(/\r\n/g, "\n");

const DIR = ".github/workflows";
const SAFE_VALUES = ["clip=card", "levels=software", "levels=fairplay", "levels=clearkey"];
const SAFE = new RegExp(`(^|[?&])(${SAFE_VALUES.join("|")})(&|$)`);
const LINK = /(https:\/\/[^\s"'`]*\/research\/drm\/|\$\{PAGE\}|\$env:PAGE|\$PAGE\b)/g;
let checked = 0;
const bad = [];
for (const file of readdirSync(DIR).filter((f) => /\.ya?ml$/.test(f))) {
  read(join(DIR, file)).split("\n").forEach((line, i) => {
    if (/^\s*#/.test(line) || /^\s*PAGE:\s/.test(line) || /^\s*echo\s/.test(line)) return;
    for (const m of line.matchAll(LINK)) {
      checked++;
      const rest = line.slice(m.index + m[0].length).replace(/^`/, "");
      const query = rest.startsWith("?") ? rest.slice(1).split(/[\s"'#]/)[0] : null;
      const params = query ? query.replace(/&amp;/g, "&").split("&") : [];
      const choosers = params.filter((p) => /^(levels|clip)=/.test(p));
      if (!query || !SAFE.test(params[0]) || choosers.length !== 1) bad.push(`${DIR}/${file}:${i + 1}: ${m[0]}${query ? "?" + query : ""} does not ask for the test card`);
    }
  });
}
// the second rule
const SITE = /(^|[^\w-])site\/|SITE_PASSWORD|walk-site/;
const BROWSER = /chrome|msedge|firefox|safari|screencapture|CopyFromScreen|import -window|playwright|puppeteer|simctl io/i;
const SITE_ALLOWED = {
  "site-photos.yml": "prepares pictures on the runner; opens no page",
  "site-fairplay.yml": "gives prepared pictures Apple's form on the runner; opens no page",
  "card-fairplay.yml": "packages the public test card (reads site/axinom.mjs for the key handling); opens no page, reads no picture",
  "site-test.yml": "tests the site's code; opens no page",
  "live-check.yml": "fetches pages with curl; every picture file it can fetch is encrypted",
  "site-walk.yml": "THE WALK: a real browser on the live site; every capture sealed (safeguards required below)",
  "site-drive.yml": "THE DRIVE: a browser on a LOCAL copy with synthetic pictures and a mocked GitHub API, never the live site (safeguards required below; the drive pinned)",
};
// "This guard runs first", read literally: the workflow's first command is this guard, and nothing but the
// checkout comes before it (an action can run code as surely as a command can).
const guardFirst = (t) => {
  const at = t.search(/^\s*(?:-\s+)?run: node tools\/check-workflow-links\.mjs\s*$/m);
  if (at < 0) return false;
  const before = t.slice(0, at);
  return !/^\s*(?:-\s+)?run:/m.test(before) && (before.match(/uses:\s*\S+/g) || []).every((u) => /^uses:\s*actions\/checkout@/.test(u));
};
const DRIVE_SAFEGUARDS = [
  [/^permissions:\s*\n\s+contents: read\s*$/m, "read-only"],
  [(t) => !/contents: write|id-token: write/.test(t), "no write access anywhere"],
  [(t) => !/secrets\s*[.[]|SITE_PASSWORD/.test(t), "no secret at all"],
  [/persist-credentials: false/, "checkout leaves no token behind"],
  [guardFirst, "this guard runs first"],
  [(t) => !/upload-artifact|screenshot|screencapture|CopyFromScreen|import -window/i.test(t), "nothing uploaded and no screen capture"],
  [(t) => (t.match(/node\s+(?:\.\/)?tools\/[\w./-]+/g) || []).every((x) => /^node\s+(?:\.\/)?tools\/(drive-site|check-workflow-links)\.mjs$/.test(x)), "it runs no tool but the drive and this guard"],
];
const WALK_SAFEGUARDS = [
  [/^permissions:\s*\n\s+contents: read/m, "read-only by default (only the keep job may write)"],
  [(t) => (t.match(/contents: write/g) || []).length === 1 && t.indexOf("contents: write") > t.indexOf("\n  keep:"), "write access only inside the keep job"],
  [guardFirst, "the walk job runs this guard before anything else"],
  [/path: \|\s*\n\s+walk\/\*\.sealed\.json\s*\n\s+walk\/\*-steps\.json\s*\n/, "the upload names only sealed captures and step records"],
  [/persist-credentials: false/, "checkout leaves no token behind"],
  [/os\.tmpdir\(\).*\^clear-.*rmSync\("walk".*process\.exit\(1\)/, "a clear capture left behind (in the temporary folder) is deleted, everything is refused, and the run fails"],
  [/if: always\(\)\s*\n\s+shell: bash\s*\n\s+run: \|\s*\n\s+ls -l walk/, "the clear-capture check runs even after a failed walk"],
  [/find dl -type f ! -name '\*\.sealed\.json' ! -name '\*-steps\.json'/, "the keep job refuses any file that is not sealed or a step record"],
  [/HEAD:walk-evidence/, "kept only on the walk-evidence branch"],
];
let siteFiles = 0;
for (const file of readdirSync(DIR).filter((f) => /\.ya?ml$/.test(f))) {
  const text = read(join(DIR, file));
  const live = text.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  if (!SITE.test(live)) continue;
  siteFiles++;
  if (!SITE_ALLOWED[file]) { bad.push(`${DIR}/${file}: touches the test site (the owner's own pictures) but is not in SITE_ALLOWED in tools/check-workflow-links.mjs`); continue; }
  if (file === "site-walk.yml") {
    for (const [re, what] of WALK_SAFEGUARDS) if (!(typeof re === "function" ? re(live) : re.test(live))) bad.push(`${DIR}/${file}: the walk lost a safeguard: ${what}`);
  } else if (file === "site-drive.yml") {
    for (const [re, what] of DRIVE_SAFEGUARDS) if (!(typeof re === "function" ? re(live) : re.test(live))) bad.push(`${DIR}/${file}: the drive lost a safeguard: ${what}`);
  } else if (BROWSER.test(live)) bad.push(`${DIR}/${file}: touches the test site and starts a browser or a screen capture (${live.match(BROWSER)[0]}); only the sealed walk may`);
}
// code only: comments removed, so a comment cannot stand in for the real line
const code = (t) => t.replace(/\/\*[\s\S]*?\*\//g, "").split("\n").map((l) => l.replace(/(^|[^:"'`])\/\/.*$/, "$1")).join("\n");
// A tool can open the live site from a workflow that never names it, and can build the address from
// parts, so EVERY file under tools/ (any extension, any depth) that names the Pages host at all must be
// the walker. (A known cost: a future tool for the public proof pages on that host must be named here
// with its reason.) The files judged are the repository's own (git ls-files), so a local run and CI see
// the same set; without git, every file but installed packages. A symbolic link is refused by name.
const HOST = /github\.io/i;
const walkDir = (d) => readdirSync(d).flatMap((x) => { const p = join(d, x); if (x === "node_modules") return []; const s = lstatSync(p); return s.isSymbolicLink() ? [p] : s.isDirectory() ? walkDir(p) : [p]; });
let toolFiles;
try { toolFiles = execFileSync("git", ["ls-files", "-z", "tools"], { encoding: "utf8" }).split("\0").filter(Boolean); } catch { toolFiles = walkDir("tools"); }
for (const f of toolFiles) {
  const rel = f.replace(/\\/g, "/");
  if (rel === "tools/walk-site.mjs") continue;
  let st; try { st = lstatSync(f); } catch { continue; } // listed by git but not on disk: nothing to open
  if (st.isSymbolicLink()) { bad.push(`${rel}: a symbolic link under tools/ is not allowed (its target cannot be judged)`); continue; }
  if (HOST.test(readFileSync(f, "latin1"))) bad.push(`${rel}: names the live Pages host; only tools/walk-site.mjs (sealed captures) may`);
}
// THE PIN. Rules about text can always be stepped around (a review found ten ways), so the walk's two
// files are pinned by content: ANY change to them fails here until this pin is updated in the same
// change, which forces whoever changes them to re-read the safeguards above, and a reviewer to see it.
const PINNED = {
  ".github/workflows/site-walk.yml": "143eb290c37498e84c3ecd128fe36845197ac1164751b9242e0152be36f8f1d0",
  "tools/walk-site.mjs": "4b2222eaa660a66bd8aa75eaf46f9821063cfa20f6f374b78e0250cf0bf1e5ce",
  ".github/workflows/site-drive.yml": "561f8bb83320ec4c3981fb399b5f09dbd4edf669fcb5826fee480f793a3dfbe7",
  "tools/drive-site.mjs": "8cec691ba3eaee61b6eea72b91e1b74637143be5cd97239e384deba0dd404b16",
};
for (const [f, want] of Object.entries(PINNED)) {
  const got = createHash("sha256").update(read(f)).digest("hex");
  if (got !== want) bad.push(`${f} changed (sha256 ${got.slice(0, 16)}…, pinned ${want.slice(0, 16)}…): re-read its sealing safeguards, then update PINNED in tools/check-workflow-links.mjs in the same change`);
}
const walker = code(read("tools/walk-site.mjs"));
const rmAt = walker.indexOf("await fs.rm(png"), sealAt = walker.indexOf("publicEncrypt(");
if (rmAt < 0 || sealAt < 0 || rmAt > sealAt) bad.push("tools/walk-site.mjs: each clear capture must be deleted (await fs.rm(png ...)) before it is sealed (publicEncrypt)");

// THIRD RULE (2026-10-11; the sixth review found three of nine downloads unpinned while the plan said all were;
// the seventh, eighth and ninth each stepped around the version before, the ninth also finding the eighth's rewrite
// narrower than what it replaced). shaka-packager is the one program the jobs fetch and run, on pictures among
// other things. Read: the repository's files (tracked or new, not ignored: git ls-files; every file where there is
// no git) that are YAML under .github/ (workflows and actions), Dockerfiles or Containerfiles, or shell scripts;
// whole-line comments left out.
//   (A) Outside those comments and YAML `name:` lines, shaka-packager may be named ONLY by the pinned download line,
//       `curl -sSL -o <file> <pinned release>` (in a Dockerfile, after RUN), and that line may stand only in a
//       workflow (.github/workflows/) or a Dockerfile, never in an action or a script a step could call: no other
//       source, version, image, action, container, package or install, however written.
//   (B) The very next line must be, exactly, that file's SHA-256 check: in YAML and scripts `echo "<sha256>  <file>"
//       | sha256sum -c - || exit 1` (a trailing comment allowed); in a Dockerfile `&& echo "<sha256>  <file>" |
//       sha256sum -c -`, after which the instruction may go on only with `&& …` lines.
//   (C) A workflow that downloads it lets no failure pass: no `continue-on-error` but false.
// This catches mistakes. An author set on getting around it (a name built from parts, say) can; review catches that.
const PACKAGER_URL = "https://github.com/shaka-project/shaka-packager/releases/download/v3.9.3/packager-linux-x64";
const PACKAGER_SHA256 = "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6";
const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const everyFile = (d) => { let names = []; try { names = readdirSync(d); } catch { return []; } return names.flatMap((x) => { const p = d === "." ? x : join(d, x); if (x === "node_modules" || x === ".git") return []; const st = lstatSync(p); return st.isDirectory() ? everyFile(p) : [p]; }); };
let repoFiles;
try { repoFiles = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\0").filter(Boolean); }
catch { repoFiles = everyFile("."); }
const isYaml = (f) => /^\.github\/.+\.ya?ml$/.test(f), isDocker = (f) => /(^|\/)(Dockerfile|Containerfile)[^/]*$|\.(dockerfile|containerfile)$/i.test(f), isScript = (f) => /\.sh$/.test(f);
const DOWNLOAD = new RegExp(`^\\s*(?:RUN\\s+)?curl -sSL -o (\\S+) ${esc(PACKAGER_URL)}(?:\\s+\\\\)?$`);
let downloads = 0;
for (const f of [...new Set(repoFiles)].filter((x) => isYaml(x) || isDocker(x) || isScript(x)).sort()) {
  let text; try { text = read(f); } catch { continue; } // a dangling link: nothing to read
  const lines = text.split("\n"), docker = isDocker(f);
  let fetches = 0;
  lines.forEach((line, i) => {
    if (/^\s*#/.test(line)) return;
    if (!/shaka-packager/i.test(line) || (isYaml(f) && /^\s*-?\s*name\s*:/.test(line))) return;
    const m = line.match(DOWNLOAD);
    if (!m) { bad.push(`${f}:${i + 1}: names shaka-packager other than by the pinned download (curl -sSL -o <file> ${PACKAGER_URL}): no other source, image, action or install`); return; }
    downloads++; fetches++;
    if (!(docker || /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f))) bad.push(`${f}:${i + 1}: downloads shaka-packager outside a workflow or a Dockerfile (an action or a script could be run where a failure passes)`);
    const out = m[1];
    const check = docker ? new RegExp(`^\\s*&& echo "${PACKAGER_SHA256}  ${esc(out)}" \\| sha256sum -c -(?:\\s+\\\\)?$`) : new RegExp(`^\\s*echo "${PACKAGER_SHA256}  ${esc(out)}" \\| sha256sum -c - \\|\\| exit 1(?:\\s+#.*)?$`);
    if (!check.test(lines[i + 1] || "")) { bad.push(`${f}:${i + 1}: the downloaded packager must be checked against its SHA-256 on the very next line, exactly: ${docker ? "&& " : ""}echo "${PACKAGER_SHA256.slice(0, 12)}…  ${out}" | sha256sum -c -${docker ? "" : " || exit 1"}`); return; }
    if (docker) for (let j = i + 2; j < lines.length && /\\\s*$/.test(lines[j - 1]); j++) if (!/^\s*&&\s/.test(lines[j])) bad.push(`${f}:${j + 1}: after the packager's check, this instruction may go on only with '&& …' lines (anything else could swallow a failed check)`);
  });
  if (fetches) lines.forEach((line, i) => { if (!/^\s*#/.test(line) && /continue-on-error\s*:(?!\s*false\b)/.test(line)) bad.push(`${f}:${i + 1}: downloads shaka-packager and lets a failure pass (continue-on-error)`); });
}

if (bad.length) {
  console.error(`FAIL: ${bad.length} problem(s); ${checked} workflow links to the route-1 page checked, ${siteFiles} workflows touching the test site, ${downloads} packager downloads:`);
  for (const b of bad) console.error("  " + b);
  if (bad.some((b) => /does not ask for the test card/.test(b))) console.error(`Add one of ${SAFE_VALUES.join(", ")} as the FIRST parameter of each link's query.`);
  process.exit(1);
}
console.log(`ok: all ${checked} workflow links to the route-1 page ask for the test card; ${siteFiles} workflows touch the test site, each named, and the walk keeps its sealing safeguards; all ${downloads} shaka-packager downloads are the pinned release, checked by its SHA-256`);
