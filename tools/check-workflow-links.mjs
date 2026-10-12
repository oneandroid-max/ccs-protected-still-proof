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
// THIRD RULE (2026-10-11, the sixth to tenth reviews): a packager gets onto a runner or into an image only by the
// pinned download, in a workflow or a Dockerfile, checked against its SHA-256 by the exact line that follows it; a
// workflow that downloads it lets no failure pass; every known download is counted (details below).
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
  ".github/workflows/site-drive.yml": "0993f64c22ef8c329b9a6a8ec8e9df5c35e4accfd4dfc8285b98ea25a4d8da90",
  "tools/drive-site.mjs": "eb0656285710d869a69dc37185882be47e707bbcae731e5ab298d5ed908fc845",
};
for (const [f, want] of Object.entries(PINNED)) {
  const got = createHash("sha256").update(read(f)).digest("hex");
  if (got !== want) bad.push(`${f} changed (sha256 ${got.slice(0, 16)}…, pinned ${want.slice(0, 16)}…): re-read its sealing safeguards, then update PINNED in tools/check-workflow-links.mjs in the same change`);
}
const walker = code(read("tools/walk-site.mjs"));
const rmAt = walker.indexOf("await fs.rm(png"), sealAt = walker.indexOf("publicEncrypt(");
if (rmAt < 0 || sealAt < 0 || rmAt > sealAt) bad.push("tools/walk-site.mjs: each clear capture must be deleted (await fs.rm(png ...)) before it is sealed (publicEncrypt)");

// THIRD RULE (2026-10-11; the sixth review found three of nine downloads unpinned while the plan said all were; the
// seventh to eleventh each found the version before stepped around). shaka-packager is the one program the jobs fetch
// and run on pictures. FOR OUR PROGRAMS AND THE TESTS THE GUARANTEE IS NOT THIS TEXT RULE: each one checks the file it is
// about to run against the pinned build's SHA-256, at that moment (service/lib/packager-pin.mjs, the same value as
// PACKAGER_SHA256 below, a test keeps them equal), refuses any other, however it got there, before it is ever run, and
// runs exactly the path it checked: site/worker.mjs, site/backfill.mjs, tools/fairplay-card.mjs, the service, and the
// tests (before any test runs it). A workflow step runs it through tools/run-packager.mjs, which does the same; that a
// step runs it only so is this text rule's to keep, rule (E) below, in the ordinary shapes (a deliberate shape is for
// review). The rest of this rule only catches the obvious slips: a workflow, image or script that brings in a packager
// some other way. It reads every file in the repository
// but what git ignores (where git cannot say, nothing is left out) of these kinds: YAML anywhere (workflows, actions,
// compose files), Dockerfiles and Containerfiles, Makefiles, package.json, and shell, PowerShell and batch scripts.
// NOT read: JavaScript, Python, lock files, files of other kinds, installed packages. Whole-line comments are left out,
// and so is a trailing comment ('#' after a space, outside quotes). One line at a time.
//   (A) A line must be the pinned download when it names shaka-packager itself (an image, a package, a repository, an
//       action), or names a packager in any form ("packager" in any case: packager-linux-x64, setup-packager,
//       /usr/local/bin/packager) AND could bring one in (an address; a fetch, copy, archive, install or package
//       command; a container image, an action or an action's input; in a Dockerfile an image to build on, ADD, COPY
//       from anything but one of its own stages, or a build mount from an image). Passed: a YAML `name:` line (outside
//       an action's inputs); a Dockerfile LABEL; an echo or printf (in a Dockerfile, after RUN) with nothing on it that
//       could fetch. The pinned
//       download is `curl -o <folder>/packager <pinned release>`, its only other options -f, -s, -S, -L or their long
//       forms, quotes allowed (in a Dockerfile after RUN), and it may stand only in a workflow (.github/workflows/) or a
//       Dockerfile. The file is saved under the name packager, so that rule (E) sees every later use of it (the
//       fourteenth review: a download saved as `pk`, or as `packager-v3.9.3`, was invisible to (E)).
//   (B) The very next line must be that file's SHA-256 check, exactly: in a workflow `echo "<sha256>  <file>" |
//       sha256sum -c - || exit 1` (a trailing comment allowed); in a Dockerfile `&& echo "<sha256>  <file>" |
//       sha256sum -c -`, after which the instruction may go on only with lines that start with '&&' and hold no ';',
//       '||' or lone '&' (each could swallow a failed check).
//   (C) A workflow that downloads it lets no failure pass: no `continue-on-error` but false, its key quoted or not.
//   (D) Every known download is counted (DOWNLOADERS): when one of the listed files has more or fewer than listed (a
//       workflow that stops downloading, or a guard that stops reading that file), it fails; a new download is listed.
//   (E) In a workflow, the packager file may be named only where nothing runs it unchecked: its pinned download and check
//       lines, `chmod +x <path>`, the value of PACKAGER_BIN (our programs and the tests check that file themselves),
//       and right after `node tools/run-packager.mjs`, the one way a workflow runs it (it checks the file at that
//       moment, then runs exactly that file). Any other word naming it is refused, in the ordinary shapes (in quotes,
//       after `if` or `timeout`, inside `$( )`, in a variable, a step in YAML's one-line form): its path (…/packager,
//       …/shaka-packager, …/packager-<platform>), its bare name (packager, packager-<platform>: the PATH would decide
//       which file), or PACKAGER_BIN read in the shell. Every run through the runner is counted (CHECKED_RUNS): a guard
//       that stops reading a workflow fails. It reads one line at a time, word by word, and judges an exception by the
//       word before it: a deliberate shape is for review (the fourteenth review ran eight past it: a shell line that
//       starts like a YAML `name:`, a YAML anchor or flow mapping that hides a run in a name, an exception's own word put
//       before a run, a `chmod` shadowed by a shell function, a line continued so that the runner's argument goes to
//       another command, a glob).
// NOT seen, by design: a packager named only on a line that brings nothing in (a `COPY --from=<image> \` whose next
// line names the packager; `cat file | tee …/packager`, though in a workflow (E) refuses that line), a script with no
// extension or of a kind not read, a packager run from inside a script a step calls or from a composite action, a name
// built from parts. Wherever one of our programs runs the packager, the run-time check refuses what any of these
// brings; the rest is for review. Also refused, though harmless: an `install` or `cp` of the downloaded file (download
// it to where it runs), an action input naming a packager file (an artifact `packager-version.txt`: name it otherwise),
// an echo of the release address, curl options beyond -f, -s, -S, -L, and in a workflow the word "packager" alone in a
// printed message (write "shaka-packager").
const PACKAGER_URL = "https://github.com/shaka-project/shaka-packager/releases/download/v3.9.3/packager-linux-x64";
const PACKAGER_SHA256 = "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6";
const DOWNLOADERS = {
  ".github/workflows/card-fairplay.yml": 1, ".github/workflows/drm-card.yml": 1, ".github/workflows/drm-package.yml": 1,
  ".github/workflows/service-test.yml": 1, ".github/workflows/site-fairplay.yml": 1, ".github/workflows/site-photos.yml": 2,
  ".github/workflows/site-test.yml": 1, "service/Dockerfile": 1,
};
const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const everyFile = (d) => { let names = []; try { names = readdirSync(d); } catch { return []; } return names.flatMap((x) => { const p = d === "." ? x : join(d, x); if (x === "node_modules" || x === ".git") return []; const st = lstatSync(p); return st.isDirectory() ? everyFile(p) : [p]; }); };
// every file, as '/' paths (a Windows checkout judges as Linux CI does); what git ignores is never committed, so it is
// left out; if git cannot say (no git, not a repository, any failure), nothing is left out
const repoFiles = everyFile(".").map((p) => p.replace(/\\/g, "/"));
let ignored = new Set();
try { ignored = new Set(execFileSync("git", ["check-ignore", "-z", "--stdin"], { input: repoFiles.join("\0") + "\0", encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] }).split("\0").filter(Boolean)); } catch {}
const kind = (f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f) ? "workflow"
  : /(^|\/)(Dockerfile|Containerfile)[^/]*$|\.(dockerfile|containerfile)$/i.test(f) ? "docker"
  : /\.ya?ml$/i.test(f) || /(^|\/)(GNUmakefile|makefile)$|\.mk$/i.test(f) || /(^|\/)package\.json$/i.test(f) || /\.(sh|bash|zsh|ps1|psm1|cmd|bat)$/i.test(f) ? "other" : null;
// a trailing comment: '#' at the start or after a space, outside quotes
const uncomment = (line) => { let q = ""; for (let i = 0; i < line.length; i++) { const c = line[i]; if (q) { if (c === "\\" && q === '"') i++; else if (c === q) q = ""; } else if (c === "'" || c === '"') q = c; else if (c === "\\") i++; else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i); } return line; };
const BRINGS = new RegExp([
  "[a-z][a-z0-9+.-]*://",
  "\\b(curl|wget|aria2c|axel|invoke-webrequest|iwr|invoke-restmethod|irm|start-bitstransfer|bitsadmin|certutil|fetch|svn|scp|rsync|s?ftp|tftp)\\b",
  "\\bgh\\s+(release|api|run\\s+download)\\b", "\\bgit\\s+(clone|fetch|pull|submodule|archive)\\b",
  "\\b(cp|mv|ln|install|dd|tar|unzip|7z|gunzip|bunzip2|unxz|zstd)\\b",
  "\\b(npm|npx|pnpm|yarn|bunx|pip3?|pipx|uvx?|conda|mamba|apt|apt-get|aptitude|dpkg|yum|dnf|rpm|apk|zypper|pacman|brew|choco|winget|scoop|snap|flatpak|nix|nix-env|cargo|gem|composer)\\b",
  "\\bgo\\s+(install|get|run)\\b", "\\bdotnet\\s+tool\\b",
  "\\b(docker|podman|nerdctl|buildah|ctr|crane|skopeo|oras)\\b", "\\bfrom=",
  "\\b(uses|image|container|with)\\s*:",
].join("|"), "i");
// a line that names shaka-packager itself is judged as bringing one in, unless it only prints or labels (a name line
// is passed before this is asked; a print line that could fetch is still judged by bringsIn)
const namesIt = (code, docker) => /shaka-packager/i.test(code) && !(docker && /^\s*LABEL\b/i.test(code)) && !/^\s*(?:-\s+)?(?:run\s*:\s*|run\s+)?(?:echo|printf)\b/i.test(code);
function bringsIn(code, docker, stages) {
  if (docker) {
    const from = code.match(/^\s*FROM\s+(?:--\S+\s+)*(\S+)/i);
    if (from) return /packager/i.test(from[1]); // only the image it is built on can bring one; a stage's name brings nothing
    if (/^\s*(ADD|COPY)\b/i.test(code)) { const src = code.match(/--from=(\S+)/i); return !(src && stages.has(src[1].toLowerCase())); }
  }
  return BRINGS.test(code);
}
// the pinned download line: the output file, or null
const unquote = (w) => /^"[^"]*"$|^'[^']*'$/.test(w) ? w.slice(1, -1) : w;
function pinnedDownload(code) {
  const words = code.trim().replace(/\s+\\$/, "").replace(/^RUN\s+/, "").split(/\s+/);
  if (words[0] !== "curl") return null;
  let out = null, url = null;
  for (let k = 1; k < words.length; k++) {
    const w = words[k];
    if (/^-[fsSL]+$/.test(w) || /^--(fail|silent|show-error|location)$/.test(w)) continue;
    if ((w === "-o" || w === "--output") && out === null && k + 1 < words.length) { out = unquote(words[++k]); continue; }
    if (unquote(w) === PACKAGER_URL && url === null) { url = w; continue; }
    return null;
  }
  return url && out && /^[\w./${}-]+$/.test(out) ? out : null;
}
let downloads = 0;
const counts = {};
for (const f of repoFiles.filter((x) => !ignored.has(x) && kind(x)).sort()) {
  let text; try { text = read(f); } catch { continue; } // a dangling link, or a link to a folder: nothing to read
  const k = kind(f), docker = k === "docker", yaml = /\.ya?ml$/i.test(f), lines = text.split("\n"), stages = new Set();
  let withAt = -1, fetches = 0;
  lines.forEach((line, i) => {
    if (/^\s*#/.test(line)) return;
    const code = uncomment(line), indent = code.search(/\S/);
    if (withAt >= 0 && indent >= 0 && indent <= withAt) withAt = -1; // the end of an action's inputs
    const inWith = withAt >= 0 && indent > withAt;
    if (yaml && /^\s*(?:-\s+)?with\s*:\s*$/.test(code)) withAt = code.indexOf("with");
    if (docker) { const st = code.match(/^\s*FROM\s+(?:--\S+\s+)*\S+\s+AS\s+(\S+)/i); if (st) stages.add(st[1].toLowerCase()); }
    if (!/packager/i.test(code)) return;
    if (yaml && !inWith && /^\s*(?:-\s+)?name\s*:/.test(code)) return; // a name brings nothing in
    if (!inWith && !namesIt(code, docker) && !bringsIn(code, docker, stages)) return;
    const out = inWith ? null : pinnedDownload(code);
    if (!out) { bad.push(`${f}:${i + 1}: brings in a packager other than by the pinned download (curl -o <file> ${PACKAGER_URL}, checked on the next line): no other source, version, image, action, artifact, cache, copy, archive or install`); return; }
    if (!/(^|\/)packager$/.test(out)) bad.push(`${f}:${i + 1}: the pinned download must be saved as <folder>/packager, so that every later use of the file is seen (rule E); ${out} is not`);
    downloads++; fetches++; counts[f] = (counts[f] || 0) + 1;
    if (k !== "workflow" && !docker) bad.push(`${f}:${i + 1}: downloads shaka-packager outside a workflow or a Dockerfile (an action or a script could be run where a failure passes)`);
    const check = docker ? new RegExp(`^\\s*&& echo "${PACKAGER_SHA256}  ${esc(out)}" \\| sha256sum -c -(?:\\s+\\\\)?$`) : new RegExp(`^\\s*echo "${PACKAGER_SHA256}  ${esc(out)}" \\| sha256sum -c - \\|\\| exit 1(?:\\s+#.*)?$`);
    if (!check.test(lines[i + 1] || "")) { bad.push(`${f}:${i + 1}: the downloaded packager must be checked against its SHA-256 on the very next line, exactly: ${docker ? "&& " : ""}echo "${PACKAGER_SHA256.slice(0, 12)}…  ${out}" | sha256sum -c -${docker ? "" : " || exit 1"}`); return; }
    if (docker) for (let j = i + 2; j < lines.length && /\\\s*$/.test(lines[j - 1]); j++) {
      const c = uncomment(lines[j]);
      if (!/^\s*&&\s/.test(c) || /;|\|\||(?<![&<>])&(?![&>])/.test(c.replace(/^\s*&&/, ""))) bad.push(`${f}:${j + 1}: after the packager's check, this instruction may go on only with '&& …' lines holding no ';', '||' or lone '&' (each could swallow a failed check)`);
    }
  });
  if (fetches) lines.forEach((line, i) => { if (!/^\s*#/.test(line) && /continue-on-error["']?\s*:(?!\s*false\b)/.test(uncomment(line))) bad.push(`${f}:${i + 1}: downloads shaka-packager and lets a failure pass (continue-on-error)`); });
}
// (E) the runs: in a workflow, every word that names the packager file must stand where nothing runs it unchecked
const RUNNER = "tools/run-packager.mjs";
const CHECKED_RUNS = {
  ".github/workflows/card-fairplay.yml": 1, ".github/workflows/drm-card.yml": 3, ".github/workflows/drm-package.yml": 3,
  ".github/workflows/service-test.yml": 1, ".github/workflows/site-fairplay.yml": 1, ".github/workflows/site-photos.yml": 2,
  ".github/workflows/site-test.yml": 1,
};
// its path (…/packager, …/shaka-packager, …/packager-<platform>) or its bare name (packager, packager-<platform>)
const PLATFORM = "(?:linux|osx|mac|macos|darwin|win|windows)[\\w.-]*";
const PATH_WORD = new RegExp(`/(?:shaka-)?packager(?:-${PLATFORM})?$`, "i"), BARE_WORD = new RegExp(`^packager(?:-${PLATFORM})?$`, "i");
const CHECK_LINE = new RegExp(`^\\s*echo "${PACKAGER_SHA256}  \\S+" \\| sha256sum -c - \\|\\| exit 1\\s*$`);
const runCounts = {};
let runsSeen = 0;
for (const f of repoFiles.filter((x) => !ignored.has(x) && kind(x) === "workflow").sort()) {
  let text; try { text = read(f); } catch { continue; }
  text.split("\n").forEach((line, i) => {
    if (/^\s*#/.test(line)) return;
    const code = uncomment(line);
    if (/^\s*(?:-\s+)?name\s*:/.test(code) || pinnedDownload(code) || CHECK_LINE.test(code)) return; // a name; (A) and (B) judge the rest
    // the words, split at spaces and at the shell's and YAML's punctuation (quotes, `$( )`, a variable's '=', a flow
    // mapping's braces, a flow sequence's brackets, a backslash stand apart; ${NAME} is read as $NAME)
    const words = code.replace(/\$\{(\w+)\}/g, "$$$1").split(/[\s;&|()<>`'"=,{}[\]\\]+/).filter(Boolean);
    words.forEach((w, k) => {
      if (w === RUNNER && words[k - 1] === "node") { runsSeen++; runCounts[f] = (runCounts[f] || 0) + 1; return; }
      if (!(PATH_WORD.test(w) || BARE_WORD.test(w) || /PACKAGER_BIN/.test(w))) return;
      if (w === "PACKAGER_BIN:" || words[k - 1] === "PACKAGER_BIN:") return; // the key and its value: our programs and the tests check that file
      if (words[k - 1] === RUNNER && words[k - 2] === "node") return; // the runner checks it, then runs exactly that file
      if (words[k - 1] === "+x" && words[k - 2] === "chmod") return; // made runnable, not run
      bad.push(`${f}:${i + 1}: names the packager file (${w}) where it could run unchecked: a workflow runs it only as \`node ${RUNNER} <path> …\` (it checks the file by its SHA-256, then runs exactly that file); elsewhere the file may stand only in its pinned download, its check line, \`chmod +x <path>\` and PACKAGER_BIN`);
    });
  });
}
for (const [f, n] of Object.entries(CHECKED_RUNS)) if ((runCounts[f] || 0) !== n) bad.push(`${f}: expected ${n} run${n === 1 ? "" : "s"} of the packager through ${RUNNER}, read ${runCounts[f] || 0} (a guard that reads less fails here; when a workflow changes, update CHECKED_RUNS in tools/check-workflow-links.mjs)`);
for (const f of Object.keys(runCounts)) if (!(f in CHECKED_RUNS)) bad.push(`${f}: runs the packager through ${RUNNER}, and CHECKED_RUNS in tools/check-workflow-links.mjs does not list it: add it there with its count`);
for (const [f, n] of Object.entries(DOWNLOADERS)) if ((counts[f] || 0) !== n) bad.push(`${f}: expected ${n} pinned download${n === 1 ? "" : "s"} of shaka-packager, read ${counts[f] || 0} (a guard that reads less fails here; when a workflow changes, update DOWNLOADERS in tools/check-workflow-links.mjs)`);
for (const f of Object.keys(counts)) if (!(f in DOWNLOADERS)) bad.push(`${f}: a pinned download of shaka-packager that DOWNLOADERS in tools/check-workflow-links.mjs does not list: add it there with its count`);

if (bad.length) {
  console.error(`FAIL: ${bad.length} problem(s); ${checked} workflow links to the route-1 page checked, ${siteFiles} workflows touching the test site, ${downloads} packager downloads:`);
  for (const b of bad) console.error("  " + b);
  if (bad.some((b) => /does not ask for the test card/.test(b))) console.error(`Add one of ${SAFE_VALUES.join(", ")} as the FIRST parameter of each link's query.`);
  process.exit(1);
}
console.log(`ok: all ${checked} workflow links to the route-1 page ask for the test card; ${siteFiles} workflows touch the test site, each named, and the walk keeps its sealing safeguards; all ${downloads} shaka-packager downloads are the pinned release, checked by its SHA-256, and all ${runsSeen} runs of it go through ${RUNNER}, which checks it first`);
