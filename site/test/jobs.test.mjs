// Runs the two job scripts of site-photos.yml, and the Apple backfill's of site-fairplay.yml, exactly as
// written (extracted from the workflow files) in
// a scratch repository with a bare remote, with a stand-in site/worker.mjs, so the commit-and-push loop
// is proven before GitHub runs it: a combined-view job with nothing to combine must end quietly (it
// once failed on `git add` of a folder that never existed), a job's output must reach the remote, and a
// job whose push loses a race must refresh, run again and push. GitHub's own wiring (if:, needs:,
// concurrency) can only be proven by GitHub; these are the scripts it runs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const WF = await fs.readFile(join(REPO, ".github", "workflows", "site-photos.yml"), "utf8");
const FP_WF = await fs.readFile(join(REPO, ".github", "workflows", "site-fairplay.yml"), "utf8");

// The `run: |` block of the step with this name, de-indented.
export function runBlock(yaml, stepName) {
  const lines = yaml.split("\n");
  const at = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
  assert.ok(at >= 0, `no step named "${stepName}"`);
  const runAt = lines.findIndex((l, i) => i > at && /^\s+run: \|\s*$/.test(l));
  assert.ok(runAt > at, `the step "${stepName}" has no run block`);
  const base = lines[runAt].search(/\S/);
  const body = [];
  for (let i = runAt + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() && l.search(/\S/) <= base) break;
    body.push(l);
  }
  const cut = Math.min(...body.filter((l) => l.trim()).map((l) => l.search(/\S/)));
  return body.map((l) => l.slice(cut)).join("\n");
}
const PHOTO = runBlock(WF, "Prepare the picture on the current tip of main and commit; refresh and redo if the push races");
const MOSAIC = runBlock(WF, "Make the combined view on the current tip of main and commit; refresh and redo if the push races");
const FP_STEP = "Give every picture and the combined view Apple's form, on the current tip of main; refresh and redo if the push races";
const BACKFILL = runBlock(FP_WF, FP_STEP);

const git = (cwd, ...a) => execFileSync("git", a, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

// The stand-in worker: STANDIN=none writes nothing; =mosaic writes site/mosaic/meta.json.enc; =photo
// writes site/photos/<ID>/x.enc. With RACE_ONCE set, its first run pushes a commit from another clone,
// so the job's own first push loses the race.
const STANDIN = `import { promises as fs } from "node:fs";
import { execFileSync } from "node:child_process";
const counter = process.env.RUN_COUNTER;
const n = Number(await fs.readFile(counter, "utf8").catch(() => "0")) + 1;
await fs.writeFile(counter, String(n));
if (process.env.RACE_ONCE && n === 1) {
  const o = process.env.RACE_ONCE;
  execFileSync("git", ["-C", o, "pull", "-q", "origin", "main"]);
  await fs.writeFile(o + "/site/other.txt", "another job's commit " + Date.now());
  execFileSync("git", ["-C", o, "add", "-A"]); execFileSync("git", ["-C", o, "commit", "-qm", "another job"]); execFileSync("git", ["-C", o, "push", "-q", "origin", "HEAD:main"]);
}
const mode = process.env.STANDIN;
if (mode === "mosaic") { await fs.mkdir("site/mosaic", { recursive: true }); await fs.writeFile("site/mosaic/meta.json.enc", "sealed " + n); }
if (mode === "photo") { await fs.mkdir("site/photos/" + process.env.ID, { recursive: true }); await fs.writeFile("site/photos/" + process.env.ID + "/x.enc", "sealed " + n); }
if (mode === "backfill") { // what the Apple backfill writes, and its counts
  await fs.mkdir("site/photos/p1/fp-0a1b2c3d", { recursive: true }); await fs.writeFile("site/photos/p1/fp-token.enc", "sealed token " + n);
  await fs.writeFile("site/gallery.json.enc", "sealed gallery " + n);
  await fs.mkdir("site/mosaic", { recursive: true }); await fs.writeFile("site/mosaic/fp-token.enc", "sealed " + n);
  await fs.writeFile("site/stray.txt", "never committed by the backfill");
  await fs.writeFile(process.env.BACKFILL_RESULT, JSON.stringify({ status: "done", added: 1, already: 0, failed: Number(process.env.FAILED || 0) }));
}
if (mode === "backfill-none") await fs.writeFile(process.env.BACKFILL_RESULT, JSON.stringify({ status: "done", added: 0, already: 3, failed: 0 }));
console.log("stand-in worker run " + n + " (" + mode + ")");
`;

async function scratch() {
  const d = await fs.mkdtemp(join(tmpdir(), "site-jobs-"));
  git(d, "init", "-q", "--bare", "-b", "main", "remote.git");
  git(d, "clone", "-q", join(d, "remote.git"), "seed");
  const seed = join(d, "seed");
  for (const c of [["user.name", "t"], ["user.email", "t@example.com"]]) git(seed, "config", ...c);
  await fs.mkdir(join(seed, "site"), { recursive: true });
  await fs.writeFile(join(seed, "site", "worker.mjs"), STANDIN);
  await fs.writeFile(join(seed, "site", "backfill.mjs"), STANDIN);
  await fs.writeFile(join(seed, "site", "gallery.json.enc"), "sealed gallery");
  git(seed, "add", "-A"); git(seed, "commit", "-qm", "seed"); git(seed, "push", "-q", "origin", "HEAD:main");
  git(d, "clone", "-q", join(d, "remote.git"), "job");
  git(d, "clone", "-q", join(d, "remote.git"), "other");
  for (const c of [["user.name", "o"], ["user.email", "o@example.com"]]) git(join(d, "other"), "config", ...c);
  return d;
}
function runJob(d, script, env) {
  const r = spawnSync("bash", ["-e", "-c", script], { cwd: join(d, "job"), encoding: "utf8", env: { ...process.env, RUN_COUNTER: join(d, "counter"), ...env } });
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}
const remoteFiles = (d) => git(d, "--git-dir", join(d, "remote.git"), "ls-tree", "-r", "--name-only", "main").split("\n");

test("the combined-view job with nothing to combine (its folder never existed) ends quietly", async () => {
  const d = await scratch();
  const r = runJob(d, MOSAIC, { STANDIN: "none" });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /nothing to commit/);
});

test("the combined-view job's output reaches the remote, and so does the picture job's", async () => {
  const d = await scratch();
  const r = runJob(d, MOSAIC, { STANDIN: "mosaic" });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /pushed/);
  assert.ok(remoteFiles(d).includes("site/mosaic/meta.json.enc"));
  const p = runJob(d, PHOTO, { STANDIN: "photo", ACTION: "add", ID: "abc", RUN_COUNTER: join(d, "counter2") });
  assert.equal(p.code, 0, p.out); assert.ok(remoteFiles(d).includes("site/photos/abc/x.enc"));
  assert.equal(git(d, "--git-dir", join(d, "remote.git"), "log", "-1", "--format=%s", "main"), "site: add abc");
});

test("a combined-view job whose push loses a race refreshes, runs again and pushes; the other job's commit survives", async () => {
  const d = await scratch();
  const r = runJob(d, MOSAIC, { STANDIN: "mosaic", RACE_ONCE: join(d, "other") });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /the push raced with another job; refreshing and making it again \(1\)/);
  assert.match(r.out, /stand-in worker run 2/);
  const files = remoteFiles(d);
  assert.ok(files.includes("site/mosaic/meta.json.enc") && files.includes("site/other.txt"), files.join(" "));
});

test("the combined-view job runs the worker ONLY in its combined-view mode, and commits only site/mosaic", async () => {
  const lines = WF.split("\n");
  const at = lines.findIndex((l) => l.trim() === "- name: Make the combined view on the current tip of main and commit; refresh and redo if the push races");
  const runAt = lines.findIndex((l, i) => i > at && /^\s+run: \|\s*$/.test(l));
  assert.ok(lines.slice(at, runAt).some((l) => l.trim() === "WORKER_ACTION: mosaic"), "the step's env sets WORKER_ACTION: mosaic");
  assert.ok(!/git add -A site\s*$/m.test(MOSAIC) && /git add -A site\/mosaic/.test(MOSAIC), "the job adds site/mosaic only");
  // a job that (wrongly) touched a picture folder still commits nothing but the combined view
  const d = await scratch();
  const r = runJob(d, MOSAIC, { STANDIN: "photo", ID: "zzz" });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /nothing to commit/);
  assert.ok(!remoteFiles(d).some((f) => f.startsWith("site/photos/")));
});

test("when the last picture goes, the combined view's committed folder is removed from the remote", async () => {
  const d = await scratch();
  assert.equal(runJob(d, MOSAIC, { STANDIN: "mosaic" }).code, 0);
  assert.ok(remoteFiles(d).includes("site/mosaic/meta.json.enc"));
  // the stand-in now writes nothing; the real worker removes the folder first, so the stand-in does too
  await fs.writeFile(join(d, "remove.mjs"), 'import { promises as fs } from "node:fs"; await fs.rm("site/mosaic", { recursive: true, force: true });');
  const script = MOSAIC.replace("node site/worker.mjs", `node ${join(d, "remove.mjs")}`);
  const r = runJob(d, script, { STANDIN: "none" });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /pushed/);
  assert.ok(!remoteFiles(d).some((f) => f.startsWith("site/mosaic/")), "the folder is gone from the remote");
});

test("the Apple backfill commits what it wrote (the pictures' folders, the list, the combined view) and nothing else; a race is redone", async () => {
  const lines = FP_WF.split("\n");
  const at = lines.findIndex((l) => l.trim() === `- name: ${FP_STEP}`);
  const runAt = lines.findIndex((l, i) => i > at && /^\s+run: \|\s*$/.test(l));
  const env = lines.slice(at, runAt).map((l) => l.trim());
  for (const e of ["SITE_PASSWORD: ${{ secrets.SITE_PASSWORD }}", "AXINOM_COM_KEY_ID: ${{ secrets.AXINOM_COM_KEY_ID }}", "AXINOM_COM_KEY: ${{ secrets.AXINOM_COM_KEY }}"]) assert.ok(env.includes(e), e);
  const on = FP_WF.slice(FP_WF.indexOf("\non:"), FP_WF.indexOf("\npermissions:"));
  assert.ok(/workflow_dispatch:/.test(on) && /schedule:/.test(on) && !/repository_dispatch|push:|pull_request/.test(on), "started by hand and weekly only, never by a page or a push: " + on);
  assert.match(FP_WF, /concurrency: \{ group: site-fairplay, cancel-in-progress: false \}/, "its own queue: never cancelled by a combined-view job");
  const d = await scratch();
  const r = runJob(d, BACKFILL, { STANDIN: "backfill", BACKFILL_RESULT: join(d, "result.json"), RACE_ONCE: join(d, "other") });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /the push raced with another job; refreshing and running again \(1\)/); assert.match(r.out, /stand-in worker run 2/); assert.match(r.out, /pushed/);
  const files = remoteFiles(d);
  for (const f of ["site/photos/p1/fp-token.enc", "site/gallery.json.enc", "site/mosaic/fp-token.enc", "site/other.txt"]) assert.ok(files.includes(f), f + " in " + files.join(" "));
  assert.ok(!files.includes("site/stray.txt"), "nothing outside what the backfill writes is committed");
});

test("the Apple backfill with pictures that failed: commits the rest, then fails visibly; with nothing to do it ends quietly", async () => {
  const d = await scratch();
  const r = runJob(d, BACKFILL, { STANDIN: "backfill", BACKFILL_RESULT: join(d, "result.json"), FAILED: "2" });
  assert.notEqual(r.code, 0, "the run is red");
  assert.match(r.out, /pushed/); assert.match(r.out, /2 form\(s\) not made or renewed/);
  assert.ok(remoteFiles(d).includes("site/photos/p1/fp-token.enc"), "what succeeded was committed first");
  const d2 = await scratch();
  const q = runJob(d2, BACKFILL, { STANDIN: "backfill-none", BACKFILL_RESULT: join(d2, "result.json") });
  assert.equal(q.code, 0, q.out); assert.match(q.out, /nothing to commit/);
});

test("the Apple backfill's WEEKLY run with the REAL site/backfill.mjs and no Axinom key yet: green, nothing committed", async () => {
  const d = await scratch(), other = join(d, "other");
  git(other, "pull", "-q", "origin", "main");
  // the real entry and everything it imports, committed to the scratch remote (the stand-in is replaced)
  for (const f of ["site/backfill.mjs", "site/crypto.js", "site/worker.mjs", "site/axinom.mjs", "site/config.json", "service/lib/pipeline.mjs", "service/lib/util.mjs", "service/lib/exif.mjs", "service/lib/packager-pin.mjs", "tools/playready-test-key.mjs"]) {
    await fs.mkdir(join(other, dirname(f)), { recursive: true });
    await fs.copyFile(join(REPO, f), join(other, f));
  }
  git(other, "add", "-A"); git(other, "commit", "-qm", "the real backfill"); git(other, "push", "-q", "origin", "HEAD:main");
  const before = git(d, "--git-dir", join(d, "remote.git"), "rev-parse", "main");
  const r = runJob(d, BACKFILL, { GITHUB_EVENT_NAME: "schedule", AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "", SITE_PASSWORD: "any password at all", BACKFILL_RESULT: join(d, "result.json") });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /the Axinom key is not set yet: nothing to renew/); assert.match(r.out, /nothing to commit/);
  assert.equal(git(d, "--git-dir", join(d, "remote.git"), "rev-parse", "main"), before, "nothing was pushed");
  // started by hand without the key, the same run is red and says why
  const h = runJob(d, BACKFILL, { GITHUB_EVENT_NAME: "workflow_dispatch", AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "", SITE_PASSWORD: "any password at all", BACKFILL_RESULT: join(d, "result2.json") });
  assert.notEqual(h.code, 0); assert.match(h.out, /::error title=Apple backfill::the Axinom communication key is not set/);
});
