// Runs the two job scripts of site-photos.yml exactly as written (extracted from the workflow file) in
// a scratch repository with a bare remote, with a stand-in site/worker.mjs, so the commit-and-push loop
// is proven before GitHub runs it: a combined-view job with nothing to combine must end quietly (it
// once failed on `git add` of a folder that never existed), a job's output must reach the remote, and a
// job whose push loses a race must refresh, run again and push. GitHub's own wiring (if:, needs:,
// concurrency) can only be proven by GitHub; these are the scripts it runs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const WF = await fs.readFile(join(REPO, ".github", "workflows", "site-photos.yml"), "utf8");

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
