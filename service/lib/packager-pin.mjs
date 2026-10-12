// The one shaka-packager build the jobs may run: v3.9.3 for Linux x64, by its SHA-256 (the release's own file, the same
// pin as every download line that tools/check-workflow-links.mjs checks). Every run of it asks checkPackager first and
// then runs EXACTLY the path it returns, so whatever put the file there (a download, an image, a cache, a copy) and
// whatever the PATH or the working folder, the file checked is the file run, and a file that is not this build is refused
// before it is ever run: site/worker.mjs and site/backfill.mjs (as their jobs start; the combined view's job just before
// it first packages, after a view of other pictures is removed), tools/fairplay-card.mjs, the service (at start, and
// again before every photo), a workflow step (only through tools/run-packager.mjs: tools/check-workflow-links.mjs refuses
// any other way), and the tests (before any test runs it).
import { promises as fs, constants } from "node:fs";
import { createHash } from "node:crypto";
import { delimiter, resolve } from "node:path";

export const PACKAGER_SHA256 = "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6";

// The file a name stands for, as an absolute path: a name with a slash from the current folder; a name without one on
// the PATH the way the shell looks it up (in order, an empty entry meaning the current folder, the first executable FILE).
async function locate(bin) {
  if (/[\\/]/.test(bin)) return resolve(bin);
  for (const dir of String(process.env.PATH || "").split(delimiter)) {
    const p = resolve(dir || ".", bin);
    try { if (!(await fs.stat(p)).isFile()) continue; await fs.access(p, constants.X_OK); return p; } catch {}
  }
  return null;
}

// Resolves to the packager's absolute path when its bytes are the pinned build (the caller runs that path and no other);
// rejects with the reason otherwise. Never remembered (about 10 MB to hash): what passes is the file as it is when asked.
// A refusal carries `packager: true`, so a job can name it as the packager's on its run's page.
export async function checkPackager(bin) {
  const refuse = (message) => Object.assign(new Error(message), { packager: true });
  const path = await locate(bin);
  if (!path) throw refuse(`the packager "${bin}" was not found`);
  let bytes;
  try { bytes = await fs.readFile(path); } catch (e) { throw refuse(e.code === "ENOENT" ? `the packager "${bin}" was not found` : `the packager at ${path} could not be read (${e.code || e.message})`); }
  const sha = createHash("sha256").update(bytes).digest("hex");
  if (sha !== PACKAGER_SHA256) throw refuse(`the packager at ${path} is not the pinned shaka-packager v3.9.3 (sha256 ${sha.slice(0, 16)}…, pinned ${PACKAGER_SHA256.slice(0, 16)}…): refused`);
  return path;
}
