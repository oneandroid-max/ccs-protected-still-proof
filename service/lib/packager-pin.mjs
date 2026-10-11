// The one shaka-packager build the jobs may run: v3.9.3 for Linux x64, by its SHA-256 (the release's own file, the same
// pin as every download line that tools/check-workflow-links.mjs checks). Every program of ours that runs the packager
// on a picture or the card asks checkPackager first (site/worker.mjs, site/backfill.mjs, tools/fairplay-card.mjs, the
// service's pipeline), so whatever put the file there (a download, an image, a cache, a copy), a file that is not this
// build is refused before it touches anything. The jobs that call the packager from a shell instead (drm-package.yml,
// drm-card.yml) check this same SHA-256 on the line after the download, and again first in any later step that runs it.
import { promises as fs, constants } from "node:fs";
import { createHash } from "node:crypto";
import { delimiter, isAbsolute, join, resolve } from "node:path";

export const PACKAGER_SHA256 = "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6";

// A name with no slash is looked up on the PATH, as the shell would run it.
async function locate(bin) {
  if (/[\\/]/.test(bin)) return isAbsolute(bin) ? bin : resolve(bin);
  for (const dir of String(process.env.PATH || "").split(delimiter).filter(Boolean)) {
    const p = join(dir, bin);
    try { await fs.access(p, constants.X_OK); return p; } catch {}
  }
  return null;
}

// Resolves to the packager's path when its bytes are the pinned build; rejects with the reason otherwise. Asked every
// time and never remembered (about 10 MB to hash): what passes is the file as it is at that moment.
export async function checkPackager(bin) {
  const path = await locate(bin);
  if (!path) throw new Error(`the packager "${bin}" was not found`);
  let bytes;
  try { bytes = await fs.readFile(path); } catch (e) { throw new Error(e.code === "ENOENT" ? `the packager "${bin}" was not found` : `the packager at ${path} could not be read (${e.code || e.message})`); }
  const sha = createHash("sha256").update(bytes).digest("hex");
  if (sha !== PACKAGER_SHA256) throw new Error(`the packager at ${path} is not the pinned shaka-packager v3.9.3 (sha256 ${sha.slice(0, 16)}…, pinned ${PACKAGER_SHA256.slice(0, 16)}…): refused`);
  return path;
}
