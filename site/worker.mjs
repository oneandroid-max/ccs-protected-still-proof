// The GitHub Action's half of the test site. Runs on a repository_dispatch "photo" event whose payload
// carries the action (add | delete), the picture id, and the password-derived key (hex; masked in the
// run's log by the workflow before this runs). For "add": fetch the encrypted blob the browser uploaded,
// decrypt it in memory, render and package it with the proof's pipeline (ffmpeg + shaka-packager,
// Widevine and PlayReady under fresh key ids), encrypt every output under the same key, and write them
// to site/photos/<id>/ with the gallery list (also encrypted). The workflow commits what this writes.
// The clear picture exists only in this runner's temporary folder and is deleted at the end.
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { importKeyHex, open, seal, sealText, openText, fromBase64 } from "./crypto.js";
import { renderClip, packageClip, checkBoxes, newProtectionIds } from "../service/lib/pipeline.mjs";
import { jpegOrientation } from "../service/lib/exif.mjs";
import { sniffImage } from "../service/lib/util.mjs";
import { derivePlayReadyTestKey } from "../tools/playready-test-key.mjs";

export const MAX_PHOTOS = 10;
const OUTPUTS = ["widevine.mpd", "video-widevine.mp4", "playready.mpd", "video-playready.mp4"];
const log = (m) => console.log(`${new Date().toISOString()} ${m}`);

export async function readGallery(siteDir, key) {
  let sealed;
  try { sealed = new Uint8Array(await fs.readFile(join(siteDir, "gallery.json.enc"))); } catch { return { photos: [] }; }
  try { return JSON.parse(await openText(key, sealed)); }
  catch { log("WARNING: the gallery could not be opened with this key (the password changed?); starting a fresh list"); return { photos: [] }; }
}
async function writeGallery(siteDir, key, g) {
  await fs.writeFile(join(siteDir, "gallery.json.enc"), await sealText(key, JSON.stringify(g)));
}

async function fetchBlob(repo, sha, token) {
  if (process.env.WORKER_BLOB_FILE) return new Uint8Array(await fs.readFile(process.env.WORKER_BLOB_FILE)); // tests
  const r = await fetch(`https://api.github.com/repos/${repo}/git/blobs/${sha}`, { headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" } });
  if (!r.ok) throw new Error(`the uploaded blob could not be fetched (${r.status})`);
  const j = await r.json();
  if (j.encoding !== "base64") throw new Error(`unexpected blob encoding ${j.encoding}`);
  return fromBase64(j.content.replace(/\n/g, ""));
}

export async function run({ payload, siteDir, repo, token, tools }) {
  const p = payload || {};
  if (p.action !== "add" && p.action !== "delete") throw new Error(`unknown action ${JSON.stringify(p.action)}`);
  if (!/^[0-9a-f]{24}$/.test(String(p.id))) throw new Error("bad picture id");
  if (!/^[0-9a-f]{64}$/.test(String(p.key))) throw new Error("bad key");
  const key = await importKeyHex(p.key);
  const gallery = await readGallery(siteDir, key);
  const photosDir = join(siteDir, "photos");
  const dir = join(photosDir, p.id);

  if (p.action === "delete") {
    gallery.photos = gallery.photos.filter((x) => x.id !== p.id);
    await fs.rm(dir, { recursive: true, force: true });
    await writeGallery(siteDir, key, gallery);
    log(`deleted ${p.id}`);
    return { status: "deleted" };
  }

  const name = String(p.name || "picture").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 120) || "picture";
  const entry = { id: p.id, name, bytes: Number(p.bytes) || 0, status: "failed", error: null, createdAt: new Date().toISOString() };
  gallery.photos = gallery.photos.filter((x) => x.id !== p.id);
  const work = await fs.mkdtemp(join(tmpdir(), "site-photo-"));
  try {
    // only prepared pictures take a slot; a failed entry stays visible until deleted but blocks nothing
    if (gallery.photos.filter((x) => x.status === "ready").length >= MAX_PHOTOS) throw new Error(`the gallery holds at most ${MAX_PHOTOS} pictures; delete one first`);
    if (!/^[0-9a-f]{40}$/.test(String(p.blobSha))) throw new Error("bad upload reference");
    const bytes = await open(key, await fetchBlob(repo, p.blobSha, token));
    const kind = sniffImage(Buffer.from(bytes));
    if (!kind) throw new Error("only JPEG, PNG or WebP pictures are accepted");
    const original = join(work, `original.${kind.ext}`);
    await fs.writeFile(original, bytes);
    const orientation = kind.type === "image/jpeg" ? jpegOrientation(Buffer.from(bytes)) : 1;
    const clip = await renderClip(tools, original, join(work, "clip.mp4"), { orientation });
    const ids = newProtectionIds(p.id);
    await packageClip(tools.packager, work, { ...ids, prKey: derivePlayReadyTestKey(ids.prKid) });
    const wv = checkBoxes(await fs.readFile(join(work, "video-widevine.mp4")));
    const pr = checkBoxes(await fs.readFile(join(work, "video-playready.mp4")));
    if (!wv.ok || !pr.ok || !pr.kids.includes(ids.prKid)) throw new Error("a packaged file is missing its sample-encryption boxes");
    await fs.rm(dir, { recursive: true, force: true });
    await fs.mkdir(dir, { recursive: true });
    for (const f of OUTPUTS) await fs.writeFile(join(dir, f + ".enc"), await seal(key, new Uint8Array(await fs.readFile(join(work, f)))));
    Object.assign(entry, { status: "ready", width: clip.width, height: clip.height, readyAt: new Date().toISOString(), prKidGuid: ids.prKidGuid });
    await fs.writeFile(join(dir, "meta.json.enc"), await sealText(key, JSON.stringify({ id: p.id, name, width: clip.width, height: clip.height, prKidGuid: ids.prKidGuid, readyAt: entry.readyAt })));
    log(`ready ${p.id} ${clip.width}x${clip.height}`);
  } catch (e) {
    entry.error = String(e.message || e).slice(0, 400);
    log(`failed ${p.id}: ${entry.error}`);
  } finally {
    await fs.rm(work, { recursive: true, force: true }); // the clear picture is gone with the runner
  }
  gallery.photos.push(entry);
  await writeGallery(siteDir, key, gallery);
  return { status: entry.status, error: entry.error };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const event = JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
  const siteDir = process.env.SITE_DIR || fileURLToPath(new URL("./", import.meta.url));
  const tools = { ffmpeg: process.env.FFMPEG_BIN || "ffmpeg", ffprobe: process.env.FFPROBE_BIN || "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
  const r = await run({ payload: event.client_payload, siteDir, repo: process.env.GITHUB_REPOSITORY || "oneandroid-max/ccs-protected-still-proof", token: process.env.GITHUB_TOKEN, tools });
  console.log(`result: ${r.status}${r.error ? " — " + r.error : ""}`);
}
