// The GitHub Action's half of the test site. Runs on a repository_dispatch "photo" event whose payload
// carries the action (add | delete | mosaic), the picture id, and the picture key (hex; masked in the
// run's log by the workflow before this runs). WORKER_ACTION=mosaic (the workflow's second job) builds
// the combined view of every ready picture instead. For "add": fetch the encrypted blob the browser uploaded,
// decrypt it in memory, render and package it with the proof's pipeline (ffmpeg + shaka-packager,
// Widevine and PlayReady under fresh key ids), encrypt every output under the same key, and write them
// to site/photos/<id>/ with the gallery list (also encrypted). The workflow commits what this writes.
// The clear picture exists only in this runner's temporary folder and is deleted at the end.
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { importKeyHex, open, seal, sealText, openText, fromBase64, toHex, randomBytes } from "./crypto.js";
import { renderClip, packageClip, checkBoxes, newProtectionIds, probe } from "../service/lib/pipeline.mjs";
import { run as execFile } from "../service/lib/util.mjs";
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
  catch { log("WARNING: the gallery could not be opened with this key (the password changed?); starting a fresh list"); return { photos: [], fresh: true }; }
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

// THE COMBINED VIEW's layout: every ready picture in ONE video frame, so a device plays all of them
// through a single protected decoder and licence (phones limit how many protected videos can play at
// once). Equal cells in the majority orientation (3:4 or 4:3); each picture scaled to fit its cell
// with its own proportions (never stretched). The frame stays within 1080×1920, the portrait form of
// 1080p, which a device that plays one picture plays too. Of the grids that fit, the one whose cells
// come out largest on a phone screen held upright (about 400×700 points) wins; then the sharper one.
export const MOSAIC_MAX = { width: 1080, height: 1920 };
export const MOSAIC_VERSION = 1; // bumped when the layout or rendering changes, so an older combined view is remade
export function mosaicLayout(sizes, pad = 6) {
  const n = sizes.length;
  if (!n) throw new Error("no pictures to combine");
  const portrait = sizes.filter((s) => s.height >= s.width).length * 2 >= n;
  const [aw, ah] = portrait ? [3, 4] : [4, 3];
  const down2 = (x) => Math.floor(x / 2) * 2;
  let best = null;
  for (let cols = 1; cols <= n; cols++) {
    const rows = Math.ceil(n / cols);
    if (cols * rows - n >= cols) continue; // never a whole empty row
    const cw = down2(Math.min(MOSAIC_MAX.width / cols, (MOSAIC_MAX.height / rows) * aw / ah));
    const ch = down2(cw * ah / aw);
    if (cw < 2 * pad + 16 || ch < 2 * pad + 16) continue;
    const W = cols * cw, H = rows * ch;
    const onPhone = cw * Math.min(400 / W, 700 / H);
    if (!best || onPhone > best.onPhone + 1e-9 || (Math.abs(onPhone - best.onPhone) <= 1e-9 && cw > best.cw)) best = { cols, rows, cw, ch, W, H, onPhone };
  }
  const tiles = sizes.map((s, i) => {
    const col = i % best.cols, row = Math.floor(i / best.cols);
    const f = Math.min((best.cw - 2 * pad) / s.width, (best.ch - 2 * pad) / s.height);
    const near2 = (v) => Math.max(2, Math.round(v / 2) * 2); // nearest even size: floor-to-even skewed very thin pictures
    const w = Math.min(best.cw - 2, near2(s.width * f)), h = Math.min(best.ch - 2, near2(s.height * f));
    return { x: col * best.cw + down2((best.cw - w) / 2), y: row * best.ch + down2((best.ch - h) / 2), w, h };
  });
  return { width: best.W, height: best.H, cols: best.cols, rows: best.rows, cell: { width: best.cw, height: best.ch }, tiles };
}

// One picture's still, read back from its own PROTECTED output: the sealed PlayReady file is opened
// with the picture key and its Common Encryption is removed with the PlayReady test key for its key
// id (public test keys, see playready-test-key.mjs). Decode errors stop ffmpeg, so a wrong key fails
// here instead of producing noise.
async function stillFromOutput(tools, key, dir, kidHex, work, i) {
  const enc = join(work, `in-${i}.mp4`), still = join(work, `still-${i}.png`);
  await fs.writeFile(enc, await open(key, new Uint8Array(await fs.readFile(join(dir, "video-playready.mp4.enc")))));
  await execFile(tools.ffmpeg, ["-hide_banner", "-loglevel", "error", "-xerror", "-err_detect", "explode", "-y", "-decryption_key", derivePlayReadyTestKey(kidHex), "-i", enc, "-frames:v", "1", "-update", "1", still]);
  await fs.rm(enc, { force: true });
  return { still, ...(await probe(tools.ffprobe, still)) };
}

// Builds site/mosaic/: the combined view of every ready picture, packaged and sealed exactly like a
// single picture, plus its sealed layout (which picture is where, for tapping and for the list).
export async function buildMosaic({ siteDir, key, tools }) {
  const gallery = await readGallery(siteDir, key);
  const out = join(siteDir, "mosaic");
  const ready = gallery.fresh ? [] : gallery.photos.filter((x) => x.status === "ready").slice(0, MAX_PHOTOS);
  // a repeated request (the page asking while the job's own run is on its way) changes nothing: when the
  // combined view already holds exactly these pictures, in this order, with none left out, keep it
  try {
    const cur = JSON.parse(await openText(key, new Uint8Array(await fs.readFile(join(out, "meta.json.enc")))));
    if (ready.length && cur.version === MOSAIC_VERSION && !(cur.skipped || []).length && JSON.stringify(cur.ids) === JSON.stringify(ready.map((x) => x.id))) {
      log(`the combined view already holds these ${ready.length} picture(s): unchanged`);
      return { status: "current", count: ready.length };
    }
  } catch {}
  await fs.rm(out, { recursive: true, force: true }); // never a combined view from an older set left beside a new one
  if (gallery.fresh) { log("the gallery belongs to another key: no combined view"); return { status: "none", count: 0 }; }
  if (!ready.length) { log("no ready pictures: no combined view"); return { status: "none", count: 0 }; }
  const work = await fs.mkdtemp(join(tmpdir(), "site-mosaic-"));
  try {
    const used = [], skipped = [];
    for (const [i, x] of ready.entries()) {
      try {
        let guid = x.prKidGuid;
        if (!guid) guid = JSON.parse(await openText(key, new Uint8Array(await fs.readFile(join(siteDir, "photos", x.id, "meta.json.enc"))))).prKidGuid;
        const kidHex = String(guid || "").replace(/-/g, "").toLowerCase();
        used.push({ id: x.id, name: x.name, ...(await stillFromOutput(tools, key, join(siteDir, "photos", x.id), kidHex, work, i)) });
      } catch (e) {
        skipped.push({ id: x.id, name: x.name, reason: String(e.message || e).slice(0, 200) });
        log(`left out of the combined view: ${x.id} — ${String(e.message || e).slice(0, 200)}`);
      }
    }
    if (!used.length) throw new Error("no picture could be read back for the combined view");
    const layout = mosaicLayout(used);
    // a black frame, then each still scaled to its rectangle and laid on it
    const args = ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", `color=c=black:s=${layout.width}x${layout.height}:d=1`];
    for (const u of used) args.push("-i", u.still);
    const chain = []; let prev = "0:v";
    used.forEach((u, i) => {
      const t = layout.tiles[i];
      chain.push(`[${i + 1}:v]scale=${t.w}:${t.h}:flags=lanczos,setsar=1[s${i}]`, `[${prev}][s${i}]overlay=${t.x}:${t.y}[o${i}]`);
      prev = `o${i}`;
    });
    args.push("-filter_complex", chain.join(";"), "-map", `[${prev}]`, "-frames:v", "1", "-update", "1", join(work, "mosaic.png"));
    await execFile(tools.ffmpeg, args);
    const clip = await renderClip(tools, join(work, "mosaic.png"), join(work, "clip.mp4"), { maxSide: Math.max(MOSAIC_MAX.width, MOSAIC_MAX.height) });
    if (clip.width !== layout.width || clip.height !== layout.height) throw new Error(`the combined clip came out ${clip.width}x${clip.height}, expected ${layout.width}x${layout.height}`);
    const ids = newProtectionIds("mosaic-" + toHex(randomBytes(8)));
    await packageClip(tools.packager, work, { ...ids, prKey: derivePlayReadyTestKey(ids.prKid) });
    const wv = checkBoxes(await fs.readFile(join(work, "video-widevine.mp4")));
    const pr = checkBoxes(await fs.readFile(join(work, "video-playready.mp4")));
    if (!wv.ok || !pr.ok || !pr.kids.includes(ids.prKid)) throw new Error("a packaged file of the combined view is missing its sample-encryption boxes");
    await fs.mkdir(out, { recursive: true });
    for (const f of OUTPUTS) await fs.writeFile(join(out, f + ".enc"), await seal(key, new Uint8Array(await fs.readFile(join(work, f)))));
    const meta = { kind: "mosaic", version: MOSAIC_VERSION, width: layout.width, height: layout.height, cols: layout.cols, rows: layout.rows, prKidGuid: ids.prKidGuid, builtAt: new Date().toISOString(),
      ids: used.map((u) => u.id), tiles: used.map((u, i) => ({ id: u.id, name: u.name, ...layout.tiles[i] })), skipped };
    await fs.writeFile(join(out, "meta.json.enc"), await sealText(key, JSON.stringify(meta)));
    log(`combined view ready: ${used.length} picture(s) in ${layout.cols}x${layout.rows}, ${layout.width}x${layout.height}${skipped.length ? `, ${skipped.length} left out` : ""}`);
    return { status: "ready", count: used.length, skipped: skipped.length };
  } finally {
    await fs.rm(work, { recursive: true, force: true }); // the clear stills are gone with the runner
  }
}

export async function run({ payload, siteDir, repo, token, tools, action }) {
  const p = payload || {};
  const act = action || p.action;
  if (act !== "add" && act !== "delete" && act !== "mosaic") throw new Error(`unknown action ${JSON.stringify(act)}`);
  if (!/^[0-9a-f]{64}$/.test(String(p.key))) throw new Error("bad key");
  if (act === "mosaic") return buildMosaic({ siteDir, key: await importKeyHex(p.key), tools });
  if (!/^[0-9a-f]{24}$/.test(String(p.id))) throw new Error("bad picture id");
  const key = await importKeyHex(p.key);
  const gallery = await readGallery(siteDir, key);
  const photosDir = join(siteDir, "photos");
  const dir = join(photosDir, p.id);
  if (gallery.fresh) {
    // nothing under the old password can be opened any more: clear every old picture folder
    let old = []; try { old = await fs.readdir(photosDir); } catch {}
    for (const d of old) await fs.rm(join(photosDir, d), { recursive: true, force: true });
    delete gallery.fresh;
    log(`cleared ${old.length} picture folder(s) written under another key`);
  }

  if (act === "delete") {
    gallery.photos = gallery.photos.filter((x) => x.id !== p.id);
    gallery.updatedAt = new Date().toISOString(); // the page compares the combined view with this
    await fs.rm(dir, { recursive: true, force: true });
    await writeGallery(siteDir, key, gallery);
    log(`deleted ${p.id}`);
    return { status: "deleted" };
  }

  const name = String(p.name || "picture").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 120) || "picture";
  const entry = { id: p.id, name, bytes: Number(p.bytes) || 0, status: "failed", error: null, createdAt: new Date().toISOString() };
  gallery.photos = gallery.photos.filter((x) => x.id !== p.id);
  await fs.rm(dir, { recursive: true, force: true }); // a re-used id never leaves old files published beside a failure
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
  gallery.updatedAt = new Date().toISOString(); // the page compares the combined view with this
  await writeGallery(siteDir, key, gallery);
  return { status: entry.status, error: entry.error };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const event = JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
  const siteDir = process.env.SITE_DIR || fileURLToPath(new URL("./", import.meta.url));
  const tools = { ffmpeg: process.env.FFMPEG_BIN || "ffmpeg", ffprobe: process.env.FFPROBE_BIN || "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
  const r = await run({ payload: event.client_payload, siteDir, repo: process.env.GITHUB_REPOSITORY || "oneandroid-max/ccs-protected-still-proof", token: process.env.GITHUB_TOKEN, tools, action: process.env.WORKER_ACTION || undefined });
  console.log(`result: ${r.status}${r.error ? " — " + r.error : ""}${r.count !== undefined ? ` (${r.count} picture(s))` : ""}`);
}
