// The GitHub Action's half of the test site. Runs on a repository_dispatch "photo" event whose payload
// carries the action (add | delete | mosaic), the picture id, and the picture key (hex; masked in the
// run's log by the workflow before this runs). WORKER_ACTION=mosaic (the workflow's second job) builds
// the combined view of every ready picture instead. For "add": fetch the encrypted blob the browser uploaded,
// decrypt it in memory, render and package it with the proof's pipeline (ffmpeg + shaka-packager,
// Widevine and PlayReady under fresh key ids), encrypt every output under the same key, and write them
// to site/photos/<id>/ with the gallery list (also encrypted). The workflow commits what this writes.
// The clear picture exists only in this runner's temporary folder and is deleted at the end.
// APPLE: when the Axinom evaluation account's communication key is set (AXINOM_COM_KEY_ID and
// AXINOM_COM_KEY), every output also gets Apple's FairPlay form: a folder fp-<8 hex>/ with the HLS files
// ('cbcs', the output's own key) and its licence token sealed under the picture key (token.enc). The
// "fairplay" action (site/backfill.mjs only, never a page's request) gives that form to pictures
// prepared before it existed or whose token is running out, and remakes the combined view.
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { importKeyHex, open, seal, sealText, openText, fromBase64, toHex, randomBytes } from "./crypto.js";
import { renderClip, packageClip, checkBoxes, newProtectionIds, probe, packageFairPlay, checkFairPlay, verifyFairPlayBytes } from "../service/lib/pipeline.mjs";
import { readCommunicationKey, readAxinomSettings, mintToken, newFairPlayIds, comKeyCheck, checkKeyWithAxinom, AXINOM_FAIRPLAY_LICENSE } from "./axinom.mjs";
import { run as execFile } from "../service/lib/util.mjs";
import { checkPackager } from "../service/lib/packager-pin.mjs";
import { jpegOrientation } from "../service/lib/exif.mjs";
import { sniffImage } from "../service/lib/util.mjs";
import { derivePlayReadyTestKey } from "../tools/playready-test-key.mjs";

export const MAX_PHOTOS = 10;
const OUTPUTS = ["widevine.mpd", "video-widevine.mp4", "playready.mpd", "video-playready.mp4"];
const log = (m) => console.log(`${new Date().toISOString()} ${m}`);
const FP_FILES = ["master.m3u8", "video.m3u8", "video.mp4", "token.enc"];
export const TOKEN_RENEW_DAYS = 14; // a token with less than this left is renewed (the weekly backfill run does it)

// Whether Axinom accepts our key, asked at most once per run and only when an Apple form is about to be made
// (checkKeyWithAxinom: a token for a throwaway key). THE RULE: a form is never deleted or replaced unless Axinom
// has accepted the key in that run, except where its pictures themselves go (the owner deletes or re-sends a
// picture, the password changes, a picture the combined view draws is deleted or a new one joins it). When Axinom
// refuses the key, or cannot be asked, the backfill stops before replacing anything and the combined view is kept
// as it is. A NEW form (a new picture, a view of other pictures) replaces nothing, so it is made unless Axinom
// refuses the key or the key cannot be used at all; one made without Axinom's acceptance is recorded as such, and
// renewed once Axinom accepts the key (fairPlayCurrent).
export function keyGate(com, checkKey = checkKeyWithAxinom) {
  let answer = null;
  return async () => {
    if (!answer) { try { answer = await checkKey(com); } catch (e) { answer = { accepted: false, reached: false, unusable: true, status: 0, message: String(e.message || e).slice(0, 200) }; } }
    return answer;
  };
}
const mayReplace = (answer) => answer.accepted;
const mayMake = (answer) => answer.accepted || (!answer.reached && !answer.unusable); // a refusal, or a key that cannot be used, stops a new form
const refusal = (com, answer) => answer.unusable ? `our key (key id ${com.id}) could not be used: ${answer.message}`
  : answer.reached ? `Axinom does not accept our key (key id ${com.id}): ${answer.message}` : `Axinom could not be asked about our key (key id ${com.id}): ${answer.message}`;
// the same, in plain words for the page (a request answered by keeping the combined view says why); none: no key set
const cause = (answer) => { const m = String(answer && answer.message || "").slice(0, 200);
  return !answer ? "no Axinom key is set" : answer.unusable ? `our Axinom key could not be used (${m})`
    : answer.reached ? `Axinom did not accept our key (Axinom: ${m})` : `Axinom could not be asked about our key (${m})`; };

// Apple's FairPlay form of the clip in `work` (work/clip.mp4), checked, then written to `outDir` as ONE
// folder, fp-<8 hex>/: the HLS files as they are (their samples are encrypted under a key that only the
// token carries, encrypted for Axinom) and the licence token sealed under the picture key (token.enc).
// The folder is assembled under a temporary name and renamed into place, so it is complete or absent;
// the meta's pointer to it swaps files and token together. A fresh name each time means a browser holding
// an older copy in its cache (Pages caches for ten minutes) never pairs old video with a new licence.
// Older forms are removed by the caller, once the meta points to the new one. Throws when the packaged
// form fails its check: nothing is written then. Returns what the meta records, the account's licence
// address with it (the page sends the token there and nowhere else).
async function addFairPlay({ tools, work, outDir, key, com, verified }) {
  const ids = newFairPlayIds();
  await fs.rm(join(work, "fp"), { recursive: true, force: true });
  await packageFairPlay(tools.packager, work, ids);
  const check = checkFairPlay(await fs.readFile(join(work, "fp", "video.m3u8"), "utf8"), await fs.readFile(join(work, "fp", "video.mp4")), ids);
  if (!check.ok) throw new Error("the FairPlay form failed its check: " + check.problems.join("; "));
  // and by its bytes: what the records call encrypted is, and it decrypts back to exactly the clip
  const bytes = await verifyFairPlayBytes(tools.packager, work, ids);
  if (!bytes.ok) throw new Error("the FairPlay form failed its byte check: " + bytes.problems.join("; "));
  const token = mintToken(com, ids.kid, ids.key);
  const expires = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")).expiration_date;
  await fs.writeFile(join(work, "fp", "token.enc"), await sealText(key, token));
  const folder = "fp-" + toHex(randomBytes(4)), part = join(outDir, folder + ".part");
  await fs.rm(part, { recursive: true, force: true });
  try {
    await fs.mkdir(part, { recursive: true });
    for (const f of FP_FILES) await fs.copyFile(join(work, "fp", f), join(part, f));
    await fs.rename(part, join(outDir, folder));
  } catch (e) { await fs.rm(part, { recursive: true, force: true }).catch(() => {}); throw e; } // a half-copied form is never left to be published
  return { keyUri: ids.keyUri, master: `${folder}/master.m3u8`, comKeyId: com.id, comKeyCheck: comKeyCheck(com), verified: !!verified, expires, license: com.license || AXINOM_FAIRPLAY_LICENSE };
}
// Removes every Apple form in `dir` but the one the meta now records (and anything half-made).
async function removeOtherFairPlay(dir, fairplay) {
  const keep = fairplay && String(fairplay.master).split("/")[0];
  let names = []; try { names = await fs.readdir(dir); } catch {}
  for (const d of names) if (/^fp-[0-9a-f]{8}(\.part)?$/.test(d) && d !== keep) await fs.rm(join(dir, d), { recursive: true, force: true });
}
// Whether a recorded Apple form is there and still good: all four files, its token made with THIS Axinom
// key (one made with another cannot be licensed: the same key id with a corrected key value counts as
// another, by the key's check value) for THIS licence address, made with Axinom's acceptance of the key (one
// made while Axinom could not be asked is renewed once it accepts), and more than TOKEN_RENEW_DAYS left on it.
export async function fairPlayCurrent(dir, fairplay, com, now = Date.now()) {
  if (!fairplay || !/^fp-[0-9a-f]{8}\/master\.m3u8$/.test(String(fairplay.master))) return false;
  const folder = fairplay.master.split("/")[0];
  try { for (const f of FP_FILES) await fs.access(join(dir, folder, f)); } catch { return false; }
  if (com && String(fairplay.comKeyId || "").toLowerCase() !== com.id.toLowerCase()) return false;
  if (com && fairplay.comKeyCheck !== comKeyCheck(com)) return false;
  if (com && fairplay.verified === false) return false;
  if (com && (fairplay.license || AXINOM_FAIRPLAY_LICENSE) !== (com.license || AXINOM_FAIRPLAY_LICENSE)) return false;
  return Date.parse(fairplay.expires) > now + TOKEN_RENEW_DAYS * 86400000;
}

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

// Every answer to a page's request carries the request's id into the view's record (the last ten kept), so the page
// that asked knows its own answer has come, whatever the answer was, and no other change to the record is taken for it.
const withAnswer = (prev, ask) => (ask ? [ask] : []).concat(Array.isArray(prev) ? prev.filter((x) => x !== ask) : []).slice(0, 10);
// A form whose token is past its own expiry date (our own record of it) can license nothing: it is not a working form.
const formAlive = (fp) => !!(fp && fp.master) && !(Date.parse(fp.expires) <= Date.now());

// Builds site/mosaic/: the combined view of every ready picture, packaged and sealed exactly like a
// single picture, plus its sealed layout (which picture is where, for tapping and for the list).
export async function buildMosaic({ siteDir, key, tools, com = null, keyOk = com ? keyGate(com) : null, ask = null }) {
  const gallery = await readGallery(siteDir, key);
  const out = join(siteDir, "mosaic"), next = join(siteDir, ".mosaic-next");
  const ready = gallery.fresh ? [] : gallery.photos.filter((x) => x.status === "ready").slice(0, MAX_PHOTOS);
  let cur = null;
  try { cur = JSON.parse(await openText(key, new Uint8Array(await fs.readFile(join(out, "meta.json.enc"))))); } catch {}
  // the view's pictures, counted as the page counts them (site/app.js, mosaicCurrent: the pictures it draws and those
  // it left out), but from the list itself: the SAME pictures when every picture it draws is still ready and every
  // ready picture is drawn or left out. Two differences, both on purpose: a left-out picture since deleted is only a
  // stale entry in its record, dropped there with nothing rebuilt (the page counts the view out of date until then);
  // and the page counts only the pictures it has seen published, the job every ready one.
  const readyIds = ready.map((x) => x.id);
  const drawn = cur && Array.isArray(cur.ids) ? cur.ids : [], leftOut = cur ? (cur.skipped || []).map((x) => x.id) : [];
  const samePictures = !!cur && !!ready.length && drawn.every((id) => readyIds.includes(id)) && readyIds.every((id) => drawn.includes(id) || leftOut.includes(id));
  const writeCur = async () => { cur.answered = withAnswer(cur.answered, ask); await fs.writeFile(join(out, "meta.json.enc"), await sealText(key, JSON.stringify(cur))); };
  let written = false;
  if (samePictures && leftOut.some((id) => !readyIds.includes(id))) {
    cur.skipped = (cur.skipped || []).filter((x) => readyIds.includes(x.id));
    await writeCur(); written = true;
    log("the combined view's record no longer names left-out pictures that were since deleted");
  }
  const hasForm = !!(cur && cur.fairplay && cur.fairplay.master), alive = !!cur && formAlive(cur.fairplay);
  const upToDate = samePictures && cur.version === MOSAIC_VERSION && !(cur.skipped || []).length && JSON.stringify(drawn) === JSON.stringify(readyIds); // in the list's order
  // a request answered by keeping the view as it is: the answer and its reason written into its record, so the page
  // can say so; a rebuild writes a new record
  const keep = async (why, fairplay) => {
    cur.kept = { at: new Date().toISOString(), why: why.slice(0, 400) };
    await writeCur();
    log(`the combined view kept as it is${hasForm ? ", with its current Apple form" : " (it has no Apple form)"}: ${why}`);
    return { status: "current", count: drawn.length, fairplay };
  };
  // a repeated request (the page asking while the job's own run is on its way) changes nothing: when the
  // combined view already holds exactly these pictures, none left out, and a good form, keep it
  if (upToDate && (!com || await fairPlayCurrent(out, cur.fairplay, com))) {
    if (ask && !written) await writeCur(); // the answer to the page that asked
    log(`the combined view already holds these ${ready.length} picture(s): unchanged`);
    return { status: "current", count: drawn.length };
  }
  // the same pictures, only the Apple form to make or renew: that form alone, from the view's own output, the old
  // one kept unless the new one is made: a renewal that fails keeps the view and its form as they are. Only when the
  // view's own output cannot be read back is it rebuilt, below (where a view with a working form is rebuilt only once
  // Axinom accepts the key).
  if (upToDate) {
    try { const r = await refreshMosaicFairPlay({ siteDir, key, tools, com, keyOk, ask }); log(`the combined view's Apple form: ${r}`); return { status: "current", count: drawn.length, fairplay: r }; }
    catch (e) {
      if (e.gate) return keep(`${e.replacing ? "its Apple form was not renewed" : "no Apple form was made for it"}: ${cause(e.answer)}`, "kept");
      if (!e.unreadable) return keep(`its new Apple form could not be made (${String(e.message || e).slice(0, 200)}); the current one stays`, "failed");
      log(`the combined view's own output could not be read back for its Apple form (${String(e.message || e).slice(0, 200)}): a rebuild`);
    }
  }
  // THE RULE on the view: a rebuild of the SAME pictures (a left-out one tried again, a new layout version, its
  // own output unreadable) would delete its form, so a view with a working form (made with Axinom's acceptance or not;
  // one whose token has expired is not working) is rebuilt only once Axinom accepts the key (without a usable key,
  // never); otherwise it is kept as it is. A view of OTHER pictures (one added, or one it draws deleted) is rebuilt
  // whatever Axinom says: its old content, and its form, must go.
  if (samePictures && alive) {
    const answer = com ? await keyOk() : null;
    if (!answer || !mayReplace(answer)) return keep(`rebuilding it would remove its Apple form, and ${cause(answer)}`, "kept");
  }
  // A rebuild is made beside the old view (.mosaic-next) and swapped in only once complete. A view of OTHER pictures
  // goes first, whatever happens next (its content must not stay on the site). For the SAME pictures the old view
  // stays until the swap, and a new view that came out without an Apple form while the old one has a working form is
  // not swapped in at all: the old view is kept whole and the failure said.
  await fs.rm(next, { recursive: true, force: true });
  if (!samePictures) await fs.rm(out, { recursive: true, force: true });
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
    await fs.mkdir(next, { recursive: true });
    for (const f of OUTPUTS) await fs.writeFile(join(next, f + ".enc"), await seal(key, new Uint8Array(await fs.readFile(join(work, f)))));
    let fairplay = null, noForm = "";
    if (com) { // the new view's own form (its old one, if any, goes with the old view)
      try {
        const answer = await keyOk();
        if (!mayMake(answer)) { noForm = refusal(com, answer); log(`combined view: no FairPlay form — ${noForm}`); }
        else { if (!answer.accepted) log(`combined view: ${refusal(com, answer)}; its form is made all the same (it replaces nothing)`); fairplay = await addFairPlay({ tools, work, outDir: next, key, com, verified: answer.accepted }); log("combined view: FairPlay form added"); }
      } catch (e) { noForm = String(e.message || e).slice(0, 300); log(`combined view: no FairPlay form — ${noForm}`); }
    }
    if (samePictures && alive && !fairplay) {
      await fs.rm(next, { recursive: true, force: true });
      return keep(`its rebuild made no Apple form (${noForm.slice(0, 200) || "no Axinom key"}); the current view and its form stay`, "failed");
    }
    const meta = { kind: "mosaic", version: MOSAIC_VERSION, width: layout.width, height: layout.height, cols: layout.cols, rows: layout.rows, prKidGuid: ids.prKidGuid, builtAt: new Date().toISOString(),
      ids: used.map((u) => u.id), tiles: used.map((u, i) => ({ id: u.id, name: u.name, ...layout.tiles[i] })), skipped, fairplay, answered: withAnswer(cur && cur.answered, ask) };
    await fs.writeFile(join(next, "meta.json.enc"), await sealText(key, JSON.stringify(meta)));
    await fs.rm(out, { recursive: true, force: true });
    await fs.rename(next, out);
    log(`combined view ready: ${used.length} picture(s) in ${layout.cols}x${layout.rows}, ${layout.width}x${layout.height}${skipped.length ? `, ${skipped.length} left out` : ""}`);
    return { status: "ready", count: used.length, skipped: skipped.length, fairplay: !!fairplay };
  } catch (e) {
    await fs.rm(next, { recursive: true, force: true }); // nothing half-made is left beside the view
    throw e;
  } finally {
    await fs.rm(work, { recursive: true, force: true }); // the clear stills are gone with the runner
  }
}

// The combined view's Apple form renewed from the view's OWN protected output (its still read back the way
// a picture's is), so a token running out never needs the whole view rebuilt (a rebuild needs Google's key
// server for its Widevine form). "current" when its form is good, "renewed", or "none" without a view.
async function refreshMosaicFairPlay({ siteDir, key, tools, com, keyOk, ask = null }) {
  const out = join(siteDir, "mosaic"), metaPath = join(out, "meta.json.enc");
  let meta; try { meta = JSON.parse(await openText(key, new Uint8Array(await fs.readFile(metaPath)))); } catch { return "none"; }
  if (await fairPlayCurrent(out, meta.fairplay, com)) return "current";
  const answer = await keyOk(), replacing = formAlive(meta.fairplay); // an expired form is replaced as if there were none
  if (!(replacing ? mayReplace(answer) : mayMake(answer))) throw Object.assign(new Error(refusal(com, answer) + "; the combined view's Apple form was left as it was"), { gate: true, answer, replacing });
  const work = await fs.mkdtemp(join(tmpdir(), "site-fp-mosaic-"));
  try {
    let s; // the view's own output unreadable is the one failure a rebuild can mend; any other (a program that could not
    // be started included) leaves the view as it is
    try { s = await stillFromOutput(tools, key, out, String(meta.prKidGuid || "").replace(/-/g, "").toLowerCase(), work, 0); }
    catch (e) { throw Object.assign(new Error(String(e.message || e)), { unreadable: !e.notRun }); }
    await renderClip(tools, s.still, join(work, "clip.mp4"), { maxSide: Math.max(MOSAIC_MAX.width, MOSAIC_MAX.height) });
    meta.fairplay = await addFairPlay({ tools, work, outDir: out, key, com, verified: answer.accepted });
    delete meta.kept; // a note that the view was kept is history once its form is renewed
    meta.answered = withAnswer(meta.answered, ask);
    await fs.writeFile(metaPath, await sealText(key, JSON.stringify(meta)));
    try { await removeOtherFairPlay(out, meta.fairplay); } // only now: the meta points to the new form; a leftover is
    catch (e) { log(`the combined view's old Apple form was not removed (${e.message}); the next renewal removes it`); } // removed next time
    return "renewed";
  } finally { await fs.rm(work, { recursive: true, force: true }); }
}

// Gives Apple's FairPlay form to every ready picture that lacks a good one (none yet, made with another
// Axinom key, or its token running out), from the picture's own protected output (its still, read back as
// the combined view reads it, made into a clip again), then remakes the combined view when it needs the
// same. A picture that cannot be read back is reported, not hidden.
export async function backfillFairPlay({ siteDir, key, tools, com, keyOk = com ? keyGate(com) : null }) {
  if (!com) throw new Error("the Axinom communication key is not set: nothing to add");
  const gallery = await readGallery(siteDir, key);
  if (gallery.fresh) return { status: "none", added: 0, failed: 0 };
  const ready = gallery.photos.filter((x) => x.status === "ready");
  let added = 0, failed = 0, already = 0; const addedIds = [];
  for (const [i, x] of ready.entries()) {
    const dir = join(siteDir, "photos", x.id);
    const metaPath = join(dir, "meta.json.enc");
    let meta;
    try { meta = JSON.parse(await openText(key, new Uint8Array(await fs.readFile(metaPath)))); }
    catch (e) { failed++; log(`FairPlay form NOT added: ${x.id} — its meta could not be read (${String(e.message || e).slice(0, 120)})`); continue; }
    if (await fairPlayCurrent(dir, meta.fairplay, com)) { already++; continue; }
    const answer = await keyOk(); // before the first form is made or replaced: a refusal, or Axinom out of reach, stops the whole run here
    if (!mayReplace(answer)) throw new Error(refusal(com, answer) + "; no Apple form was made or replaced");
    const work = await fs.mkdtemp(join(tmpdir(), "site-fp-"));
    try {
      const kidHex = String(x.prKidGuid || meta.prKidGuid || "").replace(/-/g, "").toLowerCase();
      const s = await stillFromOutput(tools, key, dir, kidHex, work, i);
      await renderClip(tools, s.still, join(work, "clip.mp4"));
      meta.fairplay = await addFairPlay({ tools, work, outDir: dir, key, com, verified: true });
      await fs.writeFile(metaPath, await sealText(key, JSON.stringify(meta)));
      await removeOtherFairPlay(dir, meta.fairplay); // only now: the meta points to the new form
      added++; addedIds.push(x.id); log(`FairPlay form added: ${x.id}`);
    } catch (e) { failed++; log(`FairPlay form NOT added: ${x.id} — ${String(e.message || e).slice(0, 300)}`); }
    finally { await fs.rm(work, { recursive: true, force: true }); }
  }
  if (addedIds.length) { // the list records it too (its updatedAt is left alone: no picture was added or removed)
    for (const x of gallery.photos) if (addedIds.includes(x.id)) x.fairplay = true;
    await writeGallery(siteDir, key, gallery);
  }
  // the combined view: its Apple form renewed from its own output when it needs it (no weekly rebuild, so no
  // new copies in the history while it is good); made, with its form, when there is none yet; a failure
  // here is counted, and never loses the pictures' renewals above (the workflow commits them first)
  let mosaic;
  try {
    mosaic = await refreshMosaicFairPlay({ siteDir, key, tools, com, keyOk });
    if (mosaic === "none" && ready.length) {
      const b = await buildMosaic({ siteDir, key, tools, com, keyOk });
      mosaic = b.status;
      if (b.status === "ready" && !b.fairplay) { failed++; mosaic = "ready without its Apple form"; log("the combined view was made without its Apple form (see above)"); }
    }
  } catch (e) { failed++; mosaic = "failed"; log(`the combined view's Apple form NOT renewed — ${String(e.message || e).slice(0, 300)}`); }
  log(`FairPlay backfill: ${added} added, ${already} already had it, ${failed} failed; combined view ${mosaic}`);
  return { status: failed ? "partial" : "done", added, already, failed, mosaic, count: ready.length };
}

export async function run({ payload, siteDir, repo, token, tools, action, com = null, checkKey = checkKeyWithAxinom }) {
  const p = payload || {};
  const act = action || p.action;
  if (act !== "add" && act !== "delete" && act !== "mosaic" && act !== "fairplay") throw new Error(`unknown action ${JSON.stringify(act)}`);
  // the backfill has its own workflow and queue: a page's request (the payload) can never start it
  if (act === "fairplay" && action !== "fairplay") throw new Error(`unknown action ${JSON.stringify(act)}`);
  if (!/^[0-9a-f]{64}$/.test(String(p.key))) throw new Error("bad key");
  // the page's request id (16 hex), written into the combined view's record with the answer; absent from the job's own runs
  if (p.ask !== undefined && !(typeof p.ask === "string" && /^[0-9a-f]{16}$/.test(p.ask))) throw new Error("bad request id");
  const keyOk = com ? keyGate(com, checkKey) : null;
  if (act === "mosaic") return buildMosaic({ siteDir, key: await importKeyHex(p.key), tools, com, keyOk, ask: p.ask || null });
  if (act === "fairplay") return backfillFairPlay({ siteDir, key: await importKeyHex(p.key), tools, com, keyOk });
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
    // Apple's FairPlay form, when the Axinom key is set; a failure here leaves the picture ready elsewhere
    let fairplay = null;
    if (com) { // a new picture: its form replaces nothing
      try {
        const answer = await keyOk();
        if (!mayMake(answer)) log(`no FairPlay form for ${p.id}: ${refusal(com, answer)}`);
        else { if (!answer.accepted) log(`${refusal(com, answer)}; the form for ${p.id} is made all the same (it replaces nothing)`); fairplay = await addFairPlay({ tools, work, outDir: dir, key, com, verified: answer.accepted }); }
      } catch (e) { log(`no FairPlay form for ${p.id}: ${String(e.message || e).slice(0, 300)}`); }
    }
    Object.assign(entry, { status: "ready", width: clip.width, height: clip.height, readyAt: new Date().toISOString(), prKidGuid: ids.prKidGuid, fairplay: !!fairplay });
    await fs.writeFile(join(dir, "meta.json.enc"), await sealText(key, JSON.stringify({ id: p.id, name, width: clip.width, height: clip.height, prKidGuid: ids.prKidGuid, readyAt: entry.readyAt, fairplay })));
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
  return { status: entry.status, error: entry.error, ...(com && entry.status === "ready" ? { fairplay: entry.fairplay } : {}) };
}

// The job's last lines: the result, and a warning on the run's page whenever the combined view or a picture ends
// without the Apple form it should have, so a form that could not be made is never silent. A view kept as it is
// ("kept": Axinom refused the key or could not be asked) is said in the result line and on the page, not warned:
// the weekly run stops with an error on the same cause.
export function resultLines(r, { com = null, action = "" } = {}) {
  const lines = [`result: ${r.status}${r.error ? " — " + r.error : ""}${r.count !== undefined ? ` (${r.count} picture(s))` : ""}${r.fairplay !== undefined ? `; Apple form: ${r.fairplay}` : ""}`];
  if (r.fairplay === "failed") lines.push("::warning title=Apple form::the combined view's new Apple form could not be made; its current one is kept (see the log above)");
  if (com && r.status === "ready" && r.fairplay === false) lines.push(`::warning title=Apple form::${action === "mosaic" ? "the combined view" : "the picture"} was made without its Apple form (see the log above); Apple devices are held back until it has one`);
  return lines;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const event = JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
  const siteDir = process.env.SITE_DIR || fileURLToPath(new URL("./", import.meta.url));
  const tools = { ffmpeg: process.env.FFMPEG_BIN || "ffmpeg", ffprobe: process.env.FFPROBE_BIN || "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
  const action = process.env.WORKER_ACTION || (event.client_payload || {}).action;
  if (action !== "delete") { // only the pinned build ever runs on a picture (a deletion runs no packager, and is never held up)
    try { await checkPackager(tools.packager); } catch (e) { console.log(`::error title=Packager::${e.message}`); process.exit(1); }
  }
  // Apple's form needs the Axinom key; without a usable one every picture is still prepared for the rest
  let com = null;
  if (process.env.AXINOM_COM_KEY_ID || process.env.AXINOM_COM_KEY) {
    try { com = readCommunicationKey(process.env.AXINOM_COM_KEY_ID, process.env.AXINOM_COM_KEY, (await readAxinomSettings(siteDir)).fairplayLicense); }
    catch (e) { console.log(`::warning title=Apple form::the Axinom key is not usable (${e.message}): no Apple (FairPlay) form this time`); }
  } else console.log("the Axinom key is not set: no Apple (FairPlay) form (Apple devices stay held back)");
  const r = await run({ payload: event.client_payload, siteDir, repo: process.env.GITHUB_REPOSITORY || "oneandroid-max/ccs-protected-still-proof", token: process.env.GITHUB_TOKEN, tools, action: process.env.WORKER_ACTION || undefined, com });
  for (const line of resultLines(r, { com, action })) console.log(line);
}
