// Turns one uploaded picture into the two protected clips the viewer plays, exactly as the proof's
// workflows do: ffmpeg renders the still to a 2-second H.264 clip (EXIF orientation honoured, longest
// side at most MAX_SIDE), then shaka-packager encrypts it for Widevine (key from Google's UAT key
// server, public test signer) and for PlayReady (the key Microsoft's public test server derives for a
// fresh key id). Every fragment is then checked for its sample-encryption boxes before the photo is
// marked ready. The keys are the vendors' PUBLIC test keys: a skilled person can decrypt these clips
// until CCS's own production credentials replace the test servers.
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { run, nowIso } from "./util.mjs";
import { jpegOrientation, ORIENTATION_FILTER } from "./exif.mjs";
import { derivePlayReadyTestKey } from "../../tools/playready-test-key.mjs";

export const MAX_SIDE = 1280;
export const WIDEVINE_TEST = {
  keyServer: "https://license.uat.widevine.com/cenc/getcontentkey/widevine_test",
  signer: "widevine_test",
  aesKey: "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9",
  aesIv: "d58ce954203b7c9a9a9d467f59839249",
};
export const PLAYREADY_TEST_SERVER = "https://test.playready.microsoft.com/service/rightsmanager.asmx";

export const kidToGuid = (kid) => { const h = kid.toUpperCase(); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; };

export async function probe(ffprobe, file) {
  const { stdout } = await run(ffprobe, ["-hide_banner", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height", "-of", "json", file]);
  const s = JSON.parse(stdout).streams?.[0];
  if (!s || !s.width || !s.height) throw new Error("the picture could not be read");
  return { width: s.width, height: s.height };
}

const even = (x) => Math.max(2, Math.round(x / 2) * 2);

// The clip's size: the picture as the viewer sees it (rotated upright), longest side at most maxSide.
export function targetSize({ width, height }, orientation, maxSide = MAX_SIDE) {
  const swap = orientation >= 5;
  const w = swap ? height : width, h = swap ? width : height;
  const f = Math.min(1, maxSide / Math.max(w, h));
  return { width: even(w * f), height: even(h * f) };
}

export async function renderClip(tools, input, outClip, { orientation = 1, maxSide = MAX_SIDE } = {}) {
  const dims = await probe(tools.ffprobe, input);
  const size = targetSize(dims, orientation, maxSide);
  const rot = ORIENTATION_FILTER[orientation] || "";
  const vf = `${rot ? rot + "," : ""}loop=loop=29:size=1:start=0,setpts=N/(15*TB),scale=${size.width}:${size.height},format=yuv420p`;
  await run(tools.ffmpeg, ["-hide_banner", "-loglevel", "error", "-y", "-noautorotate", "-i", input,
    "-vf", vf, "-r", "15", "-t", "2", "-c:v", "libx264", "-profile:v", "main", "-level", "4.0", "-pix_fmt", "yuv420p",
    "-g", "15", "-movflags", "+faststart", outClip]);
  const out = await probe(tools.ffprobe, outClip);
  return { source: dims, orientation, ...out };
}

export async function packageClip(packager, dir, { wvContentId, prKid, prKey, prKidGuid }) {
  const cid = Buffer.from(wvContentId, "utf8").toString("hex");
  await run(packager, ["in=clip.mp4,stream=video,output=video-widevine.mp4",
    "--enable_widevine_encryption", "--key_server_url", WIDEVINE_TEST.keyServer,
    "--content_id", cid, "--signer", WIDEVINE_TEST.signer, "--aes_signing_key", WIDEVINE_TEST.aesKey, "--aes_signing_iv", WIDEVINE_TEST.aesIv,
    "--protection_systems", "Widevine", "--protection_scheme", "cenc", "--clear_lead", "0",
    "--segment_duration", "2", "--fragment_duration", "2", "--mpd_output", "widevine.mpd"], { cwd: dir });
  const la = `${PLAYREADY_TEST_SERVER}?cfg=(kid:${prKidGuid},sl:2000)`.replace(/&/g, "&amp;");
  await run(packager, ["in=clip.mp4,stream=video,output=video-playready.mp4",
    "--enable_raw_key_encryption", "--keys", `label=:key_id=${prKid}:key=${prKey}`,
    "--protection_systems", "PlayReady", "--protection_scheme", "cenc", "--clear_lead", "0",
    "--segment_duration", "2", "--fragment_duration", "2",
    "--playready_extra_header_data", `<LA_URL>${la}</LA_URL>`, "--mpd_output", "playready.mpd"], { cwd: dir });
}

// Apple's FairPlay: the same clip as HLS, encrypted 'cbcs' under the given key with a constant IV, its
// playlist carrying the key address Axinom's licence service reads (skd://<key id>:<IV>). Writes
// fp/master.m3u8, fp/video.m3u8 and fp/video.mp4 in `dir`. The key comes from the caller (never a key
// server): the licence is issued later, against a token that carries the key encrypted for Axinom.
export async function packageFairPlay(packager, dir, { kid, key, iv, keyUri }) {
  await fs.mkdir(join(dir, "fp"), { recursive: true });
  await run(packager, ["in=clip.mp4,stream=video,output=fp/video.mp4,playlist_name=video.m3u8",
    "--enable_raw_key_encryption", "--keys", `label=:key_id=${kid}:key=${key}`, "--iv", iv,
    "--protection_systems", "FairPlay", "--protection_scheme", "cbcs", "--clear_lead", "0",
    "--hls_key_uri", keyUri, "--segment_duration", "2", "--fragment_duration", "2",
    "--hls_master_playlist_output", "fp/master.m3u8"], { cwd: dir });
}

// What a FairPlay output must carry before it is published: the playlist's key line with this key
// address and Apple's key format, and in the file the 'cbcs' scheme with this key id and this constant
// IV (so the licence's IV matches the encryption), and EVERY sample with encrypted bytes, read from the
// fragments' sample-encryption records ('senc': each sample's clear and protected byte counts).
export function checkFairPlay(playlist, data, { kid, iv, keyUri }) {
  const problems = [];
  const keyLine = playlist.split("\n").find((l) => l.startsWith("#EXT-X-KEY:")) || "";
  if (!/METHOD=SAMPLE-AES/.test(keyLine)) problems.push("the playlist's key line is not SAMPLE-AES");
  if (!keyLine.includes(`URI="${keyUri}"`)) problems.push("the playlist does not carry the key address");
  if (!/KEYFORMAT="com\.apple\.streamingkeydelivery"/.test(keyLine)) problems.push("the playlist does not name Apple's key format");
  let scheme = null, tencKid = null, constIv = null, ivSize = 0, samples = 0, samplesEncrypted = 0, protectedBytes = 0;
  const walk = (off, end) => {
    while (off + 8 <= end) {
      let s = data.readUInt32BE(off); const t = data.toString("latin1", off + 4, off + 8);
      if (s === 1) s = Number(data.readBigUInt64BE(off + 8)); if (s === 0) s = end - off;
      if (s < 8) return;
      if (t === "schm") scheme = data.toString("latin1", off + 12, off + 16);
      if (t === "tenc") {
        tencKid = data.toString("hex", off + 16, off + 32);
        ivSize = data[off + 15];
        if (ivSize === 0) { const n = data[off + 32]; constIv = data.toString("hex", off + 33, off + 33 + n); }
      }
      if (t === "senc" && s >= 16) { // full box: version and flags, the sample count, then per sample its IV and, with flag 2, its subsamples
        const flags = data.readUIntBE(off + 9, 3), count = data.readUInt32BE(off + 12), end = off + s;
        let p = off + 16;
        for (let i = 0; i < count; i++) {
          samples++; p += ivSize;
          if (!(flags & 2)) { if (p <= end) samplesEncrypted++; continue; } // no subsamples: the whole sample is encrypted
          if (p + 2 > end) break; // a record cut short counts as not encrypted
          const n = data.readUInt16BE(p); p += 2; let prot = 0;
          if (p + 6 * n > end) break;
          for (let j = 0; j < n; j++) { prot += data.readUInt32BE(p + 2); p += 6; }
          protectedBytes += prot; if (prot > 0) samplesEncrypted++;
        }
      }
      if (["moov", "trak", "mdia", "minf", "stbl", "sinf", "schi", "moof", "traf"].includes(t)) walk(off + 8, off + s);
      if (t === "stsd") walk(off + 16, off + s);
      if (t === "encv") walk(off + 8 + 78, off + s);
      off += s;
    }
  };
  walk(0, data.length);
  if (scheme !== "cbcs") problems.push(`the file's scheme is ${scheme}, not cbcs`);
  if (tencKid !== kid) problems.push("the file's key id is not this key id");
  if (constIv !== iv) problems.push("the file's constant IV is not this IV");
  const boxes = checkBoxes(data);
  if (!boxes.ok) problems.push("the file is missing its sample-encryption boxes");
  if (!samples || samplesEncrypted !== samples) problems.push(`${samples - samplesEncrypted} of ${samples} samples have no encrypted bytes`);
  return { ok: problems.length === 0, problems, scheme, kid: tencKid, iv: constIv, samples, samplesEncrypted, protectedBytes };
}

// Counts the boxes that matter in a packaged file and collects its key ids and protection systems.
export function checkBoxes(data) {
  const count = {}; const kids = new Set(); const pssh = [];
  const walk = (off, end) => {
    while (off + 8 <= end) {
      let s = data.readUInt32BE(off); const t = data.toString("latin1", off + 4, off + 8);
      if (s === 1) s = Number(data.readBigUInt64BE(off + 8)); if (s === 0) s = end - off;
      if (s < 8) return;
      count[t] = (count[t] || 0) + 1;
      if (t === "pssh") pssh.push(data.toString("hex", off + 12, off + 28));
      if (t === "tenc") kids.add(data.toString("hex", off + 16, off + 32));
      if (["moov", "trak", "mdia", "minf", "stbl", "moof", "traf", "sinf", "schi", "mvex"].includes(t)) walk(off + 8, off + s);
      if (t === "stsd") walk(off + 16, off + s);
      if (t === "encv") walk(off + 8 + 78, off + s);
      off += s;
    }
  };
  walk(0, data.length);
  const r = { moof: count.moof || 0, senc: count.senc || 0, saiz: count.saiz || 0, saio: count.saio || 0, tenc: count.tenc || 0, kids: [...kids], pssh };
  r.ok = r.moof > 0 && r.senc >= r.moof && r.saiz >= r.moof && r.saio >= r.moof && r.tenc > 0;
  return r;
}

export function newProtectionIds(id) {
  const prKid = randomBytes(16).toString("hex");
  return { wvContentId: `ccs-proof-${id}`, prKid, prKidGuid: kidToGuid(prKid) };
}

// Runs the whole pipeline for one record and updates its status: processing → ready | failed.
export async function processPhoto(tools, store, id) {
  const rec = store.get(id);
  if (!rec) return;
  const dir = store.dir(id);
  await store.update(id, { status: "processing", error: null });
  try {
    const original = join(dir, `original.${rec.ext}`);
    const orientation = rec.type === "image/jpeg" ? jpegOrientation(await fs.readFile(original)) : 1;
    const clip = await renderClip(tools, original, join(dir, "clip.mp4"), { orientation });
    await packageClip(tools.packager, dir, { ...rec, prKey: derivePlayReadyTestKey(rec.prKid) });
    const wv = checkBoxes(await fs.readFile(join(dir, "video-widevine.mp4")));
    const pr = checkBoxes(await fs.readFile(join(dir, "video-playready.mp4")));
    if (!wv.ok || !pr.ok) throw new Error(`a packaged file is missing its sample-encryption boxes (widevine ${JSON.stringify(wv)}, playready ${JSON.stringify(pr)})`);
    if (!pr.kids.includes(rec.prKid)) throw new Error("the PlayReady file does not carry this photo's key id");
    await fs.rm(join(dir, "clip.mp4"), { force: true }); // the clear clip is not kept
    await store.update(id, { status: "ready", readyAt: nowIso(), width: clip.width, height: clip.height, orientation,
      boxes: { widevine: { moof: wv.moof, senc: wv.senc, kids: wv.kids }, playready: { moof: pr.moof, senc: pr.senc, kids: pr.kids } } });
  } catch (e) {
    await store.update(id, { status: "failed", error: String(e.message || e).slice(0, 600) });
  }
}

// One photo at a time; a photo is queued by id and processed in order.
export function makeQueue(tools, store, log = () => {}) {
  const queue = []; let running = false;
  async function drain() {
    if (running) return; running = true;
    try {
      while (queue.length) {
        const id = queue.shift();
        log(`processing ${id}`);
        await processPhoto(tools, store, id);
        const r = store.get(id);
        log(`${id}: ${r ? r.status : "gone"}${r && r.error ? " — " + r.error : ""}`);
      }
    } finally { running = false; }
  }
  return {
    enqueue(id) { queue.push(id); drain().catch((e) => log(`queue error: ${e.message}`)); },
    pending() { return queue.length + (running ? 1 : 0); },
  };
}
