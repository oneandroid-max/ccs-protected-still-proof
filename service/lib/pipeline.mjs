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
// A picture smaller than MIN_SIDE on its short side is drawn larger (up to MIN_SIDE, never past maxSide):
// a keyframe of a few pixels has too little coded data for Apple's form to encrypt any of it (measured: a
// solid 16x16 and 2x2 refused, a solid 64x64 passed).
export const MIN_SIDE = 64;
export function targetSize({ width, height }, orientation, maxSide = MAX_SIDE) {
  const swap = orientation >= 5;
  const w = swap ? height : width, h = swap ? width : height;
  let f = Math.min(1, maxSide / Math.max(w, h));
  if (Math.min(w, h) * f < MIN_SIDE) f = Math.min(MIN_SIDE / Math.min(w, h), maxSide / Math.max(w, h));
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
// fixedClock (the public test card only): creation and modification times written as 0, so the same input
// packages to the same bytes every time (otherwise they are the clock's, and only they differ).
export async function packageFairPlay(packager, dir, { kid, key, iv, keyUri }, { fixedClock = false } = {}) {
  await fs.mkdir(join(dir, "fp"), { recursive: true });
  await run(packager, ["in=clip.mp4,stream=video,output=fp/video.mp4,playlist_name=video.m3u8",
    "--enable_raw_key_encryption", "--keys", `label=:key_id=${kid}:key=${key}`, "--iv", iv,
    "--protection_systems", "FairPlay", "--protection_scheme", "cbcs", "--clear_lead", "0",
    "--hls_key_uri", keyUri, "--segment_duration", "2", "--fragment_duration", "2",
    "--hls_master_playlist_output", "fp/master.m3u8", ...(fixedClock ? ["--use_fake_clock_for_muxer"] : [])], { cwd: dir });
}

// What a FairPlay output must carry before it is published: the playlist's key line with this key
// address and Apple's key format; in the file the 'cbcs' scheme with Apple's pattern (one 16-byte block
// encrypted in ten) on a protected track, with this key id and this constant IV (so the licence's IV
// matches the encryption); and, fragment by fragment, the sample table ('trun': each sample's size,
// whether it is a keyframe, and where its bytes lie, which must be inside the file's media data) matched
// record for record with the sample-encryption records ('senc': per sample, per slice, clear bytes then
// protected bytes), each record adding up to its sample's size and read exactly to its box's end. Then
// each sample's own bytes are read, NAL unit by NAL unit, against its records:
// - a clear run holds only whole NAL units that are not slices (the encoder's settings note, filler, an
//   access unit delimiter), then at most SLICE_HEADER_MAX bytes of the slice whose protected range follows
//   (its length, its NAL header and its slice header: 11 to 19 bytes in every real output measured);
// - that protected range ends exactly where its slice ends, and no slice is left wholly in the clear;
// - EVERY SLICE OF EVERY KEYFRAME has at least one encrypted block (16 protected bytes or more). Under
//   'cbcs' each slice is encrypted on its own and a protected range under one block encrypts nothing:
//   normal for the near-empty frames between a still picture's keyframes (10 to 13 bytes, measured on a
//   solid colour), never for a keyframe's slice, which a decoder can show on its own.
export function checkFairPlay(playlist, data, { kid, iv, keyUri }) {
  const problems = [];
  const keyLine = playlist.split("\n").find((l) => l.startsWith("#EXT-X-KEY:")) || "";
  if (!/METHOD=SAMPLE-AES/.test(keyLine)) problems.push("the playlist's key line is not SAMPLE-AES");
  if (!keyLine.includes(`URI="${keyUri}"`)) problems.push("the playlist does not carry the key address");
  if (!/KEYFORMAT="com\.apple\.streamingkeydelivery"/.test(keyLine)) problems.push("the playlist does not name Apple's key format");
  let scheme = null, tencKid = null, constIv = null, ivSize = 0, tenc = null, nalLen = 0;
  const trex = new Map(); // per track: the movie's default sample size and flags
  const mdats = [], samples = []; // the media data's byte ranges; every sample with its record
  const n = { samples: 0, samplesMarked: 0, samplesEncrypted: 0, keyframes: 0, keyframesEncrypted: 0, protectedBytes: 0, mismatched: 0, uncovered: 0, outside: 0, offSlice: 0, clearSlices: 0 };
  const NOT_KEYFRAME = 0x10000; // sample_is_non_sync_sample, in a sample's flags
  const SLICE_HEADER_MAX = 64;
  const header = (off, end) => { let s = data.readUInt32BE(off); if (s === 1) s = Number(data.readBigUInt64BE(off + 8)); if (s === 0) s = end - off; return [s, data.toString("latin1", off + 4, off + 8)]; };
  const cut = (what) => { throw new Error(`a fragment's ${what} is cut short`); };
  const sane = (count) => { if (count > 1e6) throw new Error(`a fragment lists ${count} samples`); return count; };
  // one fragment of the track (inside the 'moof' at `moof`): its defaults ('tfhd', else the movie's
  // 'trex'), its samples ('trun') and their records ('senc'), in the order the standard gives them
  const fragment = (off, end, moof) => {
    let dflt = { size: 0, flags: 0 }, base = moof, next = null, p = off; const table = [], records = [], limit = Math.min(end, data.length);
    for (; p + 8 <= limit;) {
      const [s, t] = header(p, limit); if (s < 8 || p + s > limit) cut("box");
      if (t === "tfhd") {
        const f = s >= 12 ? data.readUIntBE(p + 9, 3) : 0;
        if (16 + (f & 0x1 ? 8 : 0) + (f & 0x2 ? 4 : 0) + (f & 0x8 ? 4 : 0) + (f & 0x10 ? 4 : 0) + (f & 0x20 ? 4 : 0) > s) cut("fragment header");
        let q = p + 16;
        dflt = { ...(trex.get(data.readUInt32BE(p + 12)) || { size: 0, flags: 0 }) };
        if (f & 0x1) { base = Number(data.readBigUInt64BE(q)); q += 8; } if (f & 0x2) q += 4; if (f & 0x8) q += 4;
        if (f & 0x10) { dflt.size = data.readUInt32BE(q); q += 4; }
        if (f & 0x20) dflt.flags = data.readUInt32BE(q);
      }
      if (t === "trun") {
        if (s < 16) cut("sample table");
        const f = data.readUIntBE(p + 9, 3), count = sane(data.readUInt32BE(p + 12)); let q = p + 16, first = null, offset = null;
        const row = 4 * [0x100, 0x200, 0x400, 0x800].filter((b) => f & b).length;
        if (16 + (f & 0x1 ? 4 : 0) + (f & 0x4 ? 4 : 0) + count * row > s) cut("sample table");
        if (f & 0x1) { offset = data.readInt32BE(q); q += 4; } if (f & 0x4) { first = data.readUInt32BE(q); q += 4; }
        // where the samples lie: from the data offset (counted from the fragment's base, which is the 'moof'
        // unless the fragment names one), or straight after the previous run's samples
        let at = offset !== null ? base + offset : next !== null ? next : base;
        for (let i = 0; i < count; i++) {
          const r = { size: dflt.size, flags: i === 0 && first !== null ? first : dflt.flags, at };
          if (f & 0x100) q += 4; if (f & 0x200) { r.size = data.readUInt32BE(q); q += 4; } if (f & 0x400) { r.flags = data.readUInt32BE(q); q += 4; } if (f & 0x800) q += 4;
          table.push(r); at += r.size;
        }
        next = at;
        if (table.length && (table[0].at < 0 || next > data.length)) cut("media data");
      }
      if (t === "senc") { // full box: version and flags, the sample count, then per sample its IV and, with flag 2, its subsamples
        if (s < 16) cut("encryption record");
        const f = data.readUIntBE(p + 9, 3), count = sane(data.readUInt32BE(p + 12)); let q = p + 16;
        for (let i = 0; i < count; i++) {
          q += ivSize;
          if (!(f & 2)) { if (q > p + s) cut("encryption record"); records.push(null); continue; } // no subsamples: the whole sample is protected
          if (q + 2 > p + s) cut("encryption record");
          const k = data.readUInt16BE(q); q += 2; const subs = [];
          if (q + 6 * k > p + s) cut("encryption record");
          for (let j = 0; j < k; j++) { subs.push([data.readUInt16BE(q), data.readUInt32BE(q + 2)]); q += 6; }
          records.push(subs);
        }
        // the records fill their box exactly: a box read as something else (a flag cleared, a count changed)
        // leaves bytes over, or runs short
        if (q !== p + s) throw new Error("a fragment's encryption records do not fill their box exactly");
      }
      p += s;
    }
    if (p !== end) cut("box"); // the file ends inside the fragment
    if (records.length !== table.length) n.mismatched++;
    table.forEach((r, i) => samples.push({ r, rec: records[i] }));
  };
  const walk = (off, end, moof = 0) => {
    end = Math.min(end, data.length);
    while (off + 8 <= end) {
      const [s, t] = header(off, end);
      if (s < 8) return;
      if (t === "schm") scheme = data.toString("latin1", off + 12, off + 16);
      if (t === "tenc") {
        tenc = { version: data[off + 8], pattern: data[off + 13], isProtected: data[off + 14] };
        tencKid = data.toString("hex", off + 16, off + 32);
        ivSize = data[off + 15];
        if (ivSize === 0) { const len = data[off + 32]; constIv = data.toString("hex", off + 33, off + 33 + len); }
      }
      if (t === "avcC" && s >= 13) nalLen = (data[off + 12] & 3) + 1; // H.264's configuration: the size of each NAL unit's length field
      if (t === "trex") { if (s < 32) throw new Error("the movie's sample defaults are cut short"); trex.set(data.readUInt32BE(off + 12), { size: data.readUInt32BE(off + 24), flags: data.readUInt32BE(off + 28) }); }
      if (t === "mdat") mdats.push([off + (data.readUInt32BE(off) === 1 ? 16 : 8), Math.min(off + s, data.length)]);
      if (t === "traf") fragment(off + 8, off + s, moof);
      if (t === "moof") walk(off + 8, off + s, off);
      if (["moov", "trak", "mdia", "minf", "stbl", "sinf", "schi", "mvex"].includes(t)) walk(off + 8, off + s, moof);
      if (t === "stsd") walk(off + 16, off + s, moof);
      if (t === "encv") walk(off + 8 + 78, off + s, moof);
      off += s;
    }
  };
  // one sample's slices, read from its own bytes against its records: for each slice whose protected range
  // follows a clear run, its protected byte count; null when the records do not follow the slices
  const slicesOf = (r, subs) => {
    const out = []; let pos = r.at;
    for (const [c, prot] of subs) {
      const clearEnd = pos + c, protEnd = clearEnd + prot; let q = pos, slice = false;
      while (q < clearEnd) {
        if (q + nalLen + 1 > protEnd) return null;
        const len = data.readUIntBE(q, nalLen), type = data[q + nalLen] & 0x1f, nalEnd = q + nalLen + len;
        const isSlice = type >= 1 && type <= 5; // H.264's slice NAL units (5: a keyframe's)
        if (nalEnd <= clearEnd) { if (isSlice) out.push(0); q = nalEnd; continue; } // a slice wholly in the clear counts as one with nothing encrypted
        if (!isSlice || clearEnd - q > SLICE_HEADER_MAX || nalEnd !== protEnd) return null;
        out.push(prot); slice = true; q = protEnd;
      }
      if (prot > 0 && !slice) return null; // protected bytes that are no slice's
      pos = protEnd;
    }
    return out;
  };
  const inMedia = (a, b) => mdats.some(([x, y]) => a >= x && b <= y);
  try {
    walk(0, data.length);
    for (const { r, rec } of samples) {
      const keyframe = !(r.flags & NOT_KEYFRAME);
      n.samples++; if (keyframe) n.keyframes++;
      const inside = inMedia(r.at, r.at + r.size); if (!inside) n.outside++;
      if (rec === undefined) continue; // no record: neither protected nor encrypted
      const subs = rec === null ? [[0, r.size]] : rec; // per slice: clear bytes, then protected bytes
      const clear = subs.reduce((a, x) => a + x[0], 0), prot = subs.reduce((a, x) => a + x[1], 0);
      if (clear + prot !== r.size) n.uncovered++;
      n.protectedBytes += prot;
      if (prot > 0) n.samplesMarked++;
      if (subs.some((x) => x[1] >= 16)) n.samplesEncrypted++;
      if (rec === null) { if (keyframe && r.size >= 16) n.keyframesEncrypted++; continue; } // the whole sample protected
      if (!inside || clear + prot !== r.size || !nalLen) continue; // its bytes cannot be read against its records (named above)
      const slices = slicesOf(r, subs);
      if (slices === null) { n.offSlice++; continue; }
      if (slices.includes(0)) n.clearSlices++;
      if (keyframe && slices.length && slices.every((x) => x >= 16)) n.keyframesEncrypted++;
    }
  } catch (e) { problems.push(`the file cannot be read: ${e.message}`); }
  if (scheme !== "cbcs") problems.push(`the file's scheme is ${scheme}, not cbcs`);
  if (!tenc || tenc.version !== 1 || tenc.pattern !== 0x19 || tenc.isProtected !== 1) problems.push("the file's encryption is not Apple's (a protected track, one block encrypted in ten)");
  if (tencKid !== kid) problems.push("the file's key id is not this key id");
  if (constIv !== iv) problems.push("the file's constant IV is not this IV");
  if (!nalLen) problems.push("the file carries no H.264 configuration ('avcC'), so its slices cannot be read");
  let boxes = { ok: false }; try { boxes = checkBoxes(data); } catch {} // a file cut short is already named above
  if (!boxes.ok) problems.push("the file is missing its sample-encryption boxes");
  if (!n.samples) problems.push("the file carries no samples");
  if (n.mismatched) problems.push(`${n.mismatched} fragment(s) list a different number of encryption records than samples`);
  if (n.outside) problems.push(`${n.outside} of ${n.samples} samples lie outside the file's media data`);
  if (n.samples && n.samplesMarked !== n.samples) problems.push(`${n.samples - n.samplesMarked} of ${n.samples} samples have no protected bytes`);
  if (n.uncovered) problems.push(`${n.uncovered} of ${n.samples} samples are not covered whole by their encryption records`);
  if (n.offSlice) problems.push(`${n.offSlice} of ${n.samples} samples have encryption records that do not follow their slices (more than ${SLICE_HEADER_MAX} clear bytes of a slice, protected bytes outside a slice, or a protected range not ending with its slice)`);
  if (n.clearSlices) problems.push(`${n.clearSlices} of ${n.samples} samples carry a slice wholly in the clear`);
  if (n.samples && !n.keyframes) problems.push("no sample is marked as a keyframe");
  if (n.keyframesEncrypted !== n.keyframes) problems.push(`${n.keyframes - n.keyframesEncrypted} of ${n.keyframes} keyframes have a slice with no encrypted block`);
  const { mismatched, uncovered, outside, offSlice, clearSlices, ...counts } = n;
  return { ok: problems.length === 0, problems, scheme, kid: tencKid, iv: constIv, ...counts };
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
