#!/usr/bin/env node
// tools/build-hdr.mjs — the HDR headroom experiment, step 1: content placed ABOVE ordinary white.
//
// A screenshot file holds the ordinary range of the screen; a phone screen can show more, and the eye
// sees it. This builds two things, encoded as HDR (PQ, BT.2020, 10-bit) in three formats each:
//   1. a public test card: horizontal bands at known brightness levels (50 to 2000 nits), labelled at
//      ordinary white, so a screenshot shows exactly where the phone clips or whether it squeezes;
//   2. the photo re-mapped into 250–1000 nits, every pixel above ordinary white, encrypted with the same
//      link key and PIN as photo.enc (CCSP1 container), so it is never in the open.
//   node tools/build-hdr.mjs --secret=<s> --pin=<p>
import sharp from "sharp";
import { readFile, writeFile, mkdir, rm, mkdtemp } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
const run = promisify(execFile);
const args = {}; for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)(?:=(.*))?$/); if (m) args[m[1]] = m[2] === undefined ? true : m[2]; }
if (!args.secret || !args.pin) { console.error("usage: --secret= --pin="); process.exit(2); }
const { subtle } = webcrypto;
const outDir = "web/research/hdr"; await mkdir(outDir, { recursive: true });
const tmp = await mkdtemp(path.join(os.tmpdir(), "ccs-hdr-"));

// ---- colour maths ----
const srgbToLinear = (v) => { const c = v / 255; return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
const toBt2020 = ([r, g, b]) => [0.6274 * r + 0.3293 * g + 0.0433 * b, 0.0691 * r + 0.9195 * g + 0.0114 * b, 0.0164 * r + 0.0880 * g + 0.8956 * b];
const pq = (nits) => { const Lp = Math.max(0, nits) / 10000, m1 = 0.1593017578125, m2 = 78.84375, c1 = 0.8359375, c2 = 18.8515625, c3 = 18.6875; const p = Math.pow(Lp, m1); return Math.pow((c1 + c2 * p) / (1 + c3 * p), m2); };
const to16 = (v) => Math.max(0, Math.min(65535, Math.round(v * 65535)));
function ppm16(width, height, rgbNits) {   // rgbNits: Float64Array of linear BT.709 nits per channel → PQ-encoded BT.2020 16-bit PPM
  const header = Buffer.from(`P6\n${width} ${height}\n65535\n`, "ascii");
  const body = Buffer.alloc(width * height * 6);
  for (let p = 0; p < width * height; p++) {
    const [r, g, b] = toBt2020([rgbNits[p * 3], rgbNits[p * 3 + 1], rgbNits[p * 3 + 2]]);
    body.writeUInt16BE(to16(pq(r)), p * 6); body.writeUInt16BE(to16(pq(g)), p * 6 + 2); body.writeUInt16BE(to16(pq(b)), p * 6 + 4);
  }
  return Buffer.concat([header, body]);
}

// ---- 1. the test card ----
const W = 720, H = 1280;
const bands = [50, 100, 150, 203, 250, 300, 400, 500, 600, 800, 1000, 1500, 2000];
const bandH = Math.floor((H - 80) / bands.length);
let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}"><rect width="${W}" height="${H}" fill="#000"/>`;
svg += `<text x="16" y="36" font-family="sans-serif" font-size="26" fill="#ff00ff">HDR clipping test card · each band is the brightness it names</text>`;
svg += `<text x="16" y="64" font-family="sans-serif" font-size="20" fill="#ff00ff">labels are drawn at ordinary white (203 nits); bands above it should clip to white in a screenshot</text>`;
bands.forEach((nits, i) => {
  const y = 80 + i * bandH, code = 10 + i * 10;   // the band's grey code, remapped to nits below
  svg += `<rect x="0" y="${y}" width="${W}" height="${bandH}" fill="rgb(${code},${code},${code})"/>`;
  svg += `<text x="24" y="${y + bandH / 2 + 10}" font-family="sans-serif" font-size="30" font-weight="700" fill="#ff00ff">${nits} nits${nits === 203 ? " = ordinary white" : ""}</text>`;
});
svg += `</svg>`;
const cardRaw = await sharp(Buffer.from(svg)).removeAlpha().raw().toBuffer({ resolveWithObject: true });
if (cardRaw.info.channels !== 3) throw new Error("expected 3 channels, got " + cardRaw.info.channels);
const cardNits = new Float64Array(W * H * 3);
for (let p = 0; p < W * H; p++) {
  const r = cardRaw.data[p * 3], g = cardRaw.data[p * 3 + 1], b = cardRaw.data[p * 3 + 2];
  let n;
  if (r > g + 40 && b > g + 40) n = 203;                                   // label text (magenta in the SVG): ordinary white
  else { const code = Math.round((r - 10) / 10); n = code >= 0 && code < bands.length && Math.abs(r - (10 + code * 10)) <= 4 ? bands[code] : 0; }
  cardNits[p * 3] = n; cardNits[p * 3 + 1] = n; cardNits[p * 3 + 2] = n;
}
await writeFile(path.join(tmp, "card.ppm"), ppm16(W, H, cardNits));

// ---- 2. the photo above white ----
const buf = new Uint8Array(await readFile("photo.enc"));
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const iterations = dv.getUint32(6), salt = buf.subarray(10, 26), iv = buf.subarray(26, 38), ciphertext = buf.subarray(38);
const material = await subtle.importKey("raw", new TextEncoder().encode(`${args.secret}:${args.pin}`), "PBKDF2", false, ["deriveKey"]);
const photoKey = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
const jpeg = Buffer.from(await subtle.decrypt({ name: "AES-GCM", iv }, photoKey, ciphertext));
const PW = 720, PH = 960;
const photoRaw = await sharp(jpeg).resize(PW, PH).removeAlpha().raw().toBuffer({ resolveWithObject: true });
if (photoRaw.info.channels !== 3) throw new Error("expected 3 channels, got " + photoRaw.info.channels);
const LOW = 250, HIGH = 1000;   // the photo's black at 250 nits, its white at 1000 nits: every pixel above ordinary white
const photoNits = new Float64Array(PW * PH * 3);
for (let i = 0; i < PW * PH * 3; i++) photoNits[i] = LOW + srgbToLinear(photoRaw.data[i]) * (HIGH - LOW);
await writeFile(path.join(tmp, "photo.ppm"), ppm16(PW, PH, photoNits));

// ---- encode: VP9 profile 2 (webm), HEVC main10 (mp4), AV1 still (avif), all PQ / BT.2020 / 10-bit ----
const colour = ["-color_primaries", "bt2020", "-color_trc", "smpte2084", "-colorspace", "bt2020nc", "-color_range", "tv"];
const vf = "scale=out_color_matrix=bt2020nc:out_range=tv,format=yuv420p10le";
async function encode(src, base, maxNits) {
  const ppm = path.join(tmp, src);
  await run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-loop", "1", "-framerate", "30", "-i", ppm, "-t", "2", "-vf", vf, "-c:v", "libvpx-vp9", "-profile:v", "2", "-pix_fmt", "yuv420p10le", "-b:v", "0", "-crf", "18", "-row-mt", "1", ...colour, path.join(tmp, base + ".webm")]);
  await run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-loop", "1", "-framerate", "30", "-i", ppm, "-t", "2", "-vf", vf, "-c:v", "libx265", "-preset", "medium", "-crf", "16", "-pix_fmt", "yuv420p10le", "-tag:v", "hvc1", "-movflags", "+faststart",
    "-x265-params", `colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc:range=limited:hdr10=1:master-display=G(13250,34500)B(7500,3000)R(34000,16000)WP(15635,16450)L(10000000,1):max-cll=${maxNits},400:repeat-headers=1`, ...colour, path.join(tmp, base + ".mp4")]);
  await run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-i", ppm, "-frames:v", "1", "-vf", vf, "-c:v", "libaom-av1", "-still-picture", "1", "-crf", "12", "-cpu-used", "4", "-pix_fmt", "yuv420p10le", ...colour, path.join(tmp, base + ".avif")]);
}
await encode("card.ppm", "card", 2000);
await encode("photo.ppm", "photo", 1000);

// ---- the public card: copied as is; the photo: encrypted into CCSP1 containers with the same key and PIN ----
const getRandomValues = (a) => webcrypto.getRandomValues(a);
async function encrypt(bytes) {
  const s = getRandomValues(new Uint8Array(16)), v = getRandomValues(new Uint8Array(12));
  const key = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: s, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: v }, key, bytes));
  const header = new Uint8Array(38); header.set(new TextEncoder().encode("CCSP1"), 0); header[5] = 1; new DataView(header.buffer).setUint32(6, iterations); header.set(s, 10); header.set(v, 26);
  const file = new Uint8Array(38 + ct.length); file.set(header, 0); file.set(ct, 38); return file;
}
const report = { card: {}, photo: {} };
for (const ext of ["webm", "mp4", "avif"]) {
  const card = await readFile(path.join(tmp, "card." + ext)); await writeFile(path.join(outDir, "card." + ext), card); report.card[ext] = card.length;
  const photo = await readFile(path.join(tmp, "photo." + ext)); const enc = await encrypt(photo); await writeFile(path.join(outDir, "photo-hdr." + ext + ".enc"), enc); report.photo[ext] = { plain: photo.length, encrypted: enc.length };
}
// what ffprobe sees in the public card files (the photo files are the same encode)
for (const ext of ["webm", "mp4", "avif"]) {
  const { stdout } = await run("ffprobe", ["-hide_banner", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name,profile,pix_fmt,color_transfer,color_primaries,color_space,width,height", "-of", "json", path.join(outDir, "card." + ext)]);
  report.card[ext + "_probe"] = JSON.parse(stdout).streams[0];
}
await rm(tmp, { recursive: true, force: true });
report.mapping = { card: "bands at " + bands.join(", ") + " nits; labels at 203 nits", photo: `${LOW}–${HIGH} nits, every pixel above ordinary white` };
await writeFile(path.join(outDir, "info.json"), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 1));
