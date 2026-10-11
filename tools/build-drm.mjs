#!/usr/bin/env node
// tools/build-drm.mjs — route 1 research: the still as a two-second H.264 video encrypted with
// Common Encryption (cenc, AES-CTR) for the browser's own protected video path.
//   PlayReady (Edge on Windows): the key is derived from Microsoft's published test key seed and the
//     key id, which is what their public test licence server does for any key id it is asked about.
//   Widevine (Chrome on Android and desktop, Firefox): the key comes from Google's UAT key server
//     (web/research/drm/widevine-key.json, written by the widevine-key workflow); built only when present.
// Writes web/research/drm/video-playready.mp4, video-widevine.mp4 and info.json. The decrypted JPEG
// exists only in a temp file. Both keys are test keys that protect nothing; the measurement is the
// phone's or the PC's protected path, not the secrecy of the key.
//   node tools/build-drm.mjs --secret=<s> --pin=<p> [--file=photo.enc]
import { readFile, writeFile, mkdir, rm, mkdtemp, access } from "node:fs/promises";
import { webcrypto, createHash, createCipheriv } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
const run = promisify(execFile);
const args = {}; for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)(?:=(.*))?$/); if (m) args[m[1]] = m[2] === undefined ? true : m[2]; }
if (!args.secret || !args.pin) { console.error("usage: --secret= --pin= [--file=photo.enc]"); process.exit(2); }
const { subtle } = webcrypto;

// --- the photo, decrypted into a temp file only ---
const buf = new Uint8Array(await readFile(args.file || "photo.enc"));
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const iterations = dv.getUint32(6), salt = buf.subarray(10, 26), iv = buf.subarray(26, 38), ciphertext = buf.subarray(38);
const material = await subtle.importKey("raw", new TextEncoder().encode(`${args.secret}:${args.pin}`), "PBKDF2", false, ["deriveKey"]);
const photoKey = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
const jpeg = Buffer.from(await subtle.decrypt({ name: "AES-GCM", iv }, photoKey, ciphertext));
const tmp = await mkdtemp(path.join(os.tmpdir(), "ccs-drm-"));
const jpg = path.join(tmp, "photo.jpg"); await writeFile(jpg, jpeg);
const outDir = "web/research/drm"; await mkdir(outDir, { recursive: true });

async function encode(out, kidHex, keyHex) {
  await run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-loop", "1", "-i", jpg, "-t", "2", "-r", "15", "-vf", "scale=720:-2", "-c:v", "libx264", "-profile:v", "main", "-level", "3.1", "-pix_fmt", "yuv420p", "-g", "15",
    "-movflags", "frag_keyframe+empty_moov+default_base_moof", "-encryption_scheme", "cenc-aes-ctr", "-encryption_key", keyHex, "-encryption_kid", kidHex, out]);
  const { stdout } = await run("ffprobe", ["-hide_banner", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name,profile,level,width,height", "-of", "json", out]);
  const st = JSON.parse(stdout).streams[0];
  const profileHex = { Baseline: "42", Main: "4d", High: "64" }[st.profile] || "4d";
  const level = Number(st.level) > 0 ? Number(st.level) : 31;   // ffprobe cannot read the level of an encrypted stream; the encode asked for 3.1
  return { codecs: `avc1.${profileHex}00${level.toString(16).padStart(2, "0")}`, width: st.width, height: st.height, bytes: (await readFile(out)).length };
}
const psshBox = (systemIdHex, data) => {
  const box = Buffer.alloc(32 + data.length);
  box.writeUInt32BE(box.length, 0); box.write("pssh", 4, "latin1"); box.writeUInt32BE(0, 8);   // version 0, flags 0
  Buffer.from(systemIdHex.replace(/-/g, ""), "hex").copy(box, 12); box.writeUInt32BE(data.length, 28); data.copy(box, 32);
  return box;
};
const guidSwap = (kid) => Buffer.from([kid[3], kid[2], kid[1], kid[0], kid[5], kid[4], kid[7], kid[6], ...kid.subarray(8)]);
const guidString = (kid) => { const h = kid.toString("hex").toUpperCase(); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; };

// --- PlayReady: key from Microsoft's published test key seed (the test server derives the same) ---
const TEST_KEY_SEED = Buffer.from("XVBovsmzhP9gRIZxWfFta3VVRPzVEWmJsazEJ46I", "base64").subarray(0, 30);
const prKid = createHash("sha256").update(`ccs-playready-kid:${args.secret}`).digest().subarray(0, 16);   // the CENC key id, big-endian
const prKidSwapped = guidSwap(prKid);
const sha = (...parts) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };
const A = sha(TEST_KEY_SEED, prKidSwapped), B = sha(TEST_KEY_SEED, prKidSwapped, TEST_KEY_SEED), C = sha(TEST_KEY_SEED, prKidSwapped, TEST_KEY_SEED, prKidSwapped);
const prKey = Buffer.from(Array.from({ length: 16 }, (_, i) => A[i] ^ A[i + 16] ^ B[i] ^ B[i + 16] ^ C[i] ^ C[i + 16]));
const ecb = createCipheriv("aes-128-ecb", prKey, null); ecb.setAutoPadding(false);
const checksum = Buffer.concat([ecb.update(prKidSwapped), ecb.final()]).subarray(0, 8);
const laUrl = `https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(kid:${guidString(prKid)},sl:2000)`;
const wrm = `<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.0.0.0"><DATA><PROTECTINFO><KEYLEN>16</KEYLEN><ALGID>AESCTR</ALGID></PROTECTINFO><KID>${prKidSwapped.toString("base64")}</KID><CHECKSUM>${checksum.toString("base64")}</CHECKSUM><LA_URL>${laUrl.replace(/&/g, "&amp;")}</LA_URL></DATA></WRMHEADER>`;
const wrmUtf16 = Buffer.from(wrm, "utf16le");
const record = Buffer.alloc(4 + wrmUtf16.length); record.writeUInt16LE(1, 0); record.writeUInt16LE(wrmUtf16.length, 2); wrmUtf16.copy(record, 4);
const pro = Buffer.alloc(6 + record.length); pro.writeUInt32LE(pro.length, 0); pro.writeUInt16LE(1, 4); record.copy(pro, 6);
const prPssh = psshBox("9a04f079-9840-4286-ab92-e65be0885f95", pro);
const prVideo = await encode(path.join(outDir, "video-playready.mp4"), prKid.toString("hex"), prKey.toString("hex"));
const playready = { file: "video-playready.mp4", ...prVideo, kid: prKid.toString("hex"), kidGuid: guidString(prKid), pssh: prPssh.toString("base64"),
  licenseServer: "https://test.playready.microsoft.com/service/rightsmanager.asmx", keyDerivation: "Microsoft's published test key seed + key id (SHA-256 ×3, XOR), the test server's own rule",
  note: "test-only: Microsoft's public test licence server issues this key to anyone who asks with the key id" };

// --- Widevine: key from Google's UAT key server, fetched by the widevine-key workflow ---
let widevine = null;
try {
  await access(path.join(outDir, "widevine-key.json"));
  const wk = JSON.parse(await readFile(path.join(outDir, "widevine-key.json"), "utf8"));
  const track = wk.tracks.find((t) => t.type === "SD") || wk.tracks[0];
  const wvVideo = await encode(path.join(outDir, "video-widevine.mp4"), track.keyId, track.key);
  const box = track.psshBoxes ? Buffer.from(track.psshBoxes, "base64") : psshBox("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed", Buffer.from(track.psshData, "base64"));
  widevine = { file: "video-widevine.mp4", ...wvVideo, contentId: wk.contentId, kid: track.keyId, pssh: box.toString("base64"), licenseServer: wk.licenseProxy,
    note: "test-only: Google's public test licence proxy issues this key to anyone who presents the PSSH" };
} catch (e) { console.error(`widevine: skipped (${e.code || e.message}); run the widevine-key workflow first`); }

await rm(tmp, { recursive: true, force: true });
const info = { playready, widevine, builtAt: new Date().toISOString() };
await writeFile(path.join(outDir, "info.json"), JSON.stringify(info, null, 2) + "\n");
console.log(JSON.stringify({ playready: { kid: playready.kid, codecs: playready.codecs, size: `${playready.width}x${playready.height}`, bytes: playready.bytes, psshBytes: prPssh.length }, widevine: widevine && { kid: widevine.kid, bytes: widevine.bytes } }));
