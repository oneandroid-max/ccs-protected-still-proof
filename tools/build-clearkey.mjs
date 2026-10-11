#!/usr/bin/env node
// tools/build-clearkey.mjs — research candidate 4: the still as a two-second video encrypted with the
// standard ClearKey system (no licence server: the page supplies the key itself, derived from the link
// key and the PIN exactly like the photo's key). Writes web/research/clearkey/video.mp4 (encrypted) and
// info.json (the public key id and the codec string). The decrypted JPEG exists only in a temp file.
//   node tools/build-clearkey.mjs --secret=<s> --pin=<p> [--file=photo.enc]
import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { webcrypto, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
const run = promisify(execFile);
const args = {}; for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)(?:=(.*))?$/); if (m) args[m[1]] = m[2] === undefined ? true : m[2]; }
if (!args.secret || !args.pin) { console.error("usage: --secret= --pin= [--file=photo.enc]"); process.exit(2); }
const { subtle } = webcrypto;
const buf = new Uint8Array(await readFile(args.file || "photo.enc"));
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const iterations = dv.getUint32(6), salt = buf.subarray(10, 26), iv = buf.subarray(26, 38), ciphertext = buf.subarray(38);
const material = await subtle.importKey("raw", new TextEncoder().encode(`${args.secret}:${args.pin}`), "PBKDF2", false, ["deriveKey", "deriveBits"]);
const photoKey = await subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
const jpeg = Buffer.from(await subtle.decrypt({ name: "AES-GCM", iv }, photoKey, ciphertext));
// The ClearKey key: 16 bytes from PBKDF2 of the same password with a fixed, public salt. The page derives the same.
const ckSalt = new TextEncoder().encode("ccs-clearkey-v1");
const key = Buffer.from(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: ckSalt, iterations: 100000 }, material, 128));
const kid = createHash("sha256").update(`ccs-clearkey-kid:${args.secret}`).digest().subarray(0, 16);
const tmp = await (await import("node:fs/promises")).mkdtemp(path.join(os.tmpdir(), "ccs-ck-"));
const jpg = path.join(tmp, "photo.jpg"); await writeFile(jpg, jpeg);
const outDir = "web/research/clearkey"; await mkdir(outDir, { recursive: true });
const out = path.join(outDir, "video.mp4");
await run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-loop", "1", "-i", jpg, "-t", "2", "-r", "15", "-vf", "scale=720:-2", "-c:v", "libx264", "-profile:v", "main", "-level", "3.1", "-pix_fmt", "yuv420p", "-g", "15",
  "-movflags", "frag_keyframe+empty_moov+default_base_moof", "-encryption_scheme", "cenc-aes-ctr", "-encryption_key", key.toString("hex"), "-encryption_kid", kid.toString("hex"), out]);
await rm(tmp, { recursive: true, force: true });
const { stdout } = await run("ffprobe", ["-hide_banner", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name,profile,level,width,height", "-of", "json", out]);
const st = JSON.parse(stdout).streams[0];
const profileHex = { Baseline: "42", Main: "4d", High: "64" }[st.profile] || "4d";
const level = Number(st.level) > 0 ? Number(st.level) : 31;   // ffprobe cannot read the level of an encrypted stream; the encode asked for 3.1
const codecs = `avc1.${profileHex}00${level.toString(16).padStart(2, "0")}`;
const b64url = (b) => Buffer.from(b).toString("base64url");
const info = { kid: b64url(kid), codecs, width: st.width, height: st.height, bytes: (await readFile(out)).length, keyDerivation: "PBKDF2-SHA256(secret:pin, salt 'ccs-clearkey-v1', 100000) → 16 bytes" };
await writeFile(path.join(outDir, "info.json"), JSON.stringify(info, null, 2) + "\n");
console.log(JSON.stringify(info));
