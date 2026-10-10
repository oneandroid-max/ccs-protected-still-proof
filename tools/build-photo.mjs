#!/usr/bin/env node
// tools/build-photo.mjs — make the screen-sized derivative of the portrait and encrypt it.
//
//   node tools/build-photo.mjs --in=<portrait.jpg> --out=photo.enc [--long=1600] [--quality=86]
//                              [--iterations=200000] [--secret=<base64url>] [--pin=<6 digits>]
//
// Output file layout (big-endian):
//   bytes 0-4   "CCSP1"              magic
//   byte  5     1                    version
//   bytes 6-9   uint32               PBKDF2 iterations
//   bytes 10-25 16 bytes             PBKDF2 salt
//   bytes 26-37 12 bytes             AES-GCM IV
//   bytes 38-   AES-256-GCM ciphertext of the JPEG, GCM tag appended (WebCrypto layout)
// The key is PBKDF2-SHA256(secret + ":" + pin, salt, iterations) → AES-GCM 256.
// The secret and the PIN are printed ONCE here and never written to the repository.
import sharp from "sharp";
import { writeFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { performance } from "node:perf_hooks";

const { subtle } = webcrypto;
const getRandomValues = (a) => webcrypto.getRandomValues(a);
const args = {};
for (const a of process.argv.slice(2)) {
  const m = a.match(/^--([^=]+)(?:=(.*))?$/);
  if (m) args[m[1]] = m[2] === undefined ? true : m[2];
}
if (!args.in) { console.error("usage: --in=<jpg> [--out=photo.enc] [--long=1600] [--quality=86] [--iterations=200000] [--secret=] [--pin=]"); process.exit(2); }

const out = args.out || "photo.enc";
const longEdge = Number(args.long || 1600);
const quality = Number(args.quality || 86);
const iterations = Number(args.iterations || 200000);
const b64url = (u8) => Buffer.from(u8).toString("base64url");
const secret = args.secret || b64url(getRandomValues(new Uint8Array(16)));
const pin = args.pin || String(100000 + (getRandomValues(new Uint32Array(1))[0] % 900000));
if (!/^\d{6}$/.test(pin)) { console.error("the PIN must be 6 digits"); process.exit(2); }

const t0 = performance.now();
const jpeg = await sharp(args.in)
  .rotate()
  .resize({ width: longEdge, height: longEdge, fit: "inside", withoutEnlargement: true })
  .jpeg({ quality, mozjpeg: true })
  .toBuffer();
const meta = await sharp(jpeg).metadata();
const t1 = performance.now();

const salt = getRandomValues(new Uint8Array(16));
const iv = getRandomValues(new Uint8Array(12));
const material = await subtle.importKey("raw", new TextEncoder().encode(`${secret}:${pin}`), "PBKDF2", false, ["deriveKey"]);
const key = await subtle.deriveKey(
  { name: "PBKDF2", hash: "SHA-256", salt, iterations },
  material, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
);
const t2 = performance.now();
const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, jpeg));
const t3 = performance.now();

const header = new Uint8Array(38);
header.set(new TextEncoder().encode("CCSP1"), 0);
header[5] = 1;
new DataView(header.buffer).setUint32(6, iterations);
header.set(salt, 10);
header.set(iv, 26);
const file = new Uint8Array(header.length + ciphertext.length);
file.set(header, 0);
file.set(ciphertext, header.length);
await writeFile(out, file);

console.log(JSON.stringify({
  input: args.in,
  derivative: { width: meta.width, height: meta.height, bytes: jpeg.length, quality },
  out, bytes: file.length, headerBytes: header.length, iterations,
  timingsMs: { resize: Math.round(t1 - t0), pbkdf2: Math.round(t2 - t1), encrypt: Math.round(t3 - t2) },
  saltHex: Buffer.from(salt).toString("hex"),
  // Printed once, never committed. Hand these to the viewer out of band.
  secret, pin,
}, null, 2));
