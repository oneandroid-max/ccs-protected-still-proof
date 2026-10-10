#!/usr/bin/env node
// tools/cross-check.mjs — the JavaScript side of every port's cross-check: decrypt a CCSP1 file the way
// viewer.js does and print the same facts, so the Java, C and Swift ports can be compared byte for byte.
//
//   node tools/cross-check.mjs --file=photo.enc --secret=<s> --pin=<p> --hour=<YYYY-MM-DDTHH> [--canonical]
//
// Without --canonical: two JSON lines (the facts, then the wrong-PIN result). With --canonical: the one
// line every port must print identically, which CI diffs against tests/vectors/expected.txt:
//   ccs-vector-v1 plainBytes=… plainSha256=… jpegMagic=ffd8ff markId=… patternSha256=… patternPlusOnes=… markedRampSha256=… wrongPin=refused
// markedRampSha256 is the mark applied to a synthetic 300×200 RGB ramp (R=x, G=y, B=x+y, each mod 256)
// and hashed in RGB row order: it checks the clamping arithmetic without depending on a JPEG decoder,
// because decoders differ by ±1 between platforms and decoded pixels are never compared across them.
import { readFile } from "node:fs/promises";
import { webcrypto, createHash } from "node:crypto";
import { markSeed, tilePattern, markId, TILE, MARK_AMPLITUDE } from "../mark.js";

const args = {};
for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)(?:=(.*))?$/); if (m) args[m[1]] = m[2] === undefined ? true : m[2]; }
if (!args.file || !args.secret || !args.pin || !args.hour) { console.error("usage: --file= --secret= --pin= --hour= [--canonical]"); process.exit(2); }

const buf = new Uint8Array(await readFile(args.file));
if (String.fromCharCode(...buf.subarray(0, 5)) !== "CCSP1" || buf[5] !== 1) throw new Error("not a CCSP1 file");
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const iterations = dv.getUint32(6), salt = buf.subarray(10, 26), iv = buf.subarray(26, 38), ciphertext = buf.subarray(38);
const { subtle } = webcrypto;
async function derive(pin) {
  const material = await subtle.importKey("raw", new TextEncoder().encode(`${args.secret}:${pin}`), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
const sha = (u8) => createHash("sha256").update(u8).digest("hex");

// The same arithmetic as applyMark() in viewer.js: ±MARK_AMPLITUDE on R, G and B, clamped by the array.
function applyMark(data, W, H, pattern) {
  for (let y = 0; y < H; y++) {
    const row = (y % TILE) * TILE;
    let i = y * W * 4;
    for (let x = 0; x < W; x++, i += 4) {
      const m = MARK_AMPLITUDE * pattern[row + (x % TILE)];
      data[i] += m; data[i + 1] += m; data[i + 2] += m;
    }
  }
}
function markedRampSha256(pattern) {
  const W = 300, H = 200;
  const rgba = new Uint8ClampedArray(W * H * 4);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const i = (y * W + x) * 4;
    rgba[i] = x & 255; rgba[i + 1] = y & 255; rgba[i + 2] = (x + y) & 255; rgba[i + 3] = 255;
  }
  applyMark(rgba, W, H, pattern);
  const rgb = Buffer.alloc(W * H * 3);
  for (let p = 0; p < W * H; p++) { rgb[p * 3] = rgba[p * 4]; rgb[p * 3 + 1] = rgba[p * 4 + 1]; rgb[p * 3 + 2] = rgba[p * 4 + 2]; }
  return sha(rgb);
}

const t0 = performance.now();
const key = await derive(args.pin);
const t1 = performance.now();
const plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
const t2 = performance.now();
const seed = await markSeed(args.secret, args.pin, args.hour);
const pattern = tilePattern(seed);
let plus = 0; for (const p of pattern) if (p === 1) plus++;
const facts = {
  iterations, plainBytes: plain.length, plainSha256: sha(plain), jpegMagic: Buffer.from(plain.subarray(0, 3)).toString("hex"),
  pbkdf2Ms: Math.round((t1 - t0) * 100) / 100, decryptMs: Math.round((t2 - t1) * 100) / 100, bucket: args.hour,
  markId: markId(seed), patternSha256: sha(new Uint8Array(pattern.buffer)), patternPlusOnes: plus,
  markedRampSha256: markedRampSha256(pattern),
};
const wrong = args.pin === "000000" ? "111111" : "000000";
let wrongResult;
try { await subtle.decrypt({ name: "AES-GCM", iv }, await derive(wrong), ciphertext); wrongResult = "DECRYPTED"; }
catch (e) { wrongResult = "refused"; }

if (args.canonical) {
  console.log(`ccs-vector-v1 plainBytes=${facts.plainBytes} plainSha256=${facts.plainSha256} jpegMagic=${facts.jpegMagic} markId=${facts.markId} patternSha256=${facts.patternSha256} patternPlusOnes=${facts.patternPlusOnes} markedRampSha256=${facts.markedRampSha256} wrongPin=${wrongResult}`);
} else {
  console.log(JSON.stringify(facts));
  console.log(JSON.stringify({ wrongPin: wrong, result: wrongResult }));
}
if (wrongResult !== "refused") process.exit(1);
