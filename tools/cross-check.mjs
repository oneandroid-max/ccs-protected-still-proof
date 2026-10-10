#!/usr/bin/env node
// tools/cross-check.mjs — the JavaScript side of android/tools/CrossCheck.java: decrypt photo.enc the way
// viewer.js does and print the same facts, so the Java port can be compared byte for byte.
//   node tools/cross-check.mjs --file=photo.enc --secret=<s> --pin=<p> --hour=<YYYY-MM-DDTHH>
import { readFile } from "node:fs/promises";
import { webcrypto, createHash } from "node:crypto";
import { markSeed, tilePattern, markId } from "../mark.js";

const args = {};
for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)(?:=(.*))?$/); if (m) args[m[1]] = m[2] === undefined ? true : m[2]; }
if (!args.file || !args.secret || !args.pin || !args.hour) { console.error("usage: --file= --secret= --pin= --hour="); process.exit(2); }

const buf = new Uint8Array(await readFile(args.file));
if (String.fromCharCode(...buf.subarray(0, 5)) !== "CCSP1" || buf[5] !== 1) throw new Error("not a CCSP1 file");
const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
const iterations = dv.getUint32(6), salt = buf.subarray(10, 26), iv = buf.subarray(26, 38), ciphertext = buf.subarray(38);
const { subtle } = webcrypto;
async function derive(pin) {
  const material = await subtle.importKey("raw", new TextEncoder().encode(`${args.secret}:${pin}`), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
const t0 = performance.now();
const key = await derive(args.pin);
const t1 = performance.now();
const plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
const t2 = performance.now();
const seed = await markSeed(args.secret, args.pin, args.hour);
const pattern = tilePattern(seed);
let plus = 0; for (const p of pattern) if (p === 1) plus++;
const sha = (u8) => createHash("sha256").update(u8).digest("hex");
console.log(JSON.stringify({
  iterations, plainBytes: plain.length, plainSha256: sha(plain), jpegMagic: Buffer.from(plain.subarray(0, 3)).toString("hex"),
  pbkdf2Ms: Math.round((t1 - t0) * 100) / 100, decryptMs: Math.round((t2 - t1) * 100) / 100, bucket: args.hour,
  markId: markId(seed), patternSha256: sha(new Uint8Array(pattern.buffer)), patternPlusOnes: plus,
}));
const wrong = args.pin === "000000" ? "111111" : "000000";
try { await subtle.decrypt({ name: "AES-GCM", iv }, await derive(wrong), ciphertext); console.log(JSON.stringify({ wrongPin: wrong, result: "DECRYPTED — FAIL" })); process.exit(1); }
catch (e) { console.log(JSON.stringify({ wrongPin: wrong, result: `refused (${e.name})` })); }
