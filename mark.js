// mark.js — the viewer mark shared by the page (viewer.js) and the detector (tools/detect-mark.mjs).
// A seeded ±1 tile pattern. The seed is SHA-256 of the link secret, the PIN and the UTC hour, so a
// capture can be traced to the viewer who was shown the photo and to the hour it was shown.
// Nothing here is secret: the pattern is only as private as the secret and PIN that seed it.

export const TILE = 128;            // the pattern repeats every 128 device pixels
export const MARK_AMPLITUDE = 3;    // ±3 of 255 on every channel: invisible on a photo, recoverable by correlation

const enc = new TextEncoder();

export async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

/** "YYYY-MM-DDTHH" in UTC — the hour bucket a view is keyed to. */
export function hourBucket(date) {
  return date.toISOString().slice(0, 13);
}

/** 32-byte seed from the three things that name a viewing: the link secret, the PIN, the hour. */
export async function markSeed(secret, pin, bucket) {
  return sha256(enc.encode(`ccs-mark-v1:${secret}:${pin}:${bucket}`));
}

/** Marsaglia xorshift128 over the first 16 seed bytes; identical in the browser and in Node. */
export function xorshift128(seed) {
  const dv = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);
  let x = dv.getUint32(0) || 0x9e3779b9;
  let y = dv.getUint32(4) || 0x243f6a88;
  let z = dv.getUint32(8) || 0xb7e15162;
  let w = dv.getUint32(12) || 0x6a09e667;
  return function next() {
    const t = (x ^ (x << 11)) >>> 0;
    x = y; y = z; z = w;
    w = ((w ^ (w >>> 19)) ^ (t ^ (t >>> 8))) >>> 0;
    return w;
  };
}

/** The TILE×TILE pattern of +1 / −1 for a seed. Index = (y % TILE) * TILE + (x % TILE). */
export function tilePattern(seed, size = TILE) {
  const next = xorshift128(seed);
  const p = new Int8Array(size * size);
  for (let i = 0; i < p.length; i++) p[i] = ((next() >>> 16) & 1) ? 1 : -1;
  return p;
}

/** Eight hex characters that identify a seed on the page's readout without revealing it. */
export function markId(seed) {
  let s = "";
  for (let i = 0; i < 4; i++) s += seed[i].toString(16).padStart(2, "0");
  return s;
}
