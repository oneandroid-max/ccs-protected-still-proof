#!/usr/bin/env node
// tools/detect-mark.mjs — recover the viewer mark from a captured image.
//
//   node tools/detect-mark.mjs --image=<png|jpg> --secret=<base64url> --pin=<6 digits> \
//        [--hour=YYYY-MM-DDTHH] [--hours=1] [--crop=x,y,w,h] [--phase=search|0] [--wrong=5] [--json]
//
// Method: luminance of the photo area, high-pass filtered (minus a 5×5 box blur) so the picture
// itself drops out, then correlated with the ±1 tile pattern for a candidate seed. The score is a
// z-value: the correlation sum divided by its standard deviation under the null hypothesis of no
// mark (σ_residual · √N). A right key scores far above 8; wrong keys stay within about ±3.
// --phase=search finds the tile offset on a 256×256 patch (a capture does not start at the canvas
// origin); --phase=0 assumes the image starts at the canvas origin (the share card, a canvas
// element screenshot).
import sharp from "sharp";
import { markSeed, tilePattern, markId, TILE } from "../mark.js";

const args = {};
for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)(?:=(.*))?$/); if (m) args[m[1]] = m[2] === undefined ? true : m[2]; }
if (!args.image || !args.secret || !args.pin) { console.error("usage: --image=<file> --secret=<s> --pin=<p> [--hour=] [--hours=1] [--crop=x,y,w,h] [--phase=search|0] [--wrong=5]"); process.exit(2); }

const { data, info } = await sharp(args.image).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
let W = info.width, H = info.height, x0 = 0, y0 = 0;
if (args.crop) { const [cx, cy, cw, ch] = args.crop.split(",").map(Number); x0 = cx; y0 = cy; W = cw; H = ch; }
const N = W * H;

// luminance of the crop
const lum = new Float32Array(N);
for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
  const i = ((y + y0) * info.width + (x + x0)) * 4;
  lum[y * W + x] = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
}
// high-pass: subtract a 5×5 box blur (separable)
const tmp = new Float32Array(N), res = new Float32Array(N);
for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
  let s = 0, c = 0;
  for (let k = -2; k <= 2; k++) { const xx = x + k; if (xx >= 0 && xx < W) { s += lum[y * W + xx]; c++; } }
  tmp[y * W + x] = s / c;
}
let mean = 0;
for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
  let s = 0, c = 0;
  for (let k = -2; k <= 2; k++) { const yy = y + k; if (yy >= 0 && yy < H) { s += tmp[yy * W + x]; c++; } }
  const v = lum[y * W + x] - s / c; res[y * W + x] = v; mean += v;
}
mean /= N;
let varSum = 0; for (let i = 0; i < N; i++) { const d = res[i] - mean; varSum += d * d; }
const sigma = Math.sqrt(varSum / N) || 1;

function correlate(pattern, dx, dy, px0, py0, pw, ph) {
  let s = 0;
  for (let y = py0; y < py0 + ph; y++) {
    const row = ((y + dy) % TILE) * TILE;
    for (let x = px0; x < px0 + pw; x++) s += (res[y * W + x] - mean) * pattern[row + ((x + dx) % TILE)];
  }
  return s;
}
function zScore(pattern, dx, dy) { return correlate(pattern, dx, dy, 0, 0, W, H) / (sigma * Math.sqrt(N)); }
function searchPhase(pattern) {
  const pw = Math.min(256, W), ph = Math.min(256, H);
  const px0 = Math.floor((W - pw) / 2), py0 = Math.floor((H - ph) / 2);
  let best = { dx: 0, dy: 0, s: -Infinity };
  for (let dy = 0; dy < TILE; dy++) for (let dx = 0; dx < TILE; dx++) {
    const s = correlate(pattern, dx, dy, px0, py0, pw, ph);
    if (s > best.s) best = { dx, dy, s };
  }
  return best;
}

const hours = Number(args.hours ?? 1);
const base = args.hour ? new Date(args.hour + ":00:00Z") : new Date();
const buckets = [];
for (let h = -hours; h <= hours; h++) buckets.push(new Date(base.getTime() + h * 3600_000).toISOString().slice(0, 13));
const wrongCount = Number(args.wrong ?? 5);
const results = [];
async function evaluate(label, pin, bucket) {
  const seed = await markSeed(args.secret, pin, bucket);
  const pattern = tilePattern(seed);
  let dx = 0, dy = 0;
  if ((args.phase || "search") === "search") { const b = searchPhase(pattern); dx = b.dx; dy = b.dy; }
  const z = zScore(pattern, dx, dy);
  results.push({ label, pin, hour: bucket, markId: markId(seed), phase: { dx, dy }, z: Math.round(z * 100) / 100 });
}
for (const b of buckets) await evaluate("right-key", args.pin, b);
for (let k = 0; k < wrongCount; k++) {
  let wrong; do { wrong = String(100000 + Math.floor(Math.random() * 900000)); } while (wrong === args.pin);
  await evaluate("wrong-pin", wrong, buckets[hours]);
}
const summary = {
  image: args.image, size: { width: info.width, height: info.height }, crop: { x: x0, y: y0, w: W, h: H },
  residualSigma: Math.round(sigma * 100) / 100, pixels: N, results,
  verdict: {
    bestRight: Math.max(...results.filter((r) => r.label === "right-key").map((r) => r.z)),
    maxAbsWrong: Math.max(0, ...results.filter((r) => r.label === "wrong-pin").map((r) => Math.abs(r.z))),
  },
};
// Wrong keys are not N(0,1) on a clean still: every tile shares the 128-pixel period, so the
// cross-correlation of two tiles adds coherently and wrong keys can reach about ±4. The verdict
// therefore asks for a right-key score far above both a floor and the wrong-key spread.
summary.verdict.markRecovered = summary.verdict.bestRight > Math.max(10, 5 * summary.verdict.maxAbsWrong);
console.log(JSON.stringify(summary, null, args.json ? 0 : 2));
