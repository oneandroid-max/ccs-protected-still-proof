// web/research/decoy/decoy.js — research candidate 9: the decoy frame.
// Frame A = P + D, frame B = P − D, D a structured, multi-scale, block-balanced pattern at large amplitude,
// capped per pixel by the photo's headroom (|D| ≤ min(P, 255 − P) per channel, so both frames stay in range
// and average exactly to P). The eye blends A and B; a single frame is P under a pattern that a blur does not
// remove, because the pattern has coarse structure too; the balance within every block keeps any area's
// brightness constant between frames. Plain browser APIs; the photo is decrypted with the link key and PIN.
import { TILE, MARK_AMPLITUDE, hourBucket, markSeed, tilePattern, markId, xorshift128 } from "../../../mark.js";

const $ = (id) => document.getElementById(id);
const set = (id, t) => { $(id).textContent = t; };
const params = new URLSearchParams(location.search);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const AMP = clamp(parseInt(params.get("a") || "110", 10) || 110, 16, 127);
const BLOCK = clamp(parseInt(params.get("s") || "32", 10) || 32, 8, 128);
const secret = new URLSearchParams(location.hash.replace(/^#/, "")).get("k") || "";
const canvas = $("proof"), ctx = canvas.getContext("2d", { alpha: false }), stage = $("stage");
const S = { P: null, A: null, B: null, W: 0, H: 0, running: false, raf: 0, flip: 0, ticks: 0, t0: 0, fps: null, guardUntil: 0, markId: "-" };
set("r-time", new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC");
set("r-pat", `amplitude ${AMP} of 255, balanced within ${BLOCK} px blocks, scales ${BLOCK}/${BLOCK / 2}/${BLOCK / 4}/${BLOCK / 8} px`);

function parseHeader(buf) {
  if (String.fromCharCode(...buf.subarray(0, 5)) !== "CCSP1" || buf[5] !== 1) throw new Error("not a CCSP1 file");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return { iterations: dv.getUint32(6), salt: buf.subarray(10, 26), iv: buf.subarray(26, 38), ciphertext: buf.subarray(38) };
}
async function decryptPhoto(pin) {
  const file = new Uint8Array(await (await fetch("../../../photo.enc", { cache: "force-cache" })).arrayBuffer());
  const h = parseHeader(file);
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(`${secret}:${pin}`), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: h.salt, iterations: h.iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  return createImageBitmap(new Blob([await crypto.subtle.decrypt({ name: "AES-GCM", iv: h.iv }, key, h.ciphertext)], { type: "image/jpeg" }));
}

/** The decoy pattern: a sum of block noises at four scales, then made zero-mean within every BLOCK×BLOCK block. */
function buildPattern(W, H, next) {
  const D = new Float32Array(W * H);
  const scales = [BLOCK, BLOCK / 2, BLOCK / 4, BLOCK / 8], weights = [0.4, 0.3, 0.2, 0.1];
  scales.forEach((s, k) => {
    const cols = Math.ceil(W / s), rows = Math.ceil(H / s), cells = new Float32Array(cols * rows);
    for (let i = 0; i < cells.length; i++) cells[i] = ((next() >>> 8) / 16777216) * 2 - 1;   // uniform in [-1, 1)
    for (let y = 0; y < H; y++) { const r = Math.floor(y / s) * cols; for (let x = 0; x < W; x++) D[y * W + x] += weights[k] * cells[r + Math.floor(x / s)]; }
  });
  // balance: zero mean within every BLOCK×BLOCK block, so no area changes brightness between the two frames
  for (let by = 0; by < H; by += BLOCK) for (let bx = 0; bx < W; bx += BLOCK) {
    let sum = 0, n = 0;
    for (let y = by; y < Math.min(H, by + BLOCK); y++) for (let x = bx; x < Math.min(W, bx + BLOCK); x++) { sum += D[y * W + x]; n++; }
    const m = sum / n;
    for (let y = by; y < Math.min(H, by + BLOCK); y++) for (let x = bx; x < Math.min(W, bx + BLOCK); x++) D[y * W + x] -= m;
  }
  let peak = 0; for (let i = 0; i < D.length; i++) peak = Math.max(peak, Math.abs(D[i]));
  for (let i = 0; i < D.length; i++) D[i] = D[i] / peak * AMP;
  return D;
}
function buildFrames(P, W, H, D) {
  const A = new ImageData(W, H), B = new ImageData(W, H), p = P.data, a = A.data, b = B.data;
  let se = 0;
  for (let i = 0, px = 0; i < p.length; i += 4, px++) {
    // the same offset on R, G and B (brightness only), capped by the headroom of the pixel's channels
    const lo = Math.min(p[i], p[i + 1], p[i + 2]), hi = Math.max(p[i], p[i + 1], p[i + 2]);
    const cap = Math.min(lo, 255 - hi);
    const d = Math.max(-cap, Math.min(cap, D[px]));
    a[i] = p[i] + d; a[i + 1] = p[i + 1] + d; a[i + 2] = p[i + 2] + d; a[i + 3] = 255;
    b[i] = p[i] - d; b[i + 1] = p[i + 1] - d; b[i + 2] = p[i + 2] - d; b[i + 3] = 255;
    se += d * d * 3;
  }
  const mse = se / (p.length / 4 * 3);
  return { A, B, psnr: mse ? 10 * Math.log10(255 * 255 / mse) : Infinity, rms: Math.sqrt(mse) };
}
function applyMark(data, W, H, pattern) {
  for (let y = 0; y < H; y++) { const row = (y % TILE) * TILE; let i = y * W * 4; for (let x = 0; x < W; x++, i += 4) { const m = MARK_AMPLITUDE * pattern[row + (x % TILE)]; data[i] += m; data[i + 1] += m; data[i + 2] += m; } }
}

async function show() {
  const pin = $("pin").value.trim();
  if (!/^\d{6}$/.test(pin) || !secret) { set("r-pin", "type the 6-digit PIN; the key must be in the link"); return; }
  let bmp;
  try { bmp = await decryptPhoto(pin); set("r-pin", "accepted"); } catch { set("r-pin", "refused"); $("msg").textContent = "Wrong PIN or link key: nothing to show."; return; }
  const dpr = devicePixelRatio || 1, cssW = Math.max(200, Math.min(stage.clientWidth || 360, 1200)), cssH = Math.round(cssW * bmp.height / bmp.width);
  let W = Math.round(cssW * dpr), H = Math.round(cssH * dpr);
  if (W * H > 4_200_000) { const k = Math.sqrt(4_200_000 / (W * H)); W = Math.round(W * k); H = Math.round(H * k); }
  canvas.width = W; canvas.height = H; canvas.style.width = cssW + "px"; canvas.style.height = cssH + "px";
  const off = new OffscreenCanvas(W, H), octx = off.getContext("2d", { alpha: false });
  octx.drawImage(bmp, 0, 0, W, H); bmp.close();
  const P = octx.getImageData(0, 0, W, H);
  const seed = await markSeed(secret, pin, hourBucket(new Date()));
  applyMark(P.data, W, H, tilePattern(seed)); S.markId = markId(seed); set("r-mark", S.markId);
  const D = buildPattern(W, H, xorshift128(seed));
  const f = buildFrames(P, W, H, D);
  S.P = P; S.A = f.A; S.B = f.B; S.W = W; S.H = H;
  set("r-psnr", `${f.psnr.toFixed(1)} dB, pattern RMS ${f.rms.toFixed(1)} of 255 after the headroom cap`);
  $("msg").textContent = ""; $("stop").disabled = false;
  start();
}
function start() {
  S.running = true; S.ticks = 0; S.t0 = performance.now(); S.fps = null; set("r-mode", "alternating (decoy frames)");
  const loop = (t) => {
    if (!S.running) return;
    if (t < S.guardUntil) { ctx.fillStyle = "#000"; ctx.fillRect(0, 0, S.W, S.H); }
    else { ctx.putImageData(S.flip ? S.B : S.A, 0, 0); S.flip ^= 1; }
    S.ticks++;
    if (S.fps === null && t - S.t0 >= 1500) { S.fps = Math.round(S.ticks / ((t - S.t0) / 1000)); set("r-fps", `${S.fps} per second, measured over 1.5 s` + (S.fps < 100 ? " (below 100: the flicker is visible on this screen; a 120 Hz screen is the target)" : "")); }
    S.raf = requestAnimationFrame(loop);
  };
  S.raf = requestAnimationFrame(loop);
}
function stop() { S.running = false; cancelAnimationFrame(S.raf); if (S.P) ctx.putImageData(S.P, 0, 0); set("r-mode", "still (stopped): the photo, marked"); }
$("show").addEventListener("click", show);
$("stop").addEventListener("click", stop);
document.addEventListener("visibilitychange", () => { if (document.hidden && S.running) { S.running = false; cancelAnimationFrame(S.raf); } else if (!document.hidden && S.A && !S.running && $("r-mode").textContent.startsWith("alternating")) start(); });

// touch guard: three fingers or a palm-sized touch blanks the photo at once
const guard = (e) => {
  const big = [...e.touches].some((t) => (t.radiusX || 0) > 30 || (t.radiusY || 0) > 30);
  if (e.touches.length >= 3 || big) { S.guardUntil = performance.now() + 1500; set("r-guard", `${e.touches.length} touches${big ? ", palm-sized" : ""} at ${new Date().toISOString().slice(11, 19)} UTC: blanked for 1.5 s`); }
};
stage.addEventListener("touchstart", guard, { passive: true });
stage.addEventListener("touchmove", guard, { passive: true });
stage.addEventListener("contextmenu", (e) => e.preventDefault());
