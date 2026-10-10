// viewer.js — the proof page's engine. Plain browser APIs only; no library, no service.
// What it does and cannot do is written on the page and in README.md. Every readout value here is
// measured by this code on this device; nothing is echoed from a setting.
import { TILE, MARK_AMPLITUDE, hourBucket, markSeed, tilePattern, markId, xorshift128 } from "../mark.js";

const $ = (id) => document.getElementById(id);
const el = {
  pin: $("pin"), show: $("show"), msg: $("msg"), canvas: $("proof"), stage: $("stage"),
  stop: $("stop"), share: $("share"), testStill: $("test-still"),
  r: {
    pin: $("r-pin"), mode: $("r-mode"), fps: $("r-fps"), playing: $("r-playing"), canvas: $("r-canvas"),
    dpr: $("r-dpr"), motion: $("r-motion"), mark: $("r-mark"), amp: $("r-amp"), time: $("r-time"),
  },
};

const params = new URLSearchParams(location.search);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const AMP = clamp(parseInt(params.get("a") || "48", 10) || 48, 8, 96);   // noise amplitude, 0-255 scale
const FPS_FLOOR = 50;                                                     // below this the alternation is off
const MEASURE_MS = 1500;                                                  // how long the frame rate is measured
const FPS_CAP = clamp(parseInt(params.get("fpscap") || "0", 10) || 0, 0, 240); // verification only
const TEST = params.get("test") === "1";                                  // verification only: shows the marked still too
const MAX_PIXELS = 4_200_000;                                             // keeps canvases inside phone limits
const secret = new URLSearchParams(location.hash.replace(/^#/, "")).get("k") || "";
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

const S = {
  bitmap: null, still: null, frames: null, usePut: false,
  mode: "idle", fps: null, running: false, wasRunning: false, raf: 0, timer: 0, flip: 0,
  W: 0, H: 0, cssW: 0, cssH: 0, pattern: null, bucket: "", pin: "",
};
const ctx = el.canvas.getContext("2d", { alpha: false });

// ---------- readout ----------
function setText(node, text) { if (node) node.textContent = text; }
function now() { const d = new Date(); return d.toLocaleString() + " (" + Intl.DateTimeFormat().resolvedOptions().timeZone + ")"; }
function readoutStatic() {
  setText(el.r.dpr, String(window.devicePixelRatio || 1));
  setText(el.r.motion, reducedMotion ? "reduce (system setting)" : "no preference");
  setText(el.r.amp, `${AMP} of 255`);
  setText(el.r.time, now());
}
function setMode(text) { S.mode = text; setText(el.r.mode, text); }

// ---------- the encrypted file ----------
function parseHeader(buf) {
  const magic = String.fromCharCode(...buf.subarray(0, 5));
  if (magic !== "CCSP1" || buf[5] !== 1) throw new Error("not a CCSP1 file");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    iterations: dv.getUint32(6),
    salt: buf.subarray(10, 26),
    iv: buf.subarray(26, 38),
    ciphertext: buf.subarray(38),
  };
}
async function deriveKey(secretValue, pin, salt, iterations) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(`${secretValue}:${pin}`), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}

// ---------- pixels ----------
function applyMark(data, W, H, pattern) {
  for (let y = 0; y < H; y++) {
    const row = (y % TILE) * TILE;
    let i = y * W * 4;
    for (let x = 0; x < W; x++, i += 4) {
      const m = MARK_AMPLITUDE * pattern[row + (x % TILE)];
      data[i] += m; data[i + 1] += m; data[i + 2] += m;   // Uint8ClampedArray clamps for us
    }
  }
}
function buildFrames(still, W, H, amp) {
  const src = still.data;
  const A = new ImageData(W, H), B = new ImageData(W, H);
  const a = A.data, b = B.data;
  const seed = crypto.getRandomValues(new Uint8Array(16));
  const next = xorshift128(seed);
  for (let i = 0; i < src.length; i += 4) {
    const r = src[i], g = src[i + 1], bl = src[i + 2];
    const lo = Math.min(r, g, bl), hi = Math.max(r, g, bl);
    const cap = Math.min(amp, lo, 255 - hi);
    const n = cap > 0 ? (next() % (2 * cap + 1)) - cap : 0;   // uniform in [-cap, cap]; both frames stay in range
    a[i] = r + n; a[i + 1] = g + n; a[i + 2] = bl + n; a[i + 3] = 255;
    b[i] = r - n; b[i + 1] = g - n; b[i + 2] = bl - n; b[i + 3] = 255;
  }
  return [A, B];
}

// ---------- rendering ----------
function sizeFor(bitmap) {
  const dpr = window.devicePixelRatio || 1;
  let cssW = Math.max(200, Math.min(el.stage.clientWidth || 360, 1200));
  let cssH = Math.round(cssW * bitmap.height / bitmap.width);
  let W = Math.round(cssW * dpr), H = Math.round(cssH * dpr);
  if (W * H > MAX_PIXELS) { const k = Math.sqrt(MAX_PIXELS / (W * H)); W = Math.round(W * k); H = Math.round(H * k); }
  return { cssW, cssH, W, H };
}
async function render() {
  const { cssW, cssH, W, H } = sizeFor(S.bitmap);
  Object.assign(S, { cssW, cssH, W, H });
  el.canvas.width = W; el.canvas.height = H;
  el.canvas.style.width = cssW + "px"; el.canvas.style.height = cssH + "px";

  const off = document.createElement("canvas"); off.width = W; off.height = H;
  const octx = off.getContext("2d", { alpha: false });
  octx.drawImage(S.bitmap, 0, 0, W, H);
  const still = octx.getImageData(0, 0, W, H);
  applyMark(still.data, W, H, S.pattern);
  S.still = still;
  const frames = buildFrames(still, W, H, AMP);
  try {
    S.frames = await Promise.all(frames.map((f) => createImageBitmap(f)));
    S.usePut = false;
  } catch {
    S.frames = frames; S.usePut = true;            // older engines: draw the pixels directly
  }
  setText(el.r.canvas, `${W}×${H} device pixels (${cssW}×${cssH} CSS pixels)`);
  if (TEST && el.testStill) {
    el.testStill.hidden = false;
    el.testStill.width = W; el.testStill.height = H;
    el.testStill.style.width = cssW + "px"; el.testStill.style.height = cssH + "px";
    el.testStill.getContext("2d", { alpha: false }).putImageData(S.still, 0, 0);
  }
}
function drawFrame(i) {
  if (S.usePut) ctx.putImageData(S.frames[i], 0, 0); else ctx.drawImage(S.frames[i], 0, 0);
}
function drawStill() { ctx.putImageData(S.still, 0, 0); }

function schedule(fn) {
  if (FPS_CAP > 0) S.timer = setTimeout(() => fn(performance.now()), 1000 / FPS_CAP);
  else S.raf = requestAnimationFrame(fn);
}
function cancelScheduled() { if (S.raf) cancelAnimationFrame(S.raf); if (S.timer) clearTimeout(S.timer); S.raf = 0; S.timer = 0; }

function startAlternating() {
  cancelScheduled();
  S.running = true; S.wasRunning = true; S.flip = 0;
  let ticks = 0, t0 = 0, measured = false;
  setMode("alternating (two frames)");
  setText(el.r.fps, "measuring…");
  el.stop.textContent = "Stop the alternation";
  el.msg.hidden = true;
  const tick = (ts) => {
    if (!S.running) return;
    drawFrame(S.flip); S.flip ^= 1; ticks++;
    setText(el.r.playing, "yes");
    if (!t0) t0 = ts;
    const elapsed = ts - t0;
    if (!measured && elapsed >= MEASURE_MS) {
      measured = true;
      S.fps = Math.round(ticks * 1000 / elapsed);
      setText(el.r.fps, `${S.fps} per second, measured over ${(elapsed / 1000).toFixed(1)} s`);
      if (S.fps < FPS_FLOOR) { stillMode(`this device limits animation to about ${S.fps} frames per second`); return; }
    }
    schedule(tick);
  };
  schedule(tick);
}
function stillMode(reason) {
  cancelScheduled();
  S.running = false;
  drawStill();
  setMode(`still — ${reason}`);
  setText(el.r.playing, "yes (still)");
  el.stop.textContent = "Start the alternation";
  el.msg.hidden = true;
}

// ---------- the share card ----------
async function makeShareCard() {
  if (!S.still) return;
  const cw = 600, band = 64;
  const ch = Math.round(cw * S.H / S.W);
  const tmp = document.createElement("canvas"); tmp.width = S.W; tmp.height = S.H;
  tmp.getContext("2d", { alpha: false }).putImageData(S.still, 0, 0);
  const card = document.createElement("canvas"); card.width = cw; card.height = ch + band;
  const c = card.getContext("2d", { alpha: false });
  c.drawImage(tmp, 0, 0, cw, ch);
  const img = c.getImageData(0, 0, cw, ch);
  applyMark(img.data, cw, ch, S.pattern);            // the card carries the viewer's mark at its own size
  c.putImageData(img, 0, 0);
  c.fillStyle = "#011b51"; c.fillRect(0, ch, cw, band);
  c.fillStyle = "#ffffff"; c.font = "600 18px system-ui, sans-serif";
  c.fillText("Candid Color Systems", 16, ch + 27);
  c.font = "14px system-ui, sans-serif";
  c.fillText("Shared with the family · gallery: (your gallery link here) · marked to its viewer", 16, ch + 50);
  const blob = await new Promise((res) => card.toBlob(res, "image/jpeg", 0.9));
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "share-card.jpg";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ---------- the flow ----------
async function show() {
  const pin = (el.pin.value || "").trim();
  if (!/^\d{6}$/.test(pin)) { el.msg.hidden = false; el.msg.textContent = "Type the 6-digit PIN."; return; }
  if (!secret) { el.msg.hidden = false; el.msg.textContent = "This link is missing its key (the part after #k=)."; return; }
  el.show.disabled = true;
  el.msg.hidden = false; el.msg.textContent = "Checking the PIN…";
  let plain;
  try {
    const res = await fetch("../photo.enc", { cache: "no-store" });
    if (!res.ok) throw new Error("photo.enc " + res.status);
    const file = parseHeader(new Uint8Array(await res.arrayBuffer()));
    const t0 = performance.now();
    const key = await deriveKey(secret, pin, file.salt, file.iterations);
    const t1 = performance.now();
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: file.iv }, key, file.ciphertext);
    setText(el.r.pin, `accepted (key derived in ${Math.round(t1 - t0)} ms, ${file.iterations.toLocaleString()} rounds)`);
  } catch (e) {
    setText(el.r.pin, "refused");
    el.msg.textContent = "That PIN does not open this photo.";
    el.show.disabled = false;
    return;
  }
  S.pin = pin;
  S.bucket = hourBucket(new Date());
  const seed = await markSeed(secret, pin, S.bucket);
  S.pattern = tilePattern(seed);
  setText(el.r.mark, `${markId(seed)} · hour ${S.bucket} UTC`);
  S.bitmap = await createImageBitmap(new Blob([plain], { type: "image/jpeg" }));
  plain = null;
  el.msg.textContent = "Preparing the frames…";
  await render();
  el.stop.disabled = false; el.share.disabled = false;
  if (reducedMotion) stillMode("reduced motion is on in this device's settings");
  else startAlternating();
  setText(el.r.time, now());
}

el.show.addEventListener("click", show);
el.pin.addEventListener("keydown", (e) => { if (e.key === "Enter") show(); });
el.stop.addEventListener("click", () => { if (S.running) stillMode("stopped by the viewer"); else startAlternating(); });
el.share.addEventListener("click", makeShareCard);
for (const ev of ["contextmenu", "dragstart"]) el.canvas.addEventListener(ev, (e) => e.preventDefault());
document.addEventListener("visibilitychange", () => {
  if (!S.bitmap) return;
  if (document.hidden) { if (S.running) { cancelScheduled(); S.running = false; setMode("paused (page hidden)"); } }
  else if (S.wasRunning && !reducedMotion && !S.running && S.mode.startsWith("paused")) startAlternating();
});
let resizeTimer = 0;
window.addEventListener("resize", () => {
  if (!S.bitmap) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(async () => {
    const { cssW } = sizeFor(S.bitmap);
    if (Math.abs(cssW - S.cssW) / S.cssW < 0.1) return;
    const keepRunning = S.running;
    cancelScheduled(); S.running = false;
    await render();
    if (keepRunning) startAlternating(); else drawStill();
  }, 300);
});
window.addEventListener("pagehide", () => { cancelScheduled(); if (S.bitmap) S.bitmap.close(); });
readoutStatic();
setInterval(() => setText(el.r.time, now()), 30000);
