// web/research/bench/bench.js — three ways of drawing the same decrypted photo, each a candidate for a
// black capture on a stock browser. Plain browser APIs only. Expected on every one: the screenshot
// shows the photo, because the page can change where and how it draws, not what the device does with
// the frame once drawn.
import { TILE, MARK_AMPLITUDE, hourBucket, markSeed, tilePattern, markId } from "../../../mark.js";

const $ = (id) => document.getElementById(id);
const secret = new URLSearchParams(location.hash.replace(/^#/, "")).get("k") || "";
const set = (id, t) => { $(id).textContent = t; };
set("r-time", new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC");

function parseHeader(buf) {
  const magic = String.fromCharCode(...buf.subarray(0, 5));
  if (magic !== "CCSP1" || buf[5] !== 1) throw new Error("not a CCSP1 file");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return { iterations: dv.getUint32(6), salt: buf.subarray(10, 26), iv: buf.subarray(26, 38), ciphertext: buf.subarray(38) };
}
async function decryptPhoto(pin) {
  const file = new Uint8Array(await (await fetch("../../../photo.enc", { cache: "force-cache" })).arrayBuffer());
  const h = parseHeader(file);
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(`${secret}:${pin}`), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: h.salt, iterations: h.iterations }, material, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: h.iv }, key, h.ciphertext);
  return createImageBitmap(new Blob([plain], { type: "image/jpeg" }));
}
function markedCanvas(bitmap, pin) {
  const W = Math.min(bitmap.width, 1200), H = Math.round(bitmap.height * W / bitmap.width);
  const c = document.createElement("canvas"); c.width = W; c.height = H;
  const ctx = c.getContext("2d", { alpha: false });
  ctx.drawImage(bitmap, 0, 0, W, H);
  return markSeed(secret, pin, hourBucket(new Date())).then((seed) => {
    const pattern = tilePattern(seed);
    const img = ctx.getImageData(0, 0, W, H), d = img.data;
    for (let y = 0; y < H; y++) { const row = (y % TILE) * TILE; let i = y * W * 4; for (let x = 0; x < W; x++, i += 4) { const m = MARK_AMPLITUDE * pattern[row + (x % TILE)]; d[i] += m; d[i + 1] += m; d[i + 2] += m; } }
    ctx.putImageData(img, 0, 0);
    return { canvas: c, id: markId(seed) };
  });
}
async function open() {
  const pin = $("pin").value.trim();
  if (!/^\d{6}$/.test(pin) || !secret) { set("msg", "Type the 6-digit PIN; the key must be in the link."); return null; }
  try { const bmp = await decryptPhoto(pin); set("r-pin", "accepted"); const m = await markedCanvas(bmp, pin); bmp.close(); return m; }
  catch (e) { set("r-pin", "refused"); set("msg", "Wrong PIN or link key: nothing to show."); return null; }
}
const stage = $("stage");
function show(node) { stage.replaceChildren(node); }

// 2: fullscreen with pointer lock. The canvas is drawn normally; the page then owns the screen and the pointer.
$("b-fullscreen").addEventListener("click", async () => {
  const m = await open(); if (!m) return;
  set("r-mode", "2: fullscreen + pointer lock (mark " + m.id + ")");
  show(m.canvas);
  try { await stage.requestFullscreen(); } catch (e) { set("r-fact", "fullscreen refused: " + e.message); return; }
  let lock = "pointer lock not requested";
  try { await m.canvas.requestPointerLock(); lock = "pointer locked"; } catch (e) { lock = "pointer lock refused: " + e.message; }
  set("r-fact", `fullscreen: ${document.fullscreenElement ? "yes" : "no"}; ${lock}. Take a screenshot now; press Esc to leave.`);
  document.addEventListener("fullscreenchange", () => { if (!document.fullscreenElement) set("r-fact", "left fullscreen"); }, { once: true });
});

// 3: picture-in-picture. The canvas becomes a video stream and that video is put in the system's picture-in-picture window.
$("b-pip").addEventListener("click", async () => {
  const m = await open(); if (!m) return;
  set("r-mode", "3: picture-in-picture video (mark " + m.id + ")");
  const video = document.createElement("video"); video.muted = true; video.playsInline = true; video.autoplay = true;
  // keep the canvas changing so the stream delivers frames
  const ctx = m.canvas.getContext("2d"); let tick = 0;
  setInterval(() => { ctx.fillStyle = tick++ % 2 ? "#000" : "#010101"; ctx.fillRect(0, 0, 1, 1); }, 500);
  video.srcObject = m.canvas.captureStream(10);
  show(video);
  try { await video.play(); } catch (e) { set("r-fact", "video play refused: " + e.message); return; }
  try {
    if (!document.pictureInPictureEnabled && !video.webkitSupportsPresentationMode) throw new Error("picture-in-picture not available in this browser");
    if (video.requestPictureInPicture) await video.requestPictureInPicture();
    else video.webkitSetPresentationMode("picture-in-picture");
    set("r-fact", "picture-in-picture window open. Take a screenshot now, with the window over another app too.");
  } catch (e) { set("r-fact", "picture-in-picture refused: " + e.message); }
});

// 5: WebGL with preserveDrawingBuffer: false. The photo is a texture drawn every frame; the drawing buffer is not kept between frames.
$("b-webgl").addEventListener("click", async () => {
  const m = await open(); if (!m) return;
  set("r-mode", "5: WebGL canvas, preserveDrawingBuffer false (mark " + m.id + ")");
  const c = document.createElement("canvas"); c.width = m.canvas.width; c.height = m.canvas.height;
  const gl = c.getContext("webgl", { preserveDrawingBuffer: false, alpha: false, antialias: false });
  if (!gl) { set("r-fact", "no WebGL in this browser"); return; }
  const vs = "attribute vec2 p; varying vec2 t; void main(){ t = vec2((p.x+1.0)/2.0, (1.0-p.y)/2.0); gl_Position = vec4(p,0.0,1.0); }";
  const fs = "precision mediump float; varying vec2 t; uniform sampler2D s; void main(){ gl_FragColor = texture2D(s, t); }";
  const sh = (type, src) => { const x = gl.createShader(type); gl.shaderSource(x, src); gl.compileShader(x); return x; };
  const prog = gl.createProgram(); gl.attachShader(prog, sh(gl.VERTEX_SHADER, vs)); gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, fs)); gl.linkProgram(prog); gl.useProgram(prog);
  const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, "p"); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  const tex = gl.createTexture(); gl.bindTexture(gl.TEXTURE_2D, tex);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, gl.RGB, gl.UNSIGNED_BYTE, m.canvas);
  show(c);
  let frames = 0;
  (function draw() { gl.viewport(0, 0, c.width, c.height); gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4); frames++; requestAnimationFrame(draw); })();
  setTimeout(() => set("r-fact", `drawing every frame (${frames} frames in 2 s); the buffer is not preserved. Take a screenshot now.`), 2000);
});
