#!/usr/bin/env node
// tools/verify.mjs — drive the proof page in a real (headless) Chromium and print measured numbers.
//
//   node tools/verify.mjs --secret=<base64url> --pin=<6 digits> [--chromium=/path/to/chrome] [--port=8787]
//
// Serves the repository root on 127.0.0.1 (a secure context, so WebCrypto works), then for pixel
// ratios 1 and 2: refuses a wrong PIN, accepts the right one, reads the readout, screenshots the
// canvas, runs the detector on that screenshot, measures the captured area's PSNR against the
// marked still (served by the page in ?test=1 mode), proves the reduced-motion fallback and the
// 30-frames-per-second fallback, and downloads the share card and detects the mark in it.
// Every number printed here came from the command that produced it.
import http from "node:http";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createReadStream, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chromium } from "playwright";
import sharp from "sharp";

const run = promisify(execFile);
const args = {};
for (const a of process.argv.slice(2)) { const m = a.match(/^--([^=]+)(?:=(.*))?$/); if (m) args[m[1]] = m[2] === undefined ? true : m[2]; }
if (!args.secret || !args.pin) { console.error("usage: --secret=<s> --pin=<p> [--chromium=] [--port=8787]"); process.exit(2); }

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(root, "tools", "out");
await mkdir(outDir, { recursive: true });
const port = Number(args.port || 8787);
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".enc": "application/octet-stream", ".mpd": "application/dash+xml", ".mp4": "video/mp4", ".md": "text/plain; charset=utf-8" };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p.endsWith("/")) p += "index.html";
  const file = path.join(root, p);
  if (!file.startsWith(root) || !existsSync(file)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { "content-type": types[path.extname(file)] || "application/octet-stream", "cache-control": "no-store" });
  createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(port, "127.0.0.1", r));

const executablePath = args.chromium || "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
const browser = await chromium.launch({ executablePath, args: ["--no-sandbox"] });
const base = `http://127.0.0.1:${port}/`;
const url = (q = "") => `${base}?v=verify&test=1${q}#k=${args.secret}`;
const report = { startedAt: new Date().toISOString(), chromium: executablePath, runs: [] };
const hour = new Date().toISOString().slice(0, 13);

async function detect(image, phase = "0") {
  const { stdout } = await run("node", [path.join(root, "tools", "detect-mark.mjs"), `--image=${image}`, `--secret=${args.secret}`, `--pin=${args.pin}`, `--hour=${hour}`, "--hours=0", `--phase=${phase}`, "--wrong=5", "--json"], { maxBuffer: 1 << 24 });
  const s = JSON.parse(stdout);
  return { bestRight: s.verdict.bestRight, maxAbsWrong: s.verdict.maxAbsWrong, markRecovered: s.verdict.markRecovered, sigma: s.residualSigma };
}
async function psnr(aPath, bPath) {
  const a = await sharp(aPath).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const b = await sharp(bPath).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  if (a.info.width !== b.info.width || a.info.height !== b.info.height) return { error: `size mismatch ${a.info.width}x${a.info.height} vs ${b.info.width}x${b.info.height}` };
  let se = 0, n = 0;
  for (let i = 0; i < a.data.length; i += 4) for (let c = 0; c < 3; c++) { const d = a.data[i + c] - b.data[i + c]; se += d * d; n++; }
  const mse = se / n;
  return { mse: Math.round(mse * 100) / 100, psnrDb: mse === 0 ? Infinity : Math.round(10 * Math.log10(255 * 255 / mse) * 100) / 100 };
}
async function readout(page) {
  const ids = ["r-pin", "r-mode", "r-fps", "r-playing", "r-canvas", "r-dpr", "r-motion", "r-mark", "r-amp"];
  const out = {};
  for (const id of ids) out[id] = await page.locator("#" + id).textContent();
  return out;
}
async function openWithPin(page, pin) {
  await page.fill("#pin", pin);
  await page.click("#show");
}

for (const dpr of [1, 2]) {
  const ctx = await browser.newContext({ deviceScaleFactor: dpr, viewport: { width: 430, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  const r = { dpr, errors };
  await page.goto(url(), { waitUntil: "load" });

  // 1. wrong PIN is refused
  const wrong = args.pin === "000000" ? "111111" : "000000";
  await openWithPin(page, wrong);
  await page.waitForFunction(() => document.getElementById("r-pin").textContent === "refused", null, { timeout: 30000 });
  r.wrongPin = { readout: await page.locator("#r-pin").textContent(), message: await page.locator("#msg").textContent() };

  // 2. right PIN plays, alternating
  await openWithPin(page, args.pin);
  await page.waitForFunction(() => /^alternating/.test(document.getElementById("r-mode").textContent) && /^\d+ per second/.test(document.getElementById("r-fps").textContent), null, { timeout: 60000 });
  r.readout = await readout(page);

  // 3. real screenshot of the canvas → detector → PSNR against the marked still
  const shot = path.join(outDir, `canvas-dpr${dpr}.png`);
  await page.locator("#proof").screenshot({ path: shot });
  const still = path.join(outDir, `still-dpr${dpr}.png`);
  await page.locator("#test-still").screenshot({ path: still });
  const meta = await sharp(shot).metadata();
  r.screenshot = { path: shot, width: meta.width, height: meta.height };
  r.detector = await detect(shot, "0");
  r.psnrCapturedVsStill = await psnr(shot, still);

  // 4. stop → still → screenshot → detector
  await page.click("#stop");
  await page.waitForFunction(() => /^still/.test(document.getElementById("r-mode").textContent), null, { timeout: 10000 });
  const stillShot = path.join(outDir, `stopped-dpr${dpr}.png`);
  await page.locator("#proof").screenshot({ path: stillShot });
  r.stopped = { mode: await page.locator("#r-mode").textContent(), detector: await detect(stillShot, "0"), psnrVsStill: await psnr(stillShot, still) };

  // 5. share card download → detector
  const [download] = await Promise.all([page.waitForEvent("download", { timeout: 20000 }), page.click("#share")]);
  const card = path.join(outDir, `share-card-dpr${dpr}.jpg`);
  await download.saveAs(card);
  const cardMeta = await sharp(card).metadata();
  r.shareCard = { path: card, width: cardMeta.width, height: cardMeta.height, detector: await detect(card, "0") };
  report.runs.push(r);
  await ctx.close();
}

// 6. reduced motion → still fallback, mark still present
{
  const ctx = await browser.newContext({ deviceScaleFactor: 2, viewport: { width: 430, height: 900 }, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  await page.goto(url(), { waitUntil: "load" });
  await openWithPin(page, args.pin);
  await page.waitForFunction(() => /^still/.test(document.getElementById("r-mode").textContent), null, { timeout: 60000 });
  const shot = path.join(outDir, "reduced-motion.png");
  await page.locator("#proof").screenshot({ path: shot });
  report.reducedMotion = { mode: await page.locator("#r-mode").textContent(), motion: await page.locator("#r-motion").textContent(), detector: await detect(shot, "0") };
  await ctx.close();
}

// 7. a 30 fps device → still fallback with the measured rate in the reason
{
  const ctx = await browser.newContext({ deviceScaleFactor: 2, viewport: { width: 430, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(url("&fpscap=30"), { waitUntil: "load" });
  await openWithPin(page, args.pin);
  await page.waitForFunction(() => /^still/.test(document.getElementById("r-mode").textContent), null, { timeout: 60000 });
  report.fpsCap30 = { mode: await page.locator("#r-mode").textContent(), fps: await page.locator("#r-fps").textContent() };
  await ctx.close();
}

await browser.close();
server.close();
report.finishedAt = new Date().toISOString();
await writeFile(path.join(outDir, "report.json"), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
