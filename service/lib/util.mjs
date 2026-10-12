// Small helpers shared by the service. No outside packages anywhere in service/.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const sha256 = (data) => createHash("sha256").update(data).digest();

// Constant-time comparison of two strings of any length (both are hashed first, so the lengths match).
export function safeEqual(a, b) {
  return timingSafeEqual(sha256(String(a)), sha256(String(b)));
}

export const newId = (bytes = 12) => randomBytes(bytes).toString("hex");

export const nowIso = () => new Date().toISOString();

// Reads a request body up to `limit` bytes; rejects with { code: 413 } as soon as it is larger. The
// rest of an oversized body is drained (never stored) so the 413 reply reaches the client cleanly.
export function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0, tooBig = false;
    req.on("data", (c) => {
      if (tooBig) return;
      size += c.length;
      if (size > limit) { tooBig = true; chunks.length = 0; reject(Object.assign(new Error("body too large"), { code: 413 })); return; }
      chunks.push(c);
    });
    req.on("end", () => { if (!tooBig) resolve(Buffer.concat(chunks)); });
    req.on("error", (e) => { if (!tooBig) reject(e); });
  });
}

// The image type from the file's first bytes, never from its name or declared type.
export function sniffImage(buf) {
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { type: "image/jpeg", ext: "jpg" };
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { type: "image/png", ext: "png" };
  if (buf.length >= 12 && buf.subarray(0, 4).toString("latin1") === "RIFF" && buf.subarray(8, 12).toString("latin1") === "WEBP") return { type: "image/webp", ext: "webp" };
  return null;
}

export function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// A command's text with every key in it replaced (shaka-packager's key=<hex> and --aes_signing_key, ffmpeg's
// -decryption_key): an error message can reach a public log, and the full command line is in it.
export const redactKeys = (t) => String(t)
  .replace(/(^|[^_\w])(key=)[0-9a-fA-F]{16,}/g, "$1$2<redacted>")
  .replace(/(-decryption_key|--aes_signing_key|--aes_signing_iv)(\s+|=)[0-9a-fA-F]{16,}/g, "$1$2<redacted>");

// Runs a program with arguments (no shell), capturing output; rejects after `timeoutMs`.
export function run(bin, args, { cwd, timeoutMs = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    import("node:child_process").then(({ execFile }) => {
      execFile(bin, args, { cwd, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) reject(Object.assign(new Error(`${bin} failed: ${redactKeys((stderr || err.message).toString().trim()).slice(-800)}`), { stdout, stderr, notRun: /^spawn /.test(String(err.syscall || "")) })); // redacted before it is cut, so a cut can never leave part of a key; notRun: the program could not be started at all (not there, not executable)
        else resolve({ stdout: String(stdout), stderr: String(stderr) });
      });
    });
  });
}
