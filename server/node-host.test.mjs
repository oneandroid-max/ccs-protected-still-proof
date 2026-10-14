// node --test server/node-host.test.mjs
// Starts the real Node host and checks it survives requests that used to take it down, and that a
// damaged audit file is replayed without stopping the start.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import http from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

function start(extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(HERE, "node.mjs")], {
      env: { PATH: process.env.PATH, PORT: "0", TOKEN_SECRET: "t", ADMIN_KEY: "a", VIEWERS: "48213:Family A:p,77310:Family B:p", ALLOWED_ORIGINS: "https://x", ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "", err = "";
    child.stdout.on("data", (d) => {
      out += d;
      const m = out.match(/listening on :(\d+)/);
      if (m) resolve({ child, port: Number(m[1]), stderr: () => err });
    });
    child.stderr.on("data", (d) => { err += d; });
    child.on("exit", (code) => reject(new Error("host exited before listening, code " + code + ": " + err.slice(0, 400))));
  });
}
function raw(port, text, { close = false } = {}) {
  return new Promise((resolve) => {
    const s = net.createConnection(port, "127.0.0.1", () => {
      s.write(text);
      if (close) { s.destroy(); setTimeout(() => resolve("closed"), 150); }
    });
    let data = "";
    s.on("data", (d) => { data += d; });
    s.on("end", () => resolve(data));
    s.on("error", () => resolve(data || "error"));
    setTimeout(() => { s.destroy(); resolve(data); }, 1500);
  });
}
function get(port, path, method = "GET", body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method, headers: body ? { "content-type": "application/json" } : {} }, (res) => {
      let d = "";
      res.on("data", (c) => { d += c; });
      res.on("end", () => resolve({ status: res.statusCode, body: d }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

test("the host survives an odd method, a malformed Host header, odd request targets and a client that drops mid-upload", async () => {
  const { child, port } = await start();
  try {
    const trace = await raw(port, "TRACE /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert.match(trace, /^HTTP\/1\.1 405/);
    const badHost = await raw(port, "GET /health HTTP/1.1\r\nHost: a b\r\nConnection: close\r\n\r\n");
    assert.match(badHost, /^HTTP\/1\.1 (200|400)/);
    const star = await raw(port, "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert.match(star, /^HTTP\/1\.1 (204|400|404)/);
    const absolute = await raw(port, "GET http://elsewhere.example/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert.match(absolute, /^HTTP\/1\.1 (200|400|404)/);
    await raw(port, "POST /licence HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n" + "a".repeat(10), { close: true });
    const health = await get(port, "/health");
    assert.equal(health.status, 200, "still answering after all three");
    assert.equal(child.exitCode, null);
  } finally {
    child.kill();
  }
});

test("a damaged audit file is replayed line by line: revocations survive, a cut-off line is skipped", async () => {
  const dir = await mkdtemp(join(tmpdir(), "licence-audit-"));
  const file = join(dir, "audit.jsonl");
  await writeFile(file, [
    JSON.stringify({ at: 1, event: "session", sid: "s1", pin: "77310" }),
    JSON.stringify({ at: 2, event: "revoked", sid: null, pin: "77310" }),
    '{"at": 3, "event": "licen',
  ].join("\n"));
  const { child, port, stderr } = await start({ AUDIT_FILE: file });
  try {
    assert.equal((await get(port, "/health")).status, 200);
    const revoked = await get(port, "/session", "POST", JSON.stringify({ pin: "77310", asset: "p" }));
    assert.equal(revoked.status, 403, "the revocation in the file still holds");
    const ok = await get(port, "/session", "POST", JSON.stringify({ pin: "48213", asset: "p" }));
    assert.equal(ok.status, 200);
    assert.match(stderr(), /skipped 1 unreadable line/);
  } finally {
    child.kill();
  }
});
