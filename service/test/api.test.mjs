import { test, after } from "node:test";
import assert from "node:assert/strict";

// What is still alive when the file's tests are done (a lingering handle shows up here, not as a silent hang).
after(() => { console.error("still alive after the tests:", process.getActiveResourcesInfo().join(", ") || "nothing", "| handles:", process._getActiveHandles().map((h) => h.constructor.name).join(", ") || "none"); });
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startApp, login, tinyPng, upload, readyRecord, REPO } from "./helpers.mjs";
import { buildViewTemplate } from "../lib/pages.mjs";
import { Sessions, LoginLimiter } from "../lib/sessions.mjs";

const noPackager = { tools: { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: "/nonexistent/packager" } };

test("the site refuses to start without a password", async () => {
  await assert.rejects(startApp({ password: "" }), /PROOF_PASSWORD must be set/);
  await assert.rejects(startApp({ password: "short" }), /at least 8/);
});

test("health is public; pages, API, media and licences need a session", async () => {
  const t = await startApp(noPackager);
  try {
    const h = await fetch(t.base + "/api/health"); assert.equal(h.status, 200); assert.equal((await h.json()).ok, true);
    const app = await fetch(t.base + "/app", { redirect: "manual" }); assert.equal(app.status, 303); assert.equal(app.headers.get("location"), "/login");
    const root = await fetch(t.base + "/", { redirect: "manual" }); assert.equal(root.headers.get("location"), "/login");
    assert.equal((await fetch(t.base + "/api/photos")).status, 401);
    assert.equal((await fetch(t.base + "/media/abcdef0123456789abcdef01/widevine.mpd")).status, 401);
    assert.equal((await fetch(t.base + "/licence/widevine?photo=x", { method: "POST", body: "c" })).status, 401);
    assert.equal((await fetch(t.base + "/view/abcdef0123456789abcdef01", { redirect: "manual" })).status, 303);
  } finally { await t.close(); }
});

test("login: wrong refused, right sets a cookie, tampered cookie refused, sign-out clears it", async () => {
  const t = await startApp(noPackager);
  try {
    const bad = await login(t.base, "wrong password"); assert.equal(bad.status, 303); assert.equal(bad.location, "/login?e=1"); assert.equal(bad.cookie, "");
    const empty = await login(t.base, ""); assert.equal(empty.location, "/login?e=1");
    const ok = await login(t.base); assert.equal(ok.status, 303); assert.equal(ok.location, "/app"); assert.match(ok.cookie, /^ps=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const page = await fetch(t.base + "/app", { headers: { cookie: ok.cookie } }); assert.equal(page.status, 200);
    const body = await page.text(); assert.match(body, /Your test pictures/); assert.match(body, /Sign out/);
    const form = await (await fetch(t.base + "/login")).text(); assert.ok(!/name="username"/.test(form), "password only, no username field");
    assert.match(page.headers.get("content-security-policy"), /script-src 'nonce-/);
    const tampered = ok.cookie.slice(0, -1) + (ok.cookie.endsWith("A") ? "B" : "A");
    const r = await fetch(t.base + "/app", { headers: { cookie: tampered }, redirect: "manual" }); assert.equal(r.status, 303);
    const out = await fetch(t.base + "/logout", { method: "POST", headers: { cookie: ok.cookie }, redirect: "manual" });
    assert.equal(out.status, 303); assert.match(out.headers.get("set-cookie"), /^ps=; .*Max-Age=0/);
    const cross = await fetch(t.base + "/login", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "sec-fetch-site": "cross-site" }, body: "password=correct+horse+battery" });
    assert.equal(cross.status, 403);
  } finally { await t.close(); }
});

test("five wrong passwords lock the address, even for the right password", async () => {
  const t = await startApp(noPackager);
  try {
    let last;
    for (let i = 0; i < 5; i++) last = await login(t.base, "wrong " + i);
    assert.equal(last.location, "/login?e=locked");
    const right = await login(t.base); assert.equal(right.location, "/login?e=locked"); assert.equal(right.cookie, "");
  } finally { await t.close(); }
});

test("sessions: expiry and the limiter's clock", () => {
  const s = new Sessions("x".repeat(32), 1000);
  const tok = s.issue("bo", 1_000_000);
  assert.equal(s.verify(tok, 1_000_500).u, "bo");
  assert.equal(s.verify(tok, 1_001_000), null);
  assert.equal(new Sessions("y".repeat(32)).verify(tok), null, "another secret must not accept the token");
  const l = new LoginLimiter({ maxFails: 2, lockMs: 100 });
  assert.equal(l.fail("a", 0), 0); assert.ok(l.fail("a", 0) > 0); assert.ok(l.locked("a", 50) > 0); assert.equal(l.locked("a", 200), 0);
});

test("uploads: header, type, size, the ten-picture limit, list, delete", async () => {
  const t = await startApp(noPackager);
  try {
    const { cookie } = await login(t.base);
    const png = tinyPng();
    assert.equal((await fetch(t.base + "/api/photos", { method: "PUT", headers: { cookie, "content-type": "image/png" }, body: png })).status, 403, "no x-proof header");
    assert.equal((await upload(t.base, cookie, png, "x.png", "image/png", { "sec-fetch-site": "cross-site" })).status, 403, "cross-site");
    assert.equal((await upload(t.base, cookie, Buffer.from("hello, not a picture"), "a.png")).status, 415);
    assert.equal((await upload(t.base, cookie, Buffer.concat([png, Buffer.alloc(300000)]), "big.png")).status, 413);
    for (let i = 0; i < 10; i++) {
      const r = await upload(t.base, cookie, png, `my pic ${i}.png`);
      assert.equal(r.status, 201, `upload ${i}`);
      const j = await r.json(); assert.equal(j.photo.name, `my pic ${i}.png`); assert.equal(j.photo.status, "queued");
    }
    assert.equal((await upload(t.base, cookie, png, "eleventh.png")).status, 409);
    const list = await (await fetch(t.base + "/api/photos", { headers: { cookie } })).json();
    assert.equal(list.photos.length, 10); assert.equal(list.maxPhotos, 10);
    assert.ok(!JSON.stringify(list).includes("prKid"), "key ids never leave the server");
    const id = list.photos[3].id;
    assert.equal((await fetch(t.base + "/api/photos/" + id, { method: "DELETE", headers: { cookie } })).status, 403, "delete needs the header");
    assert.equal((await fetch(t.base + "/api/photos/" + id, { method: "DELETE", headers: { cookie, "x-proof": "1" } })).status, 204);
    assert.equal((await fetch(t.base + "/api/photos/" + id, { method: "DELETE", headers: { cookie, "x-proof": "1" } })).status, 404);
    const after = await (await fetch(t.base + "/api/photos", { headers: { cookie } })).json();
    assert.equal(after.photos.length, 9);
    await assert.rejects(fs.stat(t.app.store.dir(id)), "the deleted picture's folder is gone");
    // with no packager the pipeline must FAIL visibly, never pretend
    const deadline = Date.now() + 60000;
    let failed = 0;
    while (Date.now() < deadline) {
      const l = await (await fetch(t.base + "/api/photos", { headers: { cookie } })).json();
      failed = l.photos.filter((p) => p.status === "failed").length;
      if (failed === 9) break;
      await new Promise((r) => setTimeout(r, 300));
    }
    assert.equal(failed, 9);
    const l = await (await fetch(t.base + "/api/photos", { headers: { cookie } })).json();
    assert.match(l.photos[0].error, /packager/);
  } finally { await t.close(); }
});

test("media: session, only ready pictures, only the allowed files, byte ranges", async () => {
  const t = await startApp(noPackager);
  try {
    const { cookie } = await login(t.base);
    const { rec, bytes } = await readyRecord(t.app);
    const whole = await fetch(`${t.base}/media/${rec.id}/video-widevine.mp4`, { headers: { cookie } });
    assert.equal(whole.status, 200); assert.equal(whole.headers.get("content-type"), "video/mp4"); assert.equal(whole.headers.get("accept-ranges"), "bytes");
    assert.ok(Buffer.from(await whole.arrayBuffer()).equals(bytes));
    const part = await fetch(`${t.base}/media/${rec.id}/video-widevine.mp4`, { headers: { cookie, range: "bytes=10-19" } });
    assert.equal(part.status, 206); assert.equal(part.headers.get("content-range"), "bytes 10-19/1000");
    assert.ok(Buffer.from(await part.arrayBuffer()).equals(bytes.subarray(10, 20)));
    const tail = await fetch(`${t.base}/media/${rec.id}/video-widevine.mp4`, { headers: { cookie, range: "bytes=990-" } });
    assert.equal(tail.status, 206); assert.ok(Buffer.from(await tail.arrayBuffer()).equals(bytes.subarray(990)));
    const beyond = await fetch(`${t.base}/media/${rec.id}/video-widevine.mp4`, { headers: { cookie, range: "bytes=2000-3000" } });
    assert.equal(beyond.status, 416);
    assert.equal((await fetch(`${t.base}/media/${rec.id}/widevine.mpd`, { headers: { cookie } })).headers.get("content-type"), "application/dash+xml");
    assert.equal((await fetch(`${t.base}/media/${rec.id}/original.png`, { headers: { cookie } })).status, 404, "the original is never served");
    assert.equal((await fetch(`${t.base}/media/${rec.id}/../state.json`, { headers: { cookie } })).status, 404);
    assert.equal((await fetch(`${t.base}/media/${rec.id}/playready.mpd`, { headers: { cookie } })).status, 404, "a file that does not exist yet");
    await t.app.store.update(rec.id, { status: "queued" });
    assert.equal((await fetch(`${t.base}/media/${rec.id}/video-widevine.mp4`, { headers: { cookie } })).status, 404, "not ready: nothing is served");
  } finally { await t.close(); }
});

test("licences: forwarded only for a signed-in viewer and a ready picture, the key id taken from the record, every request logged", async () => {
  const t = await startApp(noPackager);
  try {
    const { cookie } = await login(t.base);
    const { rec } = await readyRecord(t.app);
    const wv = await fetch(`${t.base}/licence/widevine?photo=${rec.id}`, { method: "POST", headers: { cookie, "content-type": "application/octet-stream" }, body: Buffer.from("challenge-bytes") });
    assert.equal(wv.status, 200); assert.equal(await wv.text(), "LICENCE-OK");
    assert.equal(t.wv.seen.length, 1); assert.equal(t.wv.seen[0].body.toString(), "challenge-bytes"); assert.equal(t.wv.seen[0].url, "/wv");
    const pr = await fetch(`${t.base}/licence/playready?photo=${rec.id}&kid=0000-WRONG&sl=3000`, { method: "POST", headers: { cookie, "content-type": "text/xml; charset=utf-8", soapaction: '"http://x/AcquireLicense"' }, body: "<challenge/>" });
    assert.equal(pr.status, 200); assert.equal(await pr.text(), "<soap>licence</soap>");
    assert.equal(t.pr.seen.length, 1);
    assert.equal(t.pr.seen[0].url, `/pr?cfg=(kid:${rec.prKidGuid},sl:3000)`, "the record's key id, never the client's");
    assert.equal(t.pr.seen[0].headers.soapaction, '"http://x/AcquireLicense"');
    assert.equal((await fetch(`${t.base}/licence/playready?photo=${rec.id}&sl=1000`, { method: "POST", headers: { cookie }, body: "x" })).status, 400);
    assert.equal((await fetch(`${t.base}/licence/widevine?photo=ffffffffffffffffffffffff`, { method: "POST", headers: { cookie }, body: "x" })).status, 404);
    const card = await fetch(`${t.base}/licence/playready?photo=card&kid=whatever&sl=2000`, { method: "POST", headers: { cookie }, body: "<c/>" });
    assert.equal(card.status, 200); assert.equal(t.pr.seen[1].url, "/pr?cfg=(kid:5CFCB567-F2F1-9D08-A30B-20483D92E930,sl:2000)", "the card's own key id");
    const log = (await fs.readFile(join(t.dataDir, "views.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(log.length, 3); assert.equal(log[0].user, "viewer"); assert.equal(log[0].photo, rec.id); assert.equal(log[0].system, "widevine"); assert.equal(log[0].status, 200);
    assert.equal(log[1].sl, "3000");
    const list = await (await fetch(t.base + "/api/photos", { headers: { cookie } })).json();
    assert.equal(list.views[rec.id], 2);
    await t.app.store.update(rec.id, { status: "processing" });
    assert.equal((await fetch(`${t.base}/licence/widevine?photo=${rec.id}`, { method: "POST", headers: { cookie }, body: "x" })).status, 409, "not ready: no licence");
  } finally { await t.close(); }
});

test("the protected view: the proof page with this picture's files, licence addresses and name, under a nonce", async () => {
  const t = await startApp(noPackager);
  try {
    const { cookie } = await login(t.base);
    const { rec } = await readyRecord(t.app, { name: 'my <b>"photo"</b>.jpg' });
    const r = await fetch(`${t.base}/view/${rec.id}`, { headers: { cookie } });
    assert.equal(r.status, 200);
    const body = await r.text();
    const nonce = /script-src 'nonce-([^']+)'/.exec(r.headers.get("content-security-policy"))[1];
    assert.equal(body.split(`nonce="${nonce}"`).length - 1, 3, "style + player script + page script carry the nonce");
    assert.match(body, new RegExp(`widevine: "/media/${rec.id}/widevine.mpd", playready: "/media/${rec.id}/playready.mpd", prKid: "${rec.prKidGuid}"`));
    assert.match(body, new RegExp(`"/licence/widevine\\?photo=${rec.id}"`));
    assert.match(body, new RegExp("`/licence/playready\\?photo=" + rec.id + "&kid=\\$\\{CLIP.prKid\\}&sl=\\$\\{t.sl\\}`"));
    assert.match(body, /<h1>Protected view: my &lt;b&gt;&quot;photo&quot;&lt;\/b&gt;.jpg<\/h1>/);
    assert.match(body, /name: "your picture: my <b>\\"photo\\"<\\\/b>.jpg"/);
    assert.match(body, /https:\/\/oneandroid-max\.github\.io\/ccs-protected-still-proof\/web\/research\/drm\/card-widevine\.mpd/);
    assert.ok(!body.includes("cwip-shaka-proxy"), "no direct public licence address remains");
    assert.ok(!body.includes("test.playready.microsoft.com"), "no direct public licence address remains");
    assert.match(body, /Back to your pictures/);
    await t.app.store.update(rec.id, { status: "processing" });
    assert.match(await (await fetch(`${t.base}/view/${rec.id}`, { headers: { cookie } })).text(), /being prepared/);
    assert.equal((await fetch(`${t.base}/view/ffffffffffffffffffffffff`, { headers: { cookie } })).status, 404);
  } finally { await t.close(); }
});

test("the view template refuses a proof page that no longer matches", async () => {
  const html = await fs.readFile(join(REPO, "web", "research", "drm", "index.html"), "utf8");
  assert.doesNotThrow(() => buildViewTemplate(html));
  assert.throws(() => buildViewTemplate(html.replace('cfg.drm.servers["com.widevine.alpha"] = "https://cwip-shaka-proxy.appspot.com/no_auth";', "// gone")), /widevine licence address/);
  assert.throws(() => buildViewTemplate(html + html), /title/);
});

// Only the pinned shaka-packager runs on a photo (service/lib/packager-pin.mjs, checked by the file's SHA-256 each
// time, before it is ever run): a file that is there and would answer like a packager, but is not that build, is never
// run at all, is named in health, and every photo fails with the reason.
test("a packager that is not the pinned build: named in health, and every photo refused with the reason", async () => {
  const dir = await fs.mkdtemp(join(tmpdir(), "proof-wrong-")), wrong = join(dir, "packager"), ran = join(dir, "ran");
  await fs.writeFile(wrong, `#!/bin/sh\necho "$@" >> "${ran}"\necho 'packager version v3.9.3'\n`); await fs.chmod(wrong, 0o755);
  const t = await startApp({ tools: { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: wrong } });
  const REFUSED = /the packager at .*\/packager is not the pinned shaka-packager v3\.9\.3 \(sha256 [0-9a-f]{16}…, pinned 7a3cf35ad146fd78…\): refused/;
  try {
    let h; const until = Date.now() + 20000;
    do { h = await (await fetch(t.base + "/api/health")).json(); if (h.tools.problem) break; await new Promise((r) => setTimeout(r, 100)); } while (Date.now() < until);
    assert.match(h.tools.problem, new RegExp("packager: " + REFUSED.source), JSON.stringify(h.tools));
    assert.equal(h.tools.packager, "", "never run, so no version was read from it");
    const { cookie } = await login(t.base);
    const r = await upload(t.base, cookie, tinyPng(), "a.png"); assert.equal(r.status, 201);
    const id = (await r.json()).photo.id;
    let p; const end = Date.now() + 30000;
    do { p = (await (await fetch(t.base + "/api/photos", { headers: { cookie } })).json()).photos.find((x) => x.id === id); if (p.status === "failed") break; await new Promise((r) => setTimeout(r, 200)); } while (Date.now() < end);
    assert.equal(p.status, "failed"); assert.match(p.error, REFUSED);
    await assert.rejects(fs.access(ran), "the file was never run, not even for its version (the twelfth review: the service ran it before checking it)");
  } finally { await t.close(); await fs.rm(dir, { recursive: true, force: true }); }
});
