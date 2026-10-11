import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveKey, exportKeyHex, importKeyHex, seal, open, sealText, openText, toBase64, fromBase64, randomBytes } from "../crypto.js";
import { sliceRange } from "../view-prelude.js";
import { run as worker, readGallery, MAX_PHOTOS } from "../worker.mjs";
import { buildView } from "../../tools/build-site-view.mjs";
import { checkBoxes } from "../../service/lib/pipeline.mjs";
import { withOrientation } from "../../service/lib/exif.mjs";
import { run as exec } from "../../service/lib/util.mjs";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const tools = { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
const SALT = toBase64(new Uint8Array(16).fill(7));
const KEY = await deriveKey("a test password, twelve+", SALT, 1000);
const KEY_HEX = await exportKeyHex(KEY);
const ID = "0123456789abcdef01234567";
const tmp = await fs.mkdtemp(join(tmpdir(), "site-test-"));
const jpeg = async (name, w, h) => { const f = join(tmp, name); await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", `color=c=0x1f4e8c:s=${w}x${h}:d=1`, "-frames:v", "1", "-update", "1", f]); return fs.readFile(f); };
async function freshSite() { const d = await fs.mkdtemp(join(tmpdir(), "site-dir-")); return d; }
async function sealedUpload(bytes) { const f = join(tmp, "upload-" + Math.random().toString(16).slice(2) + ".enc"); await fs.writeFile(f, await seal(KEY, bytes)); return f; }
const payload = (over) => ({ action: "add", id: ID, name: "sideways.jpg", type: "image/jpeg", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX, ...over });
const noPackager = { ...tools, packager: "/nonexistent/packager" };

test("crypto: the same password and salt give the same key; sealed data opens only with that key", async () => {
  assert.equal(await exportKeyHex(await deriveKey("a test password, twelve+", SALT, 1000)), KEY_HEX);
  assert.notEqual(await exportKeyHex(await deriveKey("a test password, twelve+", toBase64(new Uint8Array(16).fill(8)), 1000)), KEY_HEX);
  const data = new Uint8Array(70000); for (let i = 0; i < data.length; i++) data[i] = (i * 31) & 255;
  const sealed = await seal(KEY, data);
  assert.equal(sealed.length, data.length + 32);
  assert.deepEqual(await open(KEY, sealed), data);
  const other = await importKeyHex(await exportKeyHex(await deriveKey("another password here", SALT, 1000)));
  await assert.rejects(open(other, sealed), /wrong password/);
  const tampered = sealed.slice(); tampered[40] ^= 1;
  await assert.rejects(open(KEY, tampered), /wrong password/);
  await assert.rejects(open(KEY, new Uint8Array([1, 2, 3])), /not a sealed file/);
  assert.equal(await openText(KEY, await sealText(KEY, "héllo")), "héllo");
  assert.deepEqual(fromBase64(toBase64(sealed)), sealed);
  assert.equal(await exportKeyHex(await importKeyHex(KEY_HEX)), KEY_HEX);
});

test("the in-memory scheme honours byte ranges the way the player asks for them", () => {
  const d = new Uint8Array(1000); for (let i = 0; i < 1000; i++) d[i] = i & 255;
  assert.equal(sliceRange(d, undefined), d);
  assert.deepEqual(sliceRange(d, "bytes=10-19"), d.subarray(10, 20));
  assert.deepEqual(sliceRange(d, "bytes=990-"), d.subarray(990));
  assert.deepEqual(sliceRange(d, "bytes=-10"), d.subarray(990));
  assert.deepEqual(sliceRange(d, "bytes=0-5000"), d);
  assert.equal(sliceRange(d, "bytes=2000-3000").length, 0);
});

test("site/view.html is generated from the route-1 page and is current", async () => {
  const index = await fs.readFile(join(REPO, "web", "research", "drm", "index.html"), "utf8");
  const out = buildView(index);
  assert.equal(out, await fs.readFile(join(REPO, "site", "view.html"), "utf8"), "run node tools/build-site-view.mjs");
  for (const s of ['widevine: "mem://photo/widevine.mpd"', "const CTX = await window.__ccsReady", 'src="view-prelude.js"', "../web/research/drm/card-widevine.mpd", 'href="index.html"']) assert.ok(out.includes(s), s);
  assert.ok(!out.includes('"widevine.mpd"'), "no plain manifest name remains");
  assert.throws(() => buildView(index.replace("<h1>Route 1", "<h1>Changed")), /heading/);
});

test("worker: bad payloads are refused; without a packager a picture fails visibly; the eleventh is refused; delete removes", async () => {
  const siteDir = await freshSite();
  await assert.rejects(worker({ payload: payload({ id: "zz" }), siteDir, tools: noPackager }), /bad picture id/);
  await assert.rejects(worker({ payload: payload({ key: "nope" }), siteDir, tools: noPackager }), /bad key/);
  await assert.rejects(worker({ payload: payload({ action: "steal" }), siteDir, tools: noPackager }), /unknown action/);
  process.env.WORKER_BLOB_FILE = await sealedUpload(await jpeg("a.jpg", 64, 48));
  const r = await worker({ payload: payload(), siteDir, tools: noPackager });
  assert.equal(r.status, "failed"); assert.match(r.error, /packager/);
  const g = await readGallery(siteDir, KEY);
  assert.equal(g.photos.length, 1); assert.equal(g.photos[0].id, ID); assert.equal(g.photos[0].status, "failed"); assert.equal(g.photos[0].name, "sideways.jpg");
  await assert.rejects(fs.stat(join(siteDir, "photos", ID)), "no folder for a failed picture");
  // a gallery written under another key reads as empty, never as a crash
  const otherKey = await deriveKey("yet another password", SALT, 1000);
  assert.deepEqual(await readGallery(siteDir, otherKey), { photos: [] });
  // an upload that is not a picture
  process.env.WORKER_BLOB_FILE = await sealedUpload(new TextEncoder().encode("not a picture"));
  const bad = await worker({ payload: payload({ id: "e".repeat(24) }), siteDir, tools: noPackager });
  assert.match(bad.error, /only JPEG, PNG or WebP/);
  // a blob sealed under another key
  await fs.writeFile(process.env.WORKER_BLOB_FILE, await seal(otherKey, await jpeg("b.jpg", 32, 32)));
  const wrong = await worker({ payload: payload({ id: "d".repeat(24) }), siteDir, tools: noPackager });
  assert.match(wrong.error, /wrong password/);
  assert.equal((await readGallery(siteDir, KEY)).photos.length, 3, "three failed entries, visible to the page");
  // the eleventh PREPARED picture is refused; failed entries take no slot
  const full = { photos: [...(await readGallery(siteDir, KEY)).photos, ...Array.from({ length: MAX_PHOTOS }, (_, i) => ({ id: i.toString(16).padStart(24, "0"), name: "p" + i, status: "ready" }))] };
  await fs.writeFile(join(siteDir, "gallery.json.enc"), await sealText(KEY, JSON.stringify(full)));
  process.env.WORKER_BLOB_FILE = await sealedUpload(await jpeg("c.jpg", 32, 32));
  const r11 = await worker({ payload: payload({ id: "f".repeat(24) }), siteDir, tools: noPackager });
  assert.equal(r11.status, "failed"); assert.match(r11.error, /at most 10/);
  assert.equal((await readGallery(siteDir, KEY)).photos.length, 14, "the refusal is recorded so the page can show it");
  const del = await worker({ payload: { action: "delete", id: "0".repeat(23) + "1", key: KEY_HEX }, siteDir, tools: noPackager });
  assert.equal(del.status, "deleted");
  const after = await worker({ payload: payload({ id: "f".repeat(24) }), siteDir, tools: noPackager });
  assert.match(after.error, /packager/, "with a slot free the upload is attempted again (and fails here only for want of the packager)");
});

test("worker with the real packager: a sideways upload becomes encrypted protected files and an encrypted gallery entry (needs shaka-packager)", async (t) => {
  let have = false;
  try { await exec(tools.packager, ["--version"]); have = true; } catch {}
  if (!have) {
    if (process.env.REQUIRE_PACKAGER === "1") assert.fail(`shaka-packager is required here and "${tools.packager}" did not run`);
    t.skip(`NOT RUN HERE: shaka-packager ("${tools.packager}") is not installed in this environment; CI runs it`);
    return;
  }
  const siteDir = await freshSite();
  process.env.WORKER_BLOB_FILE = await sealedUpload(withOrientation(await jpeg("card.jpg", 720, 960), 6));
  const r = await worker({ payload: payload(), siteDir, tools });
  assert.equal(r.status, "ready", r.error || "");
  const dir = join(siteDir, "photos", ID);
  const names = (await fs.readdir(dir)).sort();
  assert.deepEqual(names, ["meta.json.enc", "playready.mpd.enc", "video-playready.mp4.enc", "video-widevine.mp4.enc", "widevine.mpd.enc"]);
  for (const n of names) assert.ok((await fs.readFile(join(dir, n))).subarray(0, 4).equals(Buffer.from("CCS1")), n + " is sealed");
  const meta = JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(dir, "meta.json.enc")))));
  assert.equal(meta.name, "sideways.jpg"); assert.deepEqual({ w: meta.width, h: meta.height }, { w: 960, h: 720 }); assert.match(meta.prKidGuid, /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/);
  const pr = checkBoxes(Buffer.from(await open(KEY, new Uint8Array(await fs.readFile(join(dir, "video-playready.mp4.enc"))))));
  assert.equal(pr.ok, true); assert.equal(pr.kids[0], meta.prKidGuid.replace(/-/g, "").toLowerCase());
  const wv = checkBoxes(Buffer.from(await open(KEY, new Uint8Array(await fs.readFile(join(dir, "video-widevine.mp4.enc"))))));
  assert.equal(wv.ok, true);
  const mpd = await openText(KEY, new Uint8Array(await fs.readFile(join(dir, "widevine.mpd.enc"))));
  assert.match(mpd, /video-widevine\.mp4/);
  const g = await readGallery(siteDir, KEY);
  assert.equal(g.photos[0].status, "ready"); assert.equal(g.photos[0].prKidGuid, meta.prKidGuid);
  const del = await worker({ payload: { action: "delete", id: ID, key: KEY_HEX }, siteDir, tools });
  assert.equal(del.status, "deleted"); await assert.rejects(fs.stat(dir)); assert.equal((await readGallery(siteDir, KEY)).photos.length, 0);
});
