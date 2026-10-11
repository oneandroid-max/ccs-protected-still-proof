import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveKey, derivePhotoKey, exportKeyHex, importKeyHex, seal, open, sealText, openText, toBase64, fromBase64, randomBytes } from "../crypto.js";
import { sliceRange, tileAt } from "../view-prelude.js";
import { run as worker, readGallery, MAX_PHOTOS, mosaicLayout, MOSAIC_MAX } from "../worker.mjs";
import { buildView } from "../../tools/build-site-view.mjs";
import { checkBoxes } from "../../service/lib/pipeline.mjs";
import { derivePlayReadyTestKey } from "../../tools/playready-test-key.mjs";
import { withOrientation } from "../../service/lib/exif.mjs";
import { run as exec } from "../../service/lib/util.mjs";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const tools = { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
const SALT = toBase64(new Uint8Array(16).fill(7));
const KEY = await deriveKey("a test password, twelve+", SALT, 1000);
const KEY_HEX = await exportKeyHex(KEY);
const ID = "0123456789abcdef01234567";
const tmp = await fs.mkdtemp(join(tmpdir(), "site-test-"));
const jpeg = async (name, w, h, color = "0x1f4e8c") => { const f = join(tmp, name); await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", `color=c=${color}:s=${w}x${h}:d=1`, "-frames:v", "1", "-update", "1", f]); return fs.readFile(f); };
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
  // the picture key: fixed for a given password key, different from it, and sealing under one does not open under the other
  const photo = await derivePhotoKey(KEY), photo2 = await derivePhotoKey(await importKeyHex(KEY_HEX));
  assert.equal(await exportKeyHex(photo), await exportKeyHex(photo2));
  assert.notEqual(await exportKeyHex(photo), KEY_HEX);
  await assert.rejects(open(KEY, await seal(photo, data)), /wrong password/);
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

test("site/view.html and site/all.html are generated from the route-1 page and are current", async () => {
  const index = await fs.readFile(join(REPO, "web", "research", "drm", "index.html"), "utf8");
  const out = buildView(index), all = buildView(index, "all");
  assert.equal(out, await fs.readFile(join(REPO, "site", "view.html"), "utf8"), "run node tools/build-site-view.mjs");
  assert.equal(all, await fs.readFile(join(REPO, "site", "all.html"), "utf8"), "run node tools/build-site-view.mjs");
  for (const page of [out, all]) {
    for (const s of ['widevine: "mem://photo/widevine.mpd"', "const CTX = await window.__ccsReady", 'src="view-prelude.js"', "../web/research/drm/card-widevine.mpd", 'href="index.html"', "name: CTX.content", "textContent = CTX.title", 'integrity="sha384-']) assert.ok(page.includes(s), s);
    assert.ok(!page.includes('"widevine.mpd"'), "no plain manifest name remains");
  }
  assert.ok(all.includes('window.__ccsMode = "all";') && !out.includes("__ccsMode"), "only the combined view runs the prelude in its 'all' mode");
  assert.throws(() => buildView(index.replace("<h1>Route 1", "<h1>Changed")), /heading/);
  assert.throws(() => buildView(index, "some"), /unknown view mode/);
});

test("the combined view's layout: every picture whole and in proportion, inside 1080x1920, no overlap; a tap finds its picture", () => {
  const portrait = { width: 960, height: 1280 }, landscape = { width: 1280, height: 720 }, square = { width: 800, height: 800 };
  const expect = { 8: "3x3", 10: "3x4", 4: "2x2", 1: "1x1" };
  for (const set of [portrait, landscape, square, "mixed"]) for (let n = 1; n <= MAX_PHOTOS; n++) {
    const sizes = Array.from({ length: n }, (_, i) => set === "mixed" ? [portrait, landscape, square][i % 3] : set);
    const L = mosaicLayout(sizes);
    const what = `${n} ${set === "mixed" ? "mixed" : set.width + "x" + set.height}`;
    assert.ok(L.width <= MOSAIC_MAX.width && L.height <= MOSAIC_MAX.height && L.width % 2 === 0 && L.height % 2 === 0, `${what}: frame ${L.width}x${L.height}`);
    assert.ok(Math.ceil(L.width / 16) * Math.ceil(L.height / 16) <= 8160, `${what}: within a 1080p frame's macroblocks`);
    assert.equal(L.tiles.length, n);
    assert.ok(L.cols * L.rows - n < L.cols, `${what}: no empty row`);
    L.tiles.forEach((t, i) => {
      const col = i % L.cols, row = Math.floor(i / L.cols);
      assert.ok(t.x >= col * L.cell.width && t.x + t.w <= (col + 1) * L.cell.width && t.y >= row * L.cell.height && t.y + t.h <= (row + 1) * L.cell.height, `${what}: tile ${i} stays in its own cell`);
      const want = sizes[i].width / sizes[i].height, got = t.w / t.h;
      assert.ok(Math.abs(got - want) / want < 0.012, `${what}: tile ${i} keeps its proportions (${got.toFixed(4)} vs ${want.toFixed(4)})`);
      assert.ok(t.w >= 100 && t.h >= 100, `${what}: tile ${i} is not a speck`);
    });
    if (set === portrait && expect[n]) assert.equal(`${L.cols}x${L.rows}`, expect[n], `${n} portrait pictures`);
  }
  assert.throws(() => mosaicLayout([]), /no pictures/);
  // a tap on a box drawn "contain": the frame is 1080x1440 inside a 400x600 box (bars above and below)
  const L = mosaicLayout(Array.from({ length: 8 }, () => portrait));
  const meta = { width: L.width, height: L.height, tiles: L.tiles.map((t, i) => ({ ...t, id: "id" + i })) };
  const s = 400 / L.width, top = (600 - L.height * s) / 2;
  for (const [i, t] of meta.tiles.entries()) assert.equal(tileAt(meta, { width: 400, height: 600 }, (t.x + t.w / 2) * s, top + (t.y + t.h / 2) * s).id, "id" + i);
  assert.equal(tileAt(meta, { width: 400, height: 600 }, 200, top / 2), null, "a tap on the bar above is no picture");
  assert.equal(tileAt(meta, { width: 400, height: 600 }, (L.tiles[0].x + L.tiles[0].w + 1) * s, top + 20 * s), null, "a tap in the gap between pictures is no picture");
});

test("worker: bad payloads are refused; without a packager a picture fails visibly; the eleventh is refused; delete removes", async () => {
  const siteDir = await freshSite();
  await assert.rejects(worker({ payload: payload({ id: "zz" }), siteDir, tools: noPackager }), /bad picture id/);
  await assert.rejects(worker({ payload: payload({ key: "nope" }), siteDir, tools: noPackager }), /bad key/);
  await assert.rejects(worker({ payload: payload({ action: "steal" }), siteDir, tools: noPackager }), /unknown action/);
  await assert.rejects(worker({ payload: { action: "mosaic", key: "nope" }, siteDir, tools: noPackager }), /bad key/);
  // the combined view with nothing ready: none, and an old one is removed
  await fs.mkdir(join(siteDir, "mosaic"), { recursive: true }); await fs.writeFile(join(siteDir, "mosaic", "meta.json.enc"), "old");
  assert.equal((await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools: noPackager })).status, "none");
  await assert.rejects(fs.stat(join(siteDir, "mosaic")), "no combined view without ready pictures");
  process.env.WORKER_BLOB_FILE = await sealedUpload(await jpeg("a.jpg", 64, 48));
  const r = await worker({ payload: payload(), siteDir, tools: noPackager });
  assert.equal(r.status, "failed"); assert.match(r.error, /packager/);
  const g = await readGallery(siteDir, KEY);
  assert.equal(g.photos.length, 1); assert.equal(g.photos[0].id, ID); assert.equal(g.photos[0].status, "failed"); assert.equal(g.photos[0].name, "sideways.jpg");
  await assert.rejects(fs.stat(join(siteDir, "photos", ID)), "no folder for a failed picture");
  // a gallery written under another key reads as a fresh list, never as a crash, and the next job clears the old folders
  const otherKey = await deriveKey("yet another password", SALT, 1000);
  assert.deepEqual(await readGallery(siteDir, otherKey), { photos: [], fresh: true });
  await fs.mkdir(join(siteDir, "photos", "a".repeat(24)), { recursive: true });
  await fs.writeFile(join(siteDir, "photos", "a".repeat(24), "widevine.mpd.enc"), "old");
  const freshDel = await worker({ payload: { action: "delete", id: "b".repeat(24), key: await exportKeyHex(otherKey) }, siteDir, tools: noPackager });
  assert.equal(freshDel.status, "deleted");
  await assert.rejects(fs.stat(join(siteDir, "photos", "a".repeat(24))), "the old folder is gone");
  assert.deepEqual(await readGallery(siteDir, otherKey), { photos: [] }, "the list now belongs to the new key");
  await fs.writeFile(join(siteDir, "gallery.json.enc"), await sealText(KEY, JSON.stringify(g))); // back to the first key for the rest of the test
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

async function stillRgb(kidGuid, sealedFile, key, w, h) {
  const enc = join(tmp, "mosaic-check-" + Math.random().toString(16).slice(2) + ".mp4");
  await fs.writeFile(enc, await open(key, new Uint8Array(await fs.readFile(sealedFile))));
  const raw = join(tmp, "mosaic-check-" + Math.random().toString(16).slice(2) + ".rgb");
  await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-xerror", "-y", "-decryption_key", derivePlayReadyTestKey(kidGuid.replace(/-/g, "").toLowerCase()), "-i", enc, "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", raw]);
  const px = await fs.readFile(raw);
  assert.equal(px.length, w * h * 3, "one decoded frame of the expected size");
  return (x, y) => { const o = (Math.round(y) * w + Math.round(x)) * 3; return [px[o], px[o + 1], px[o + 2]]; };
}
const near = (a, b, tol = 14) => a.every((v, i) => Math.abs(v - b[i]) <= tol);

test("worker with the real packager: the combined view holds every ready picture where its layout says, protected like one picture (needs shaka-packager)", async (t) => {
  let have = false;
  try { await exec(tools.packager, ["--version"]); have = true; } catch {}
  if (!have) {
    if (process.env.REQUIRE_PACKAGER === "1") assert.fail(`shaka-packager is required here and "${tools.packager}" did not run`);
    t.skip(`NOT RUN HERE: shaka-packager ("${tools.packager}") is not installed in this environment; CI runs it`);
    return;
  }
  const siteDir = await freshSite();
  const pics = [["b".repeat(24), "blue.jpg", "0x1f4e8c", [31, 78, 140], 720, 960], ["c".repeat(24), "red.jpg", "0xc0392b", [192, 57, 43], 960, 720], ["d".repeat(24), "broken.jpg", "0x27ae60", null, 720, 960]];
  for (const [id, name, color, , w, h] of pics) {
    process.env.WORKER_BLOB_FILE = await sealedUpload(await jpeg(name, w, h, color));
    assert.equal((await worker({ payload: payload({ id, name }), siteDir, tools })).status, "ready");
  }
  // the third picture's key id is damaged in the list: it must be LEFT OUT and named, never drawn as noise
  const g = await readGallery(siteDir, KEY);
  g.photos.find((x) => x.id === "d".repeat(24)).prKidGuid = "00000000-0000-0000-0000-000000000000";
  await fs.writeFile(join(siteDir, "gallery.json.enc"), await sealText(KEY, JSON.stringify(g)));
  const r = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools });
  assert.equal(r.status, "ready"); assert.equal(r.count, 2); assert.equal(r.skipped, 1);
  const dir = join(siteDir, "mosaic");
  const names = (await fs.readdir(dir)).sort();
  assert.deepEqual(names, ["meta.json.enc", "playready.mpd.enc", "video-playready.mp4.enc", "video-widevine.mp4.enc", "widevine.mpd.enc"]);
  for (const n of names) assert.ok((await fs.readFile(join(dir, n))).subarray(0, 4).equals(Buffer.from("CCS1")), n + " is sealed");
  const meta = JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(dir, "meta.json.enc")))));
  assert.deepEqual(meta.ids, ["b".repeat(24), "c".repeat(24)]);
  assert.deepEqual(meta.skipped.map((x) => [x.id, x.name]), [["d".repeat(24), "broken.jpg"]]);
  assert.deepEqual(meta.tiles.map((x) => x.name), ["blue.jpg", "red.jpg"]);
  const L = mosaicLayout([{ width: 720, height: 960 }, { width: 960, height: 720 }]);
  assert.deepEqual({ w: meta.width, h: meta.height, tiles: meta.tiles.map(({ x, y, w, h }) => ({ x, y, w, h })) }, { w: L.width, h: L.height, tiles: L.tiles });
  const wv = checkBoxes(Buffer.from(await open(KEY, new Uint8Array(await fs.readFile(join(dir, "video-widevine.mp4.enc"))))));
  const pr = checkBoxes(Buffer.from(await open(KEY, new Uint8Array(await fs.readFile(join(dir, "video-playready.mp4.enc"))))));
  assert.equal(wv.ok, true); assert.equal(pr.ok, true); assert.equal(pr.kids[0], meta.prKidGuid.replace(/-/g, "").toLowerCase());
  assert.ok(!g.photos.some((x) => x.prKidGuid === meta.prKidGuid), "the combined view has its own key id");
  // decrypt the combined view the way a licence would and look: each picture's colour at its tile's centre, black between
  const at = await stillRgb(meta.prKidGuid, join(dir, "video-playready.mp4.enc"), KEY, meta.width, meta.height);
  for (const [i, tile] of meta.tiles.entries()) {
    const want = pics[i][3], got = at(tile.x + tile.w / 2, tile.y + tile.h / 2);
    assert.ok(near(got, want), `${tile.name} at its centre: got ${got}, want ${want}`);
  }
  assert.ok(near(at(1, 1), [0, 0, 0], 20), "the frame around the pictures is black: " + at(1, 1));
  // the mosaic is remade from the list each time: deleting a picture removes it from the next one
  await worker({ payload: { action: "delete", id: "b".repeat(24), key: KEY_HEX }, siteDir, tools });
  const r2 = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools });
  assert.equal(r2.count, 1);
  assert.deepEqual(JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(dir, "meta.json.enc"))))).ids, ["c".repeat(24)]);
});
