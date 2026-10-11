import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { jpegOrientation, withOrientation } from "../lib/exif.mjs";
import { renderClip, targetSize, checkBoxes, MAX_SIDE, probe } from "../lib/pipeline.mjs";
import { run } from "../lib/util.mjs";
import { startApp, login, upload, REPO } from "./helpers.mjs";

const tools = { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
const tmp = await fs.mkdtemp(join(tmpdir(), "proof-pipe-"));
const jpeg = async (name, w, h, color = "0x1f4e8c") => { const f = join(tmp, name); await run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", `color=c=${color}:s=${w}x${h}:d=1`, "-frames:v", "1", "-update", "1", f]); return f; };

test("EXIF orientation: every value reads back; other files read as upright", async () => {
  const plain = await fs.readFile(await jpeg("plain.jpg", 64, 48));
  assert.equal(jpegOrientation(plain), 1);
  for (let o = 1; o <= 8; o++) assert.equal(jpegOrientation(withOrientation(plain, o)), o);
  assert.equal(jpegOrientation(Buffer.from([0x89, 0x50, 0x4e, 0x47])), 1);
  assert.equal(jpegOrientation(Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00])), 1, "truncated: no crash");
});

test("the clip's size: upright, rotated, capped at the longest side, always even", () => {
  assert.deepEqual(targetSize({ width: 900, height: 600 }, 1), { width: 900, height: 600 });
  assert.deepEqual(targetSize({ width: 900, height: 600 }, 6), { width: 600, height: 900 });
  assert.deepEqual(targetSize({ width: 3000, height: 2000 }, 1), { width: MAX_SIDE, height: 854 });
  assert.deepEqual(targetSize({ width: 3000, height: 2000 }, 8), { width: 854, height: MAX_SIDE });
  assert.deepEqual(targetSize({ width: 333, height: 333 }, 1), { width: 334, height: 334 });
});

test("ffmpeg renders a sideways phone photo upright and caps a large one (real ffmpeg)", async () => {
  const big = await jpeg("big.jpg", 3000, 2000);
  const side = join(tmp, "side.jpg");
  await fs.writeFile(side, withOrientation(await fs.readFile(big), 6));
  const out = await renderClip(tools, side, join(tmp, "side.mp4"), { orientation: 6 });
  assert.deepEqual({ width: out.width, height: out.height }, { width: 854, height: MAX_SIDE });
  const { stdout } = await run("ffprobe", ["-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name,profile,nb_frames,pix_fmt", "-of", "csv=p=0", join(tmp, "side.mp4")]);
  assert.equal(stdout.trim(), "h264,Main,yuv420p,30");
});

test("the box check reads the public test card's packaged files", async () => {
  const pr = checkBoxes(await fs.readFile(join(REPO, "web", "research", "drm", "card-playready.mp4")));
  assert.equal(pr.ok, true); assert.deepEqual(pr.kids, ["5cfcb567f2f19d08a30b20483d92e930"]); assert.ok(pr.pssh.includes("9a04f07998404286ab92e65be0885f95"));
  const wv = checkBoxes(await fs.readFile(join(REPO, "web", "research", "drm", "card-widevine.mp4")));
  assert.equal(wv.ok, true); assert.ok(wv.pssh.includes("edef8ba979d64acea3c827dcd51d21ed"));
  assert.equal(checkBoxes(Buffer.from("not an mp4 at all")).ok, false);
});

test("the whole pipeline through the API with the real packager: upload → ready → files served (needs shaka-packager)", async (t) => {
  let have = false;
  try { await run(tools.packager, ["--version"]); have = true; } catch {}
  if (!have) {
    if (process.env.REQUIRE_PACKAGER === "1") assert.fail(`shaka-packager is required here and "${tools.packager}" did not run`);
    t.skip(`NOT RUN HERE: shaka-packager ("${tools.packager}") is not installed in this environment; CI runs it`);
    return;
  }
  const app = await startApp({ maxUploadBytes: 5 * 1024 * 1024 });
  try {
    const { cookie } = await login(app.base);
    const pic = await fs.readFile(await jpeg("card.jpg", 720, 960, "0x8c1f4e"));
    const r = await upload(app.base, cookie, withOrientation(pic, 6), "sideways card.jpg", "image/jpeg");
    assert.equal(r.status, 201);
    const id = (await r.json()).photo.id;
    const deadline = Date.now() + 150000; let rec;
    while (Date.now() < deadline) {
      rec = (await (await fetch(app.base + "/api/photos", { headers: { cookie } })).json()).photos.find((p) => p.id === id);
      if (rec.status === "ready" || rec.status === "failed") break;
      await new Promise((s) => setTimeout(s, 1000));
    }
    assert.equal(rec.status, "ready", `pipeline result: ${rec.status} ${rec.error || ""}`);
    assert.deepEqual({ w: rec.width, h: rec.height }, { w: 960, h: 720 }, "rotated upright");
    const full = app.app.store.get(id);
    assert.equal(full.boxes.playready.kids[0], full.prKid);
    for (const f of ["widevine.mpd", "playready.mpd", "video-widevine.mp4", "video-playready.mp4"]) {
      const m = await fetch(`${app.base}/media/${id}/${f}`, { headers: { cookie } });
      assert.equal(m.status, 200, f);
    }
    const mpd = await (await fetch(`${app.base}/media/${id}/widevine.mpd`, { headers: { cookie } })).text();
    assert.match(mpd, /video-widevine\.mp4/); assert.match(mpd, /edef8ba9-79d6-4ace-a3c8-27dcd51d21ed/i);
    await assert.rejects(fs.stat(join(app.app.store.dir(id), "clip.mp4")), "the clear clip is not kept");
    const view = await (await fetch(`${app.base}/view/${id}`, { headers: { cookie } })).text();
    assert.match(view, new RegExp(`/media/${id}/widevine.mpd`));
  } finally { await app.close(); }
});
