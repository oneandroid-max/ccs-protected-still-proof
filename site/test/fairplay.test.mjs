// Apple's FairPlay form for the test site: the licence tokens the job mints (site/axinom.mjs), the check
// every packaged form must pass (checkFairPlay), the pages' Axinom settings and public token, and, with
// the real shaka-packager (CI), the packaging itself: our own key and IV, decrypted back by an
// independent decryptor to exactly the picture, the worker's add / backfill / combined view, and the
// test card's form (tools/fairplay-card.mjs).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createDecipheriv, createHmac, randomBytes as nodeRandom } from "node:crypto";
import { readCommunicationKey, encryptContentKey, mintToken, newFairPlayIds, kidToUuid, AXINOM_PUBLIC_TEST, AXINOM_FAIRPLAY_LICENSE, AXINOM_FAIRPLAY_CERT } from "../axinom.mjs";
import { checkFairPlay, packageFairPlay, renderClip } from "../../service/lib/pipeline.mjs";
import { spawnSync } from "node:child_process";
import { deriveKey, derivePhotoKey, exportKeyHex, seal, sealText, openText, open, toBase64 } from "../crypto.js";
import { run as worker, readGallery, fairPlayCurrent, TOKEN_RENEW_DAYS } from "../worker.mjs";
import { run as exec, redactKeys } from "../../service/lib/util.mjs";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const tools = { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
const COM = { id: "0e2c58d1-7c4b-4f3e-9a51-3d1f0b7e6a42", key: nodeRandom(32) }; // a throwaway communication key
const b64url = (s) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
// on GitHub, what a test measured is also written as a notice on the run (readable without the log)
const notice = (title, msg) => { if (process.env.GITHUB_ACTIONS === "true") console.log(`::notice title=${title}::${msg}`); };
const unwrapKey = (comKey, kidHex, encB64) => { const d = createDecipheriv("aes-256-cbc", comKey, Buffer.from(kidHex, "hex")); d.setAutoPadding(false); return Buffer.concat([d.update(Buffer.from(encB64, "base64")), d.final()]).toString("hex"); };

test("the communication key is read strictly: both values, a GUID, 32 bytes; the id kept as given; no value in a message", () => {
  assert.throws(() => readCommunicationKey("", ""), /not set/);
  assert.throws(() => readCommunicationKey(COM.id, ""), /not set/);
  assert.throws(() => readCommunicationKey("not-a-guid", COM.key.toString("base64")), /not a GUID/);
  const short = nodeRandom(16).toString("base64");
  assert.throws(() => readCommunicationKey(COM.id, short), (e) => /32 bytes/.test(e.message) && !e.message.includes(short));
  const c = readCommunicationKey(` ${COM.id.toUpperCase()} `, ` ${COM.key.toString("base64")}\n`);
  assert.equal(c.id, COM.id.toUpperCase(), "kept as given (trimmed): Axinom compares it with its own record"); assert.ok(c.key.equals(COM.key));
});

test("a failing command's message carries no key (it can reach a public log)", async () => {
  const keyArg = "label=:key_id=00112233445566778899aabbccddeeff:key=0123456789abcdef0123456789abcdef";
  const e = await exec(process.execPath, ["-e", "process.exit(3)", "--", "--keys", keyArg, "-decryption_key", "fc35340837310cc0fb53de97e22a69e0"]).catch((x) => x);
  assert.ok(e instanceof Error);
  for (const secret of ["0123456789abcdef0123456789abcdef", "fc35340837310cc0fb53de97e22a69e0"]) assert.ok(!e.message.includes(secret), "no key in: " + e.message);
  assert.match(e.message, /key_id=00112233445566778899aabbccddeeff:key=<redacted>/, "key ids stay (they are not secret)");
  assert.equal(redactKeys("--aes_signing_key 1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9"), "--aes_signing_key <redacted>");
  // a long message is redacted before it is cut, so no tail of a key survives the cut
  const long = await exec(process.execPath, ["-e", "process.exit(3)", "--", "x".repeat(900), "--keys", keyArg, "y".repeat(10)]).catch((x) => x);
  assert.ok(!/[0-9a-f]{8}/.test(long.message.replace(/key_id=[0-9a-f]{32}/g, "")), "no run of key digits survives: " + long.message.slice(-160));
});

test("a minted token: HS256 under the communication key, the content key encrypted for Axinom the way its quick start does, its policy hardened instead of relaxed", () => {
  const ids = newFairPlayIds();
  for (const k of ["kid", "key", "iv"]) assert.match(ids[k], /^[0-9a-f]{32}$/, k);
  assert.equal(ids.keyUri, `skd://${kidToUuid(ids.kid)}:${ids.iv.toUpperCase()}`);
  assert.match(ids.keyUri, /^skd:\/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9A-F]{32}$/);
  const now = new Date("2026-10-11T12:00:00Z");
  const token = mintToken(COM, ids.kid, ids.key, { now, days: 60 });
  const [h, b, sig] = token.split(".");
  assert.deepEqual(b64url(h), { alg: "HS256", typ: "JWT" });
  assert.equal(sig, createHmac("sha256", COM.key).update(`${h}.${b}`).digest("base64url"), "signed with the communication key");
  assert.notEqual(sig, createHmac("sha256", nodeRandom(32)).update(`${h}.${b}`).digest("base64url"));
  const p = b64url(b);
  assert.equal(p.version, 1); assert.equal(p.com_key_id, COM.id);
  assert.equal(p.message.type, "entitlement_message"); assert.equal(p.message.version, 2);
  assert.ok(Date.parse(p.begin_date) < now.getTime() && Date.parse(p.expiration_date) === now.getTime() + 60 * 86400000);
  assert.equal(p.message.license.allow_persistence, false);
  assert.equal(p.message.license.expiration_datetime, p.expiration_date);
  const k = p.message.content_keys_source.inline;
  assert.equal(k.length, 1); assert.equal(k[0].id, kidToUuid(ids.kid));
  assert.equal(unwrapKey(COM.key, ids.kid, k[0].encrypted_key), ids.key, "the encrypted key opens, with an independent decryptor, to the content key");
  assert.equal(k[0].usage_policy, "Policy A", "the policy reference every Axinom example carries");
  assert.deepEqual(p.message.content_key_usage_policies, [{ name: "Policy A", playready: { min_device_security_level: 3000 } }], "the same shape, hardened: PlayReady hardware clients only");
  assert.ok(!JSON.stringify(p).includes("786627D8"), "no virtual-machine play enabler");
  assert.equal(encryptContentKey(COM.key, ids.kid, ids.key), k[0].encrypted_key);
  assert.throws(() => encryptContentKey(COM.key, "zz", ids.key), /32 hex/);
  assert.equal(kidToUuid("4060A865887842679CBF91AE5BAE1E72"), "4060a865-8878-4267-9cbf-91ae5bae1e72");
});

test("the pages use Axinom's licence service, certificate and PUBLIC token, the same in both, and the token unlocks only the public test key", async () => {
  const route1 = await fs.readFile(join(REPO, "web", "research", "drm", "index.html"), "utf8");
  const apple = await fs.readFile(join(REPO, "web", "research", "apple", "index.html"), "utf8");
  const tok1 = route1.match(/const AXINOM_PUBLIC_TOKEN = "([^"]+)"/)[1], tok2 = apple.match(/const TOKEN = "([^"]+)"/)[1];
  assert.equal(tok1, tok2, "one public token on both pages");
  const p = b64url(tok1.split(".")[1]);
  assert.equal(p.com_key_id, "69e54088-e9e0-4530-8c1a-1eb6dcd0d14e", "Axinom's own public test account");
  assert.deepEqual(p.message.content_keys_source.inline.map((x) => x.id), [kidToUuid(AXINOM_PUBLIC_TEST.kid)], "it licenses the public test key and nothing else");
  assert.equal(AXINOM_PUBLIC_TEST.key, "fc35340837310cc0fb53de97e22a69e0", "the key Axinom publishes for it (/DU0CDcxDMD7U96X4ipp4A==)");
  for (const [page, lic, cert] of [[route1, /const AXINOM_LICENSE = "([^"]+)"/, /const AXINOM_CERT = "([^"]+)"/], [apple, /const LICENSE = "([^"]+)"/, /const CERT = "([^"]+)"/]]) {
    assert.equal(page.match(lic)[1], AXINOM_FAIRPLAY_LICENSE); assert.equal(page.match(cert)[1], AXINOM_FAIRPLAY_CERT);
  }
});

test("every test value the workflow guard accepts makes the route-1 page play the TEST CARD; the Apple switch holds only dates", async () => {
  const guard = await fs.readFile(join(REPO, "tools", "check-workflow-links.mjs"), "utf8");
  const values = JSON.parse(guard.match(/const SAFE_VALUES = (\[[^\]]+\]);/)[1]);
  const page = await fs.readFile(join(REPO, "web", "research", "drm", "index.html"), "utf8");
  const testLine = page.match(/const TEST = ([^;]+);/)[1].split("||").map((x) => x.trim());
  assert.match(page, /const CARD = TEST \|\| params\.get\("clip"\) === "card";/);
  for (const v of values) {
    const [k, val] = v.split("=");
    if (k === "clip") { assert.equal(val, "card"); continue; }
    const name = page.match(new RegExp(`const (TEST_[A-Z]+) = params\\.get\\("${k}"\\) === "${val}";`));
    assert.ok(name, `the page reads ${v}`);
    assert.ok(testLine.includes(name[1]), `${v} (${name[1]}) is part of TEST, so it plays the card`);
  }
  const measured = JSON.parse(page.match(/const FAIRPLAY_MEASURED = (\{[^}]*\});/)[1]);
  assert.deepEqual(Object.keys(measured).sort(), ["Mac", "iPhone/iPad"]);
  for (const [k, v] of Object.entries(measured)) assert.ok(v === "" || /^\d{4}-\d{2}-\d{2}$/.test(v), `${k}: empty, or the date of a measurement`);
});

// A minimal fragmented MP4 with the boxes checkFairPlay and checkBoxes read: an encrypted sample entry
// whose 'tenc' carries the key id and (for 'cbcs') a constant IV, and fragments, each with its sample
// table ('trun': sizes, and flags saying which samples are keyframes) and its sample-encryption box
// ('senc': per sample one subsample, 10 clear bytes, then `prot` protected ones). The keyframe flags are
// written the three ways the standard allows: per sample (as shaka-packager writes them), or as the first
// sample's flags with the rest from the fragment's defaults ('tfhd') or from the movie's ('trex').
const box = (type, ...parts) => { const body = Buffer.concat(parts.map((p) => Buffer.isBuffer(p) ? p : Buffer.from(p))); const h = Buffer.alloc(8); h.writeUInt32BE(8 + body.length); h.write(type, 4, "latin1"); return Buffer.concat([h, body]); };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }, u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const NOT_KEY = 0x10000; // sample_is_non_sync_sample
const senc = (prot, ivSize, count = prot.length) => box("senc", Buffer.from([0, 0, 0, 2]), u32(count), ...prot.flatMap((p) => [Buffer.alloc(ivSize), u16(1), u16(10), u32(p)]));
function fakeFile({ scheme = "cbcs", kid, iv, perSampleIvSize = 0, fragments = 1, prot = [900, 700], sizes = prot.map((p) => 10 + p), flags = [0, NOT_KEY], defaults = "per-sample", sencCount = prot.length }) {
  const tenc = box("tenc", Buffer.from([1, 0, 0, 0, 0, 0x19, 1, perSampleIvSize]), Buffer.from(kid, "hex"), perSampleIvSize ? Buffer.alloc(0) : Buffer.concat([Buffer.from([16]), Buffer.from(iv, "hex")]));
  const sinf = box("sinf", box("frma", "avc1"), box("schm", Buffer.from([0, 0, 0, 0]), scheme, Buffer.from([0, 1, 0, 0])), box("schi", tenc));
  const encv = box("encv", Buffer.alloc(78), sinf);
  const stsd = box("stsd", Buffer.from([0, 0, 0, 0, 0, 0, 0, 1]), encv);
  const trex = box("trex", Buffer.from([0, 0, 0, 0]), u32(1), u32(1), u32(0), u32(0), u32(defaults === "trex" ? flags[1] : 0));
  const moov = box("moov", box("trak", box("mdia", box("minf", box("stbl", stsd)))), box("mvex", trex));
  const table = defaults === "per-sample"
    ? [box("tfhd", Buffer.from([0, 2, 0, 0]), u32(1)), box("trun", Buffer.from([0, 0, 0x06, 0x01]), u32(sizes.length), u32(0), ...sizes.flatMap((s, i) => [u32(s), u32(flags[i])]))]
    : [defaults === "tfhd" ? box("tfhd", Buffer.from([0, 2, 0, 0x20]), u32(1), u32(flags[1])) : box("tfhd", Buffer.from([0, 2, 0, 0]), u32(1)),
       box("trun", Buffer.from([0, 0, 0x02, 0x05]), u32(sizes.length), u32(0), u32(flags[0]), ...sizes.map(u32))];
  const frags = Array.from({ length: fragments }, () => box("moof", box("traf", ...table, senc(prot, perSampleIvSize, sencCount), box("saiz", Buffer.alloc(9)), box("saio", Buffer.alloc(12)))));
  return Buffer.concat([moov, ...frags]);
}

test("the check every FairPlay form must pass: Apple's key line with this address, 'cbcs', this key id, this IV, every sample recorded whole and protected, every keyframe encrypted", () => {
  const ids = newFairPlayIds();
  const playlist = `#EXTM3U\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI="${ids.keyUri}",KEYFORMATVERSIONS="1",KEYFORMAT="com.apple.streamingkeydelivery"\n#EXTINF:2,\nvideo.mp4\n`;
  const good = checkFairPlay(playlist, fakeFile(ids), ids);
  assert.deepEqual(good.problems, []); assert.equal(good.ok, true);
  const counts = (r) => [r.samples, r.samplesMarked, r.samplesEncrypted, r.keyframes, r.keyframesEncrypted, r.protectedBytes];
  assert.deepEqual([good.scheme, good.kid, good.iv, ...counts(good)], ["cbcs", ids.kid, ids.iv, 2, 2, 2, 1, 1, 1600]);
  // a still picture's shape (measured from shaka-packager on a solid colour): a keyframe carrying the
  // picture, then near-empty frames whose protected range is under one block, so nothing in them is encrypted
  const still = checkFairPlay(playlist, fakeFile({ ...ids, prot: [104, 13, 10] , flags: [0, NOT_KEY, NOT_KEY] }), ids);
  assert.deepEqual(still.problems, [], "a still's near-empty frames are fine");
  assert.deepEqual(counts(still), [3, 3, 1, 1, 1, 127], "and counted honestly: 3 protected, 1 encrypted");
  // which samples are keyframes is read however the file says it (the fragment's or the movie's defaults)
  for (const defaults of ["tfhd", "trex"]) {
    const r = checkFairPlay(playlist, fakeFile({ ...ids, prot: [104, 13, 10], flags: [0, NOT_KEY, NOT_KEY], defaults }), ids);
    assert.deepEqual([r.problems, r.keyframes, r.keyframesEncrypted], [[], 1, 1], `keyframes from the ${defaults} defaults`);
    const bad = checkFairPlay(playlist, fakeFile({ ...ids, prot: [13, 104, 10], flags: [0, NOT_KEY, NOT_KEY], defaults }), ids);
    assert.ok(bad.problems.some((p) => /1 of 1 keyframes have no encrypted block/.test(p)), `${defaults}: ${JSON.stringify(bad.problems)}`);
  }
  // each way it can be wrong is named
  const other = newFairPlayIds();
  const cases = [
    [checkFairPlay(playlist.replace("SAMPLE-AES", "AES-128"), fakeFile(ids), ids), /not SAMPLE-AES/],
    [checkFairPlay(playlist.replace(ids.keyUri, other.keyUri), fakeFile(ids), ids), /key address/],
    [checkFairPlay(playlist.replace("com.apple.streamingkeydelivery", "identity"), fakeFile(ids), ids), /Apple's key format/],
    [checkFairPlay(playlist.replace(/#EXT-X-KEY.*\n/, ""), fakeFile(ids), ids), /not SAMPLE-AES/],
    [checkFairPlay(playlist, fakeFile({ ...ids, scheme: "cenc" }), ids), /scheme is cenc/],
    [checkFairPlay(playlist, fakeFile({ ...ids, kid: other.kid }), ids), /key id/],
    [checkFairPlay(playlist, fakeFile({ ...ids, iv: other.iv }), ids), /constant IV/],
    [checkFairPlay(playlist, fakeFile({ ...ids, perSampleIvSize: 8 }), ids), /constant IV/],
    [checkFairPlay(playlist, fakeFile({ ...ids, fragments: 0 }), ids), /sample-encryption boxes/],
    [checkFairPlay(playlist, fakeFile({ ...ids, fragments: 0 }), ids), /carries no samples/],
    [checkFairPlay(playlist, fakeFile({ ...ids, prot: [900, 0] }), ids), /1 of 2 samples have no protected bytes/],
    [checkFairPlay(playlist, fakeFile({ ...ids, prot: [0, 0] }), ids), /2 of 2 samples have no protected bytes/],
    // the keyframe carries the picture: under one block there, nothing of the picture is encrypted
    [checkFairPlay(playlist, fakeFile({ ...ids, prot: [15, 900] }), ids), /1 of 1 keyframes have no encrypted block/],
    [checkFairPlay(playlist, fakeFile({ ...ids, prot: [900, 13, 15], flags: [0, NOT_KEY, 0] }), ids), /1 of 2 keyframes have no encrypted block/],
    [checkFairPlay(playlist, fakeFile({ ...ids, flags: [NOT_KEY, NOT_KEY] }), ids), /no sample is marked as a keyframe/],
    // bytes of a sample outside its record would be in the clear
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910, 2710] }), ids), /1 of 2 samples are not covered whole/],
    // a sample with no record at all, and records that do not match the samples
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910, 710, 500], flags: [0, NOT_KEY, 0] }), ids), /different number of encryption records/],
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910, 710, 500], flags: [0, NOT_KEY, 0] }), ids), /1 of 3 samples have no protected bytes/],
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910], flags: [0] }), ids), /different number of encryption records/],
    // a file or a record cut short is named, never read past: the file ending inside a box, or inside a box's header
    [checkFairPlay(playlist, (() => { const f = fakeFile(ids); return f.subarray(0, f.length - 30); })(), ids), /cannot be read: a fragment's box is cut short/],
    [checkFairPlay(playlist, (() => { const f = fakeFile(ids); return f.subarray(0, f.length - 33); })(), ids), /cannot be read: a fragment's box is cut short/],
    [checkFairPlay(playlist, fakeFile({ ...ids, sencCount: 3 }), ids), /cannot be read: a fragment's encryption record is cut short/],
    // a sample count no file could hold is refused, not looped over (records and table entries of no bytes)
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("senc"); f[at + 7] = 0; f.writeUInt32BE(0xffffffff, at + 8); return f; })(), ids), /cannot be read: a fragment lists 4294967295 samples/],
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("trun"); f[at + 6] = 0; f.writeUInt32BE(0xffffffff, at + 8); return f; })(), ids), /cannot be read: a fragment lists 4294967295 samples/],
  ];
  for (const [r, re] of cases) { assert.equal(r.ok, false, `a form that should fail with ${re} passed the check`); assert.ok(r.problems.some((p) => re.test(p)), `${re} in ${JSON.stringify(r.problems)}`); }
});

// ---- with the real shaka-packager (CI) ----
async function havePackager(t) {
  try { await exec(tools.packager, ["--version"]); return true; } catch {}
  if (process.env.REQUIRE_PACKAGER === "1") assert.fail(`shaka-packager is required here and "${tools.packager}" did not run`);
  t.skip(`NOT RUN HERE: shaka-packager ("${tools.packager}") is not installed in this environment; CI runs it`);
  return false;
}
const tmp = await fs.mkdtemp(join(tmpdir(), "fp-test-"));
const solid = async (name, w, h, color) => { const f = join(tmp, name); await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", `color=c=${color}:s=${w}x${h}:d=1`, "-frames:v", "1", "-update", "1", f]); return f; };
async function frame(file, extra = []) {
  const raw = file + "." + Math.random().toString(16).slice(2) + ".rgb";
  await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-xerror", "-y", ...extra, "-i", file, "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", raw]);
  const px = await fs.readFile(raw); await fs.rm(raw, { force: true }); return px;
}
const centre = (px, w, h) => { const o = (Math.floor(h / 2) * w + Math.floor(w / 2)) * 3; return [px[o], px[o + 1], px[o + 2]]; };
const near = (a, b, tol = 14) => a.every((v, i) => Math.abs(v - b[i]) <= tol);

test("packaged for FairPlay with the real packager: Apple's playlist, 'cbcs' under our key and IV, and an independent decryptor gives the picture back (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const dir = await fs.mkdtemp(join(tmp, "pkg-"));
  await renderClip(tools, await solid("red.png", 640, 480, "0xc0392b"), join(dir, "clip.mp4"));
  const ids = newFairPlayIds();
  await packageFairPlay(tools.packager, dir, ids);
  const master = await fs.readFile(join(dir, "fp", "master.m3u8"), "utf8"), media = await fs.readFile(join(dir, "fp", "video.m3u8"), "utf8");
  assert.match(master, /video\.m3u8/, "the master playlist names the media playlist");
  const data = await fs.readFile(join(dir, "fp", "video.mp4"));
  const check = checkFairPlay(media, data, ids);
  assert.deepEqual(check.problems, [], media);
  // the files decrypt with OUR key (ffmpeg's own 'cbcs' decryption, not the packager's) to the red picture
  const clear = await frame(join(dir, "clip.mp4"));
  const back = await frame(join(dir, "fp", "video.mp4"), ["-decryption_key", ids.key]);
  assert.ok(back.equals(clear), "decrypted, the first frame is exactly the clear clip's");
  assert.ok(near(centre(back, 640, 480), [192, 57, 43]), "and it is the red picture");
  // and not with another key
  let wrong = null; try { wrong = await frame(join(dir, "fp", "video.mp4"), ["-decryption_key", newFairPlayIds().key]); } catch {}
  assert.ok(!wrong || !wrong.equals(clear), "another key does not give the picture back");
  notice("FairPlay packaging", `checkFairPlay ok (scheme ${check.scheme}, kid ${check.kid}, iv ${check.iv}; ${check.samples} samples, every one recorded whole and protected, ${check.keyframesEncrypted} of ${check.keyframes} keyframes encrypted, ${check.samplesEncrypted} samples with an encrypted block); ${data.length} bytes; key line: ${media.split("\n").find((l) => l.startsWith("#EXT-X-KEY"))}; decrypted by ffmpeg with our key: first frame identical to the clear clip, centre ${centre(back, 640, 480)}; another key: ${wrong ? "a different frame" : "decoding refused"}`);
});

test("the worker with the Axinom key: a new picture gets its Apple form, its token (sealed) carries the key that decrypts it; the combined view too; a backfill adds the form to an older picture (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const KEY = await deriveKey("a test password, twelve+", toBase64(new Uint8Array(16).fill(7)), 1000);
  const KEY_HEX = await exportKeyHex(KEY);
  const siteDir = await fs.mkdtemp(join(tmp, "site-"));
  const upload = async (file) => { const f = join(tmp, "up-" + Math.random().toString(16).slice(2)); await fs.writeFile(f, await seal(KEY, await fs.readFile(file))); return f; };
  const add = async (id, file, com) => { process.env.WORKER_BLOB_FILE = await upload(file); return worker({ payload: { action: "add", id, name: id + ".png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools, com }); };
  const A = "a".repeat(24), B = "b".repeat(24);
  // B is prepared BEFORE the key exists: no Apple form
  assert.equal((await add(B, await solid("blue.png", 480, 640, "0x1f4e8c"), null)).status, "ready");
  assert.ok(!(await fs.readdir(join(siteDir, "photos", B))).some((f) => /^fp/.test(f)), "no Apple form without the key");
  // A is prepared with it
  assert.equal((await add(A, await solid("green.png", 640, 480, "0x27ae60"), COM)).status, "ready");
  async function verify(id, want, w, h) {
    const dir = join(siteDir, "photos", id);
    const meta = JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(dir, "meta.json.enc")))));
    assert.match(meta.fairplay.master, /^fp-[0-9a-f]{8}\/master\.m3u8$/);
    const folder = meta.fairplay.master.split("/")[0];
    assert.deepEqual((await fs.readdir(join(dir, folder))).sort(), ["master.m3u8", "token.enc", "video.m3u8", "video.mp4"], "the form's folder holds its files AND its sealed token");
    assert.deepEqual((await fs.readdir(dir)).filter((f) => /^fp/.test(f)), [folder], "one Apple form, nothing half-made");
    const token = await openText(KEY, new Uint8Array(await fs.readFile(join(dir, folder, "token.enc"))));
    const p = b64url(token.split(".")[1]); const k = p.message.content_keys_source.inline[0];
    assert.equal(p.com_key_id, COM.id); assert.equal(meta.fairplay.comKeyId, COM.id); assert.equal(meta.fairplay.expires, p.expiration_date, "the meta records which key made the token and when it ends");
    const contentKey = unwrapKey(COM.key, k.id.replace(/-/g, ""), k.encrypted_key);
    const media = await fs.readFile(join(dir, folder, "video.m3u8"), "utf8");
    assert.ok(media.includes(`URI="${meta.fairplay.keyUri}"`) && meta.fairplay.keyUri.startsWith(`skd://${k.id}:`), "the playlist's key address names the token's key id");
    const px = await frame(join(dir, folder, "video.mp4"), ["-decryption_key", contentKey]);
    assert.ok(near(centre(px, w, h), want), `${id}: the key inside the token decrypts its Apple form to its own picture: ${centre(px, w, h)}`);
    return { meta, token, folder };
  }
  const a1 = await verify(A, [39, 174, 96], 640, 480);
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === A).fairplay, true);
  // a combined view made WITHOUT the key has no form, and is kept while the key is absent ...
  const mosaic = (com) => worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, com });
  const mosaicMeta = async () => JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(siteDir, "mosaic", "meta.json.enc")))));
  assert.equal((await mosaic(null)).status, "ready"); assert.equal((await mosaicMeta()).fairplay, null);
  assert.equal((await mosaic(null)).status, "current");
  // ... and remade with its own form once the key exists; then kept
  assert.equal((await mosaic(COM)).status, "ready", "the same pictures, but no Apple form: remade");
  const mm = await mosaicMeta();
  assert.match(mm.fairplay.master, /^fp-[0-9a-f]{8}\/master\.m3u8$/);
  await fs.access(join(siteDir, "mosaic", mm.fairplay.master)); await fs.access(join(siteDir, "mosaic", mm.fairplay.master.split("/")[0], "token.enc"));
  assert.equal((await mosaic(COM)).status, "current");
  // a page's request can never start the backfill (it has its own workflow and queue)
  await assert.rejects(worker({ payload: { key: KEY_HEX, action: "fairplay" }, siteDir, tools, com: COM }), /unknown action/);
  // the backfill: B gets its form; A (already has one) is left exactly as it is
  const r = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, com: COM });
  assert.deepEqual({ added: r.added, already: r.already, failed: r.failed }, { added: 1, already: 1, failed: 0 });
  await verify(B, [31, 78, 140], 480, 640);
  const a2 = await verify(A, [39, 174, 96], 640, 480);
  assert.equal(a2.folder, a1.folder); assert.equal(a2.token, a1.token, "a picture that has its form is not repackaged");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === B).fairplay, true, "the list records it");
  // a second backfill changes nothing
  const counts = (r) => ({ added: r.added, already: r.already, failed: r.failed });
  assert.deepEqual(counts(await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, com: COM })), { added: 0, already: 2, failed: 0 });
  // RENEWAL: a token close to its end, or made with another Axinom key, is renewed (a new form), the old one removed
  const metaPath = join(siteDir, "photos", A, "meta.json.enc");
  const m = JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(metaPath))));
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, COM), true);
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, COM, Date.parse(m.fairplay.expires) - (TOKEN_RENEW_DAYS - 1) * 86400000), false, "less than the renewal margin left: not current");
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, { ...COM, id: "11111111-2222-3333-4444-555555555555" }), false, "made with another key: not current");
  await fs.writeFile(metaPath, await sealText(KEY, JSON.stringify({ ...m, fairplay: { ...m.fairplay, expires: new Date(Date.now() + 3 * 86400000).toISOString() } })));
  assert.deepEqual(counts(await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, com: COM })), { added: 1, already: 1, failed: 0 }, "the expiring one is renewed");
  const a3 = await verify(A, [39, 174, 96], 640, 480);
  assert.notEqual(a3.folder, a1.folder, "a new form"); await assert.rejects(fs.access(join(siteDir, "photos", A, a1.folder)), "the old form is gone");
  const OTHER = { id: "11111111-2222-3333-4444-555555555555", key: nodeRandom(32) };
  const r2 = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, com: OTHER });
  assert.deepEqual(counts(r2), { added: 2, already: 0, failed: 0 }, "another Axinom key: every form is remade under it");
  assert.equal(JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(siteDir, "mosaic", "meta.json.enc"))))).fairplay.comKeyId, OTHER.id, "the combined view too");
  // without the key the backfill refuses plainly
  await assert.rejects(worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, com: null }), /not set/);
  // a picture whose form fails to package is still ready for everything else
  process.env.WORKER_BLOB_FILE = await upload(await solid("grey.png", 320, 240, "0x7f8c8d"));
  const broken = await worker({ payload: { action: "add", id: "c".repeat(24), name: "c.png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools: { ...tools, packager: tools.packager }, com: { ...COM, key: Buffer.alloc(31) } });
  assert.equal(broken.status, "ready", "a key the token cannot be made with leaves the picture ready elsewhere");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === "c".repeat(24)).fairplay, false);
  assert.ok(!(await fs.readdir(join(siteDir, "photos", "c".repeat(24)))).some((f) => /^fp/.test(f)), "and no half-made Apple form is left behind");
  notice("FairPlay worker", `added with the key: ${A} (its token's key decrypts its form to its colour; the token inside the form's folder); combined view remade with its form; backfill: 1 added, 1 already, 0 failed, then 0/2/0; an expiring token renewed (1/1/0), another Axinom key: 2/0/0; a page request for the backfill refused; a bad key left the picture ready without a form`);
});

test("the test card's Apple form (tools/fairplay-card.mjs): Axinom's public key, our IV, decrypted back two ways to exactly the card (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const { buildFairPlayCard, cardFairPlayIds } = await import("../../tools/fairplay-card.mjs");
  const out = await fs.mkdtemp(join(tmp, "card-"));
  const info = await buildFairPlayCard({ tools, outDir: out });
  assert.deepEqual((await fs.readdir(out)).sort(), ["info.json", "master.m3u8", "video.m3u8", "video.mp4"]);
  assert.deepEqual(info.decryptCheck.ffmpeg, 0); assert.deepEqual(info.decryptCheck.shakaPackager, 0);
  const u = info.decryptCheck.undecrypted;
  assert.ok(u === "decoding refused" || u === "no frame decoded" || /^a frame of another size/.test(u) || (typeof u === "number" && u >= 40), "undecrypted it is not the card: " + u);
  assert.ok(info.samples > 0 && info.samplesEncrypted === info.samples, `every sample encrypted: ${info.samplesEncrypted} of ${info.samples}`);
  // the public form comes out the same byte for byte every time (fixed clock), so a run with nothing new commits nothing
  const again = await fs.mkdtemp(join(tmp, "card-again-"));
  await new Promise((r) => setTimeout(r, 1100)); // a different second on the clock
  await buildFairPlayCard({ tools, outDir: again });
  for (const f of ["master.m3u8", "video.m3u8", "video.mp4", "info.json"]) assert.ok((await fs.readFile(join(out, f))).equals(await fs.readFile(join(again, f))), `${f}: the same bytes on a second build`);
  assert.equal(info.keyUri, cardFairPlayIds().keyUri);
  assert.ok(info.keyUri.startsWith("skd://4060a865-8878-4267-9cbf-91ae5bae1e72:"), "the key Axinom's public token licenses");
  assert.deepEqual([info.width, info.height], [720, 960]);
  notice("FairPlay card", `${info.keyUri}; ${info.bytes} bytes; decryptCheck ${JSON.stringify(info.decryptCheck)}; ${info.packager}`);
  // the own-account form: a random key of its own, and a token minted by OUR account (here a throwaway one)
  const { ownCardCurrent, buildOwnCard } = await import("../../tools/fairplay-card.mjs");
  const root = await fs.mkdtemp(join(tmp, "card-own-"));
  assert.equal(await ownCardCurrent(root, COM), false, "nothing there yet");
  const own = await buildOwnCard({ tools, root, com: COM });
  const ownDir = join(root, own.folder);
  assert.deepEqual((await fs.readdir(root)).sort(), ["current.json", own.folder].sort(), "one folder, named by current.json");
  assert.equal(JSON.parse(await fs.readFile(join(root, "current.json"), "utf8")).folder, own.folder);
  assert.deepEqual((await fs.readdir(ownDir)).sort(), ["info.json", "master.m3u8", "token.txt", "video.m3u8", "video.mp4"]);
  assert.ok(!own.keyUri.startsWith("skd://4060a865"), "not the public test key");
  const token = (await fs.readFile(join(ownDir, "token.txt"), "utf8")).trim();
  const [h, b, sig] = token.split(".");
  assert.equal(sig, createHmac("sha256", COM.key).update(`${h}.${b}`).digest("base64url"), "minted by our account's key");
  const k = b64url(b).message.content_keys_source.inline[0];
  assert.ok(own.keyUri.startsWith(`skd://${k.id}:`), "the token names the form's key id");
  const ownKey = unwrapKey(COM.key, k.id.replace(/-/g, ""), k.encrypted_key);
  const clearCard = await frame(join(REPO, "web", "research", "drm", "card-playready.mp4"), ["-decryption_key", "a64cde52f25e07a56d7770f4d31fc1f3"]);
  assert.ok((await frame(join(ownDir, "video.mp4"), ["-decryption_key", ownKey])).equals(clearCard), "the key inside our token decrypts it to exactly the card");
  assert.equal(own.decryptCheck.ffmpeg, 0);
  assert.equal(await ownCardCurrent(root, COM), true, "current: same account, 60 days left");
  assert.equal(await ownCardCurrent(root, { ...COM, id: "11111111-2222-3333-4444-555555555555" }), false, "another account: remade");
  assert.equal(await ownCardCurrent(root, COM, Date.parse(own.expires) - 13 * 86400000), false, "13 days left: remade");
  const renewed = await buildOwnCard({ tools, root, com: COM });
  assert.notEqual(renewed.folder, own.folder); assert.deepEqual((await fs.readdir(root)).sort(), ["current.json", renewed.folder].sort(), "a renewal is a fresh folder; the old one is gone");
  notice("FairPlay own card", `${own.keyUri}; token by the (test) account ${COM.id}; decryptCheck ${JSON.stringify(own.decryptCheck)}`);
});

// THE BACKFILL'S ENTRY, run as the workflow runs it (a child process, the real site/backfill.mjs) on a
// scratch site: the picture key is masked before anything else is printed and appears nowhere else; a
// password that does not open the gallery is a named error, not a quiet green run; a missing Axinom key is
// an error when started by hand and nothing to do on the weekly run.
test("the backfill's entry: the picture key masked first and nowhere else; a wrong password or a missing key named; the weekly run without a key does nothing", async () => {
  const PW = "a test password, twelve+", SALT = toBase64(new Uint8Array(16).fill(9));
  const site = await fs.mkdtemp(join(tmp, "bf-"));
  await fs.writeFile(join(site, "config.json"), JSON.stringify({ salt: SALT, iterations: 1000 }));
  const want = await exportKeyHex(await derivePhotoKey(await deriveKey(PW, SALT, 1000)));
  const env = { ...process.env, SITE_DIR: site, SITE_PASSWORD: PW, AXINOM_COM_KEY_ID: COM.id, AXINOM_COM_KEY: COM.key.toString("base64"), BACKFILL_RESULT: join(site, "result.json"), PACKAGER_BIN: "/nonexistent/packager", GITHUB_EVENT_NAME: "workflow_dispatch" };
  const go = (over = {}) => { const r = spawnSync(process.execPath, [join(REPO, "site", "backfill.mjs")], { encoding: "utf8", env: { ...env, ...over } }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; };
  const masked = (out) => { const lines = out.split("\n"); assert.equal(lines[0], `::add-mask::${want}`, "the first thing printed is the mask"); assert.equal(lines.filter((l) => l.includes(want)).length, 1, "and the key appears nowhere else"); };
  // an empty site: nothing to do, a green run that says so
  let r = go();
  assert.equal(r.code, 0, r.out); masked(r.out);
  assert.match(r.out, /::notice title=Apple backfill::done — 0 added or renewed, 0 already good, 0 failed; combined view none/);
  assert.equal(JSON.parse(await fs.readFile(join(site, "result.json"), "utf8")).status, "done");
  // a gallery the password opens: still masked first
  await fs.writeFile(join(site, "gallery.json.enc"), await sealText(await derivePhotoKey(await deriveKey(PW, SALT, 1000)), JSON.stringify({ photos: [] })));
  r = go(); assert.equal(r.code, 0, r.out); masked(r.out);
  // a gallery the password does NOT open: a named error, red
  await fs.writeFile(join(site, "gallery.json.enc"), await sealText(await derivePhotoKey(await deriveKey("another password altogether", SALT, 1000)), JSON.stringify({ photos: [] })));
  r = go(); assert.equal(r.code, 1, r.out); masked(r.out);
  assert.match(r.out, /::error title=Apple backfill::SITE_PASSWORD does not open the gallery/);
  // no Axinom key: an error when started by hand, nothing to do on the weekly run; a malformed one named
  r = go({ AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "" }); assert.equal(r.code, 1); assert.match(r.out, /::error title=Apple backfill::the Axinom communication key is not set/);
  r = go({ AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "", GITHUB_EVENT_NAME: "schedule" }); assert.equal(r.code, 0, r.out); assert.match(r.out, /::notice title=Apple backfill::the Axinom key is not set yet: nothing to renew/);
  r = go({ AXINOM_COM_KEY_ID: "not-a-guid" }); assert.equal(r.code, 1); assert.match(r.out, /::error title=Apple backfill::AXINOM_COM_KEY_ID is not a GUID/);
  assert.ok(!r.out.includes(COM.key.toString("base64")), "the Axinom key never printed");
  r = go({ SITE_PASSWORD: "" }); assert.equal(r.code, 1); assert.match(r.out, /SITE_PASSWORD is not set/);
});

after(async () => { await fs.rm(tmp, { recursive: true, force: true }); });
