// Apple's FairPlay form for the test site: the licence tokens the job mints (site/axinom.mjs), the check
// every packaged form must pass (checkFairPlay), the pages' Axinom settings and public token, and, with
// the real shaka-packager (CI), the packaging itself: our own key and IV, decrypted back by an
// independent decryptor to exactly the picture, the worker's add / backfill / combined view, and the
// test card's form (tools/fairplay-card.mjs).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, delimiter, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createDecipheriv, createHash, createHmac, randomBytes as nodeRandom } from "node:crypto";
import { readCommunicationKey, readAxinomSettings, encryptContentKey, mintToken, newFairPlayIds, kidToUuid, checkTokenWithAxinom, checkKeyWithAxinom, tokenSignedWith, comKeyCheck, TOKEN_CHECK_BODY_BYTES, TOKEN_CHECK_TIMEOUT_MS, AXINOM_PUBLIC_TEST, AXINOM_FAIRPLAY_LICENSE, AXINOM_FAIRPLAY_CERT, FAIRPLAY_LICENSE_ADDRESS } from "../axinom.mjs";
import { checkFairPlay, checkFairPlayBytes, verifyFairPlayBytes, readTrack, packageFairPlay, renderClip, SAMPLE_OPEN_MAX } from "../../service/lib/pipeline.mjs";
import { spawnSync } from "node:child_process";
import { deriveKey, derivePhotoKey, exportKeyHex, seal, sealText, openText, open, toBase64 } from "../crypto.js";
import { run as worker, readGallery, fairPlayCurrent, TOKEN_RENEW_DAYS, resultLines } from "../worker.mjs";
import { checkPackager, PACKAGER_SHA256 } from "../../service/lib/packager-pin.mjs";
import { mosaicCurrent } from "../app.js";
import { run as exec, redactKeys } from "../../service/lib/util.mjs";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
// The packager the tests run: the pinned build only, checked by its SHA-256 before any test runs it, and run by the path
// checked (the CI test step sets PACKAGER_BIN). Any other file is refused here, never run: with REQUIRE_PACKAGER=1 that
// ends the run; without it the tests that need the packager are skipped.
const pinnedPackager = await checkPackager(process.env.PACKAGER_BIN || "packager").catch((e) => { if (process.env.REQUIRE_PACKAGER === "1") throw e; return null; });
const tools = { ffmpeg: "ffmpeg", ffprobe: "ffprobe", packager: pinnedPackager || "/nonexistent/no-pinned-packager-here" };
const COM = { id: "0e2c58d1-7c4b-4f3e-9a51-3d1f0b7e6a42", key: nodeRandom(32) }; // a throwaway communication key
const OWN_LICENSE = "https://0a1b2c3d.drm-fairplay-licensing.axprod.net/AcquireLicense"; // an account's own licence address (a made-up prefix)
const b64url = (s) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
// the worker asks Axinom whether it accepts our key before it makes any Apple form; the tests answer for Axinom
const acceptKey = async () => ({ accepted: true, reached: true, status: 400, message: "Invalid license request. (answered by the test)" });
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
  assert.equal(c.license, AXINOM_FAIRPLAY_LICENSE, "without an address of its own: Axinom's shared one");
  assert.equal(readCommunicationKey(COM.id, COM.key.toString("base64"), OWN_LICENSE).license, OWN_LICENSE);
  for (const bad of ["https://licence.example.com/AcquireLicense", "http://0a1b2c3d.drm-fairplay-licensing.axprod.net/AcquireLicense", "https://0a1b2c3d.drm-widevine-licensing.axprod.net/AcquireLicense", "https://0a1b2c3d.drm-fairplay-licensing.axprod.net.example.com/AcquireLicense", "https://evil.example/collect?u=https://drm-fairplay-licensing.axprod.net/AcquireLicense"])
    assert.throws(() => readCommunicationKey(COM.id, COM.key.toString("base64"), bad), /not one of Axinom's/, bad);
});

test("the account's own licence address (site/axinom.json): the committed one is Axinom's FairPlay host with a prefix; none means the shared one; anything else is refused", async () => {
  const committed = await readAxinomSettings(join(REPO, "site"));
  assert.match(committed.fairplayLicense, FAIRPLAY_LICENSE_ADDRESS); assert.notEqual(committed.fairplayLicense, AXINOM_FAIRPLAY_LICENSE, "the account's own, not the shared one");
  const d = await fs.mkdtemp(join(tmp, "settings-"));
  assert.deepEqual(await readAxinomSettings(d), { fairplayLicense: AXINOM_FAIRPLAY_LICENSE }, "no file: the shared address");
  for (const [body, re] of [["not json", /not readable JSON/], [JSON.stringify({ fairplayLicense: "https://licence.example.com/AcquireLicense" }), /not one of Axinom's/], [JSON.stringify({ fairplayLicense: "https://a.b.drm-fairplay-licensing.axprod.net/AcquireLicense" }), /not one of Axinom's/],
    [JSON.stringify({ fairplayLicense: "https://evil.example/collect?u=https://drm-fairplay-licensing.axprod.net/AcquireLicense" }), /not one of Axinom's/], [JSON.stringify({ fairplayLicense: null }), /not one of Axinom's/], [JSON.stringify({ fairplayLicense: 7 }), /not one of Axinom's/], ["[]", /not an object of settings/], ["null", /not an object of settings/]]) {
    await fs.writeFile(join(d, "axinom.json"), body); await assert.rejects(readAxinomSettings(d), re, body);
  }
  await fs.writeFile(join(d, "axinom.json"), "{}");
  assert.deepEqual(await readAxinomSettings(d), { fairplayLicense: AXINOM_FAIRPLAY_LICENSE }, "no setting in the file: the shared address (only a missing setting means that)");
  notice("FairPlay licence address", `committed: ${committed.fairplayLicense}`);
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
  assert.deepEqual(p.message.content_key_usage_policies, [{ name: "Policy A", playready: { min_device_security_level: 3000 }, widevine: { device_security_level: "HW_SECURE_ALL" } }], "the same shape, hardened: PlayReady and Widevine hardware clients only");
  assert.ok(!JSON.stringify(p).includes("786627D8"), "no virtual-machine play enabler");
  assert.equal(encryptContentKey(COM.key, ids.kid, ids.key), k[0].encrypted_key);
  assert.throws(() => encryptContentKey(COM.key, "zz", ids.key), /32 hex/);
  assert.equal(kidToUuid("4060A865887842679CBF91AE5BAE1E72"), "4060a865-8878-4267-9cbf-91ae5bae1e72");
});

// The check that Axinom accepts our account's key (the key id and the key value as a pair), from a runner: a
// dummy request whose answer is about the request when the token is good, about the token when not. Axinom's
// answers below were measured 2026-10-11 17:15Z and 18:03Z (site/axinom.mjs).
test("the token check accepts only Axinom's answers about the request, never one about the token; out of reach is said so", async () => {
  const seen = [];
  const reply = (message) => async (url, init) => { seen.push({ url, init }); return { status: 400, headers: new Headers(message === null ? {} : { "X-AxDRM-ErrorMessage": message }) }; };
  const good = await checkTokenWithAxinom("h.p.s", OWN_LICENSE, reply("Invalid license request. Supported versions are 1, 2 or 3, but used version is 0."));
  assert.deepEqual([good.accepted, good.reached], [true, true]);
  assert.deepEqual([seen[0].url, seen[0].init.method, seen[0].init.headers["X-AxDRM-Message"], seen[0].init.body.length], [OWN_LICENSE, "POST", "h.p.s", TOKEN_CHECK_BODY_BYTES], "the token, to the account's address, with a dummy body");
  // a good token's answer at the other body sizes measured: still about the request
  for (const m of ["Invalid license request. License request total size is less than the expected header size.", "Invalid license request. The request body is missing."])
    assert.equal((await checkTokenWithAxinom("h.p.s", OWN_LICENSE, reply(m))).accepted, true, m);
  // about the token, or nothing: refused, with Axinom's words or the HTTP status. "Invalid license request." also
  // opens Axinom's answer about the token's own header (measured by the seventh review for a blank token): refused
  for (const m of ["Invalid DRM message. The signature is invalid.", "License denied. The DRM message references the ID of an unknown communication key.", 'Invalid license request. The "X-AxDRM-Message" HTTP header must have exactly one non-empty value.', "Invalid license request. Something else entirely.", "", null]) {
    const r = await checkTokenWithAxinom("h.p.s", OWN_LICENSE, reply(m));
    assert.deepEqual([r.accepted, r.reached], [false, true], `refused: ${JSON.stringify(m)}`); assert.ok(r.message.length > 0);
  }
  // something that is not a token is never sent
  const sentBefore = seen.length;
  for (const bad of ["", " ", "a,b.c.d", "TOKEN-1", "a.b"]) { const r = await checkTokenWithAxinom(bad, OWN_LICENSE, reply("Invalid license request. The request body is missing.")); assert.deepEqual([r.accepted, r.reached], [false, false], JSON.stringify(bad)); }
  assert.equal(seen.length, sentBefore, "nothing sent for what is not a token");
  // each try has its own time limit (passed to fetch as a signal); a server error is retried, then reported as Axinom out of reach
  let signals = 0, served = 0;
  const busy = await checkTokenWithAxinom("a.b.c", OWN_LICENSE, async (url, init) => { if (init.signal instanceof AbortSignal) signals++; served++; return { status: 503, headers: new Headers() }; }, { pause: async () => {} });
  assert.deepEqual([busy.accepted, busy.reached, served, signals], [false, false, 3, 3]); assert.match(busy.message, /^Axinom could not be reached \(3 tries\): Axinom answered HTTP 503$/);
  // each try is cut at its time limit (a server that never answers), and a 429 or a 500 is tried again, never taken
  // as an answer
  assert.equal(TOKEN_CHECK_TIMEOUT_MS, 20000);
  const limits = [];
  await checkTokenWithAxinom("h.p.s", OWN_LICENSE, reply("Invalid license request. Supported versions are 1, 2 or 3, but used version is 0."), { signalFor: (ms) => { limits.push(ms); return AbortSignal.timeout(ms); } });
  assert.deepEqual(limits, [20000], "each try, by default, is limited to 20 seconds");
  let started = 0; const t0 = Date.now();
  const silent = await checkTokenWithAxinom("h.p.s", OWN_LICENSE, (url, init) => { started++; return new Promise((_, reject) => { const hold = setTimeout(() => {}, 10000); init.signal.addEventListener("abort", () => { clearTimeout(hold); reject(init.signal.reason); }); }); } /* a silent server holds its connection open; here a timer does */, { pause: async () => {}, timeoutMs: 60 });
  const took = Date.now() - t0;
  assert.deepEqual([silent.accepted, silent.reached, started], [false, false, 3]); assert.ok(took >= 150 && took < 3000, `three tries cut at 60 ms each: ${took} ms`);
  assert.match(silent.message, /^Axinom could not be reached \(3 tries\): .*(timeout|aborted)/i);
  const codes = [429, 500];
  const third = await checkTokenWithAxinom("h.p.s", OWN_LICENSE, async () => { const c = codes.shift(); return c ? { status: c, headers: new Headers() } : { status: 400, headers: new Headers({ "X-AxDRM-ErrorMessage": "Invalid license request. Supported versions are 1, 2 or 3, but used version is 0." }) }; }, { pause: async () => {} });
  assert.deepEqual([third.accepted, third.reached, codes.length], [true, true, 0], "a 429 and a 500 tried again; the third answer counts");
  // Axinom out of reach: three tries, then said so plainly (never taken as accepted)
  let tries = 0; const pauses = [];
  const down = await checkTokenWithAxinom("h.p.s", OWN_LICENSE, async () => { tries++; throw Object.assign(new TypeError("fetch failed"), { cause: new Error("connect ECONNREFUSED (a test)") }); }, { pause: async (ms) => { pauses.push(ms); } });
  assert.deepEqual([down.accepted, down.reached, tries, pauses], [false, false, 3, [2000, 4000]]);
  assert.match(down.message, /^Axinom could not be reached \(3 tries\): connect ECONNREFUSED \(a test\)$/);
  const before = seen.length;
  await assert.rejects(checkTokenWithAxinom("h.p.s", "https://evil.example/collect?u=https://drm-fairplay-licensing.axprod.net/AcquireLicense", reply("x")), /not one of Axinom's/);
  assert.equal(seen.length, before, "nothing is sent to an address that is not Axinom's");
  // the key itself, asked with a token for a throwaway key: signed with this key, naming its id, to its address
  const asked = [];
  const k = await checkKeyWithAxinom({ ...COM, license: OWN_LICENSE }, async (url, init) => { asked.push([url, init.headers["X-AxDRM-Message"]]); return { status: 400, headers: new Headers({ "X-AxDRM-ErrorMessage": "Invalid license request. Supported versions are 1, 2 or 3, but used version is 0." }) }; });
  assert.equal(k.accepted, true); assert.equal(asked.length, 1); assert.equal(asked[0][0], OWN_LICENSE);
  assert.equal(tokenSignedWith(asked[0][1], COM.key), true, "signed with our key"); assert.equal(b64url(asked[0][1].split(".")[1]).com_key_id, COM.id, "naming our key id");
  // a token's signature read back with the key, and the key's check value: both tell a corrected key VALUE
  // (the same key id) from the one a form was made with
  const token = mintToken(COM, newFairPlayIds().kid, newFairPlayIds().key), other = nodeRandom(32);
  assert.equal(tokenSignedWith(token, COM.key), true); assert.equal(tokenSignedWith(token, other), false); assert.equal(tokenSignedWith("not.a-token", COM.key), false);
  assert.match(comKeyCheck(COM), /^[0-9a-f]{16}$/); assert.equal(comKeyCheck(COM), comKeyCheck({ ...COM })); assert.notEqual(comKeyCheck(COM), comKeyCheck({ ...COM, key: other }));
});

// The limit per try AS WIRED by default (the tenth review: the test above passes its own signalFor, so a default that
// waited ten times as long passed it too): no signalFor given, a silent server is cut at the limit itself
test("the token check's own default cuts a silent server at the limit it is given, not later", async () => {
  let started = 0; const t0 = Date.now();
  const r = await checkTokenWithAxinom("h.p.s", OWN_LICENSE, (url, init) => { started++; return new Promise((_, reject) => { const hold = setTimeout(() => {}, 10000); init.signal.addEventListener("abort", () => { clearTimeout(hold); reject(init.signal.reason); }); }); }, { tries: 1, timeoutMs: 100 });
  const took = Date.now() - t0;
  assert.deepEqual([r.accepted, r.reached, started], [false, false, 1]);
  assert.ok(took >= 90 && took < 600, `cut at 100 ms by the default signal: ${took} ms`);
});

test("the route-1 page uses Axinom's licence service, certificate and PUBLIC token, held once; the token unlocks only the public test key", async () => {
  const route1 = await fs.readFile(join(REPO, "web", "research", "drm", "index.html"), "utf8");
  const tok1 = route1.match(/const AXINOM_PUBLIC_TOKEN = "([^"]+)"/)[1];
  assert.equal(route1.split(tok1).length, 2, "the public token is written once on the page; Apple's test and the card's Apple form both use that one");
  const p = b64url(tok1.split(".")[1]);
  assert.equal(p.com_key_id, "69e54088-e9e0-4530-8c1a-1eb6dcd0d14e", "Axinom's own public test account");
  assert.deepEqual(p.message.content_keys_source.inline.map((x) => x.id), [kidToUuid(AXINOM_PUBLIC_TEST.kid)], "it licenses the public test key and nothing else");
  assert.equal(AXINOM_PUBLIC_TEST.key, "fc35340837310cc0fb53de97e22a69e0", "the key Axinom publishes for it (/DU0CDcxDMD7U96X4ipp4A==)");
  assert.equal(route1.match(/const AXINOM_LICENSE_ADDRESS = \/(.+)\/;/)[1], FAIRPLAY_LICENSE_ADDRESS.source, "the page sends a token only where site/axinom.mjs allows");
  assert.equal(route1.match(/const AXINOM_LICENSE = "([^"]+)"/)[1], AXINOM_FAIRPLAY_LICENSE); assert.equal(route1.match(/const AXINOM_CERT = "([^"]+)"/)[1], AXINOM_FAIRPLAY_CERT);
  // Apple's test (the one link for every device): those same settings, and only public material, never the photo
  assert.match(route1, /^ {4}async function protectedPlay\(videoId, p, url, what, token = AXINOM_PUBLIC_TOKEN, license = AXINOM_LICENSE\) \{$/m);
  assert.match(route1, /^ {6}player\.configure\(\{ drm: \{ servers: \{ "com\.apple\.fps": license \}, advanced: \{ "com\.apple\.fps": \{ serverCertificateUri: AXINOM_CERT \} \} \} \}\);$/m);
  const from = route1.indexOf("  async function appleTest() {"), to = route1.indexOf("\n  }\n", from);
  assert.ok(from > 0 && to > from, "Apple's test is where this test reads it");
  const body = route1.slice(from, to);
  assert.ok(!/\bCLIP\b|\btryOne\b|\bORDER\b|\.mpd\b|photo\.enc/.test(body), "Apple's test names nothing of the photo's");
  assert.deepEqual([...body.matchAll(/(?:protectedPlay\("v\w", "\w", |\.load\(|v\.src = )([^,);]+)/g)].map((m) => m[1]).sort(), ["APPLE_FILM", "APPLE_FILM_CLEAR", "APPLE_FILM_CLEAR", "CARD_FAIRPLAY.manifest", "ownBase + \"master.m3u8\"", "url"].sort(), "it plays the film, the film unprotected, the card's Apple form and the own card's: nothing else");
});

// Apple's test's own lines for our account's card (read from the route-1 page, never copied): the card is
// played only through the folder current.json names (8 hex characters, nothing else) and that folder's own
// token; with nothing made yet, or a folder name of any other shape, or no token there, nothing is played.
test("Apple's test plays our account's card only from the folder current.json names, with that folder's token", async () => {
  const page = await fs.readFile(join(REPO, "web", "research", "drm", "index.html"), "utf8");
  const from = page.indexOf("    let ownToken = null, ownBase = null, ownLicense = AXINOM_LICENSE,"), to = page.indexOf("\n  }\n", from);
  assert.ok(from > 0 && to > from, "the page's own-card lines are where this test reads them");
  const lines = page.slice(from, to), OWN = page.match(/const CARD_FAIRPLAY_OWN = "([^"]+)";/)[1], LICENSE = page.match(/const AXINOM_LICENSE = "([^"]+)";/)[1];
  const LICENSE_ADDRESS = new RegExp(page.match(/const AXINOM_LICENSE_ADDRESS = \/(.+)\/;/)[1]);
  assert.equal(OWN, "card-fairplay-own/");
  const runWith = async (files) => {
    const seen = [], calls = [];
    const fetch = async (url) => { seen.push(url); const k = url.replace(/\?v=\d+$/, ""); const body = files[k];
      return body === undefined ? { ok: false, json: async () => { throw new Error("404"); }, text: async () => "" } : { ok: true, json: async () => JSON.parse(body), text: async () => body }; };
    const protectedPlay = async (...a) => { calls.push(a); };
    const set = (id, text) => calls.push(["set", id, text]);
    await new Function("fetch", "CARD_FAIRPLAY_OWN", "AXINOM_LICENSE", "AXINOM_LICENSE_ADDRESS", "protectedPlay", "set", "alog", `return (async () => {${lines}\n})();`)(fetch, OWN, LICENSE, LICENSE_ADDRESS, protectedPlay, set, () => {});
    return { plays: calls.filter((c) => c[0] !== "set"), sets: calls.filter((c) => c[0] === "set"), seen };
  };
  // nothing made yet: the cell says so, nothing is played
  let r = await runWith({});
  assert.deepEqual(r.plays, []); assert.ok(r.sets.some(([, id, text]) => id === "o-play" && /not made yet/.test(text)), JSON.stringify(r.sets));
  assert.ok(/^card-fairplay-own\/current\.json\?v=\d+$/.test(r.seen[0]), "current.json is asked for fresh: " + r.seen[0]);
  // a folder and its token: the card in that folder, with that token
  r = await runWith({ [OWN + "current.json"]: JSON.stringify({ folder: "1a2b3c4d" }), [OWN + "1a2b3c4d/token.txt"]: "TOKEN-1\n" });
  assert.deepEqual(r.plays.map((a) => [a[0], a[1], a[2], a[4], a[5]]), [["vo", "o", OWN + "1a2b3c4d/master.m3u8", "TOKEN-1", LICENSE]], "no address recorded: the shared one");
  // the account's own licence address, recorded with the card: the token goes there; any other host, nowhere
  r = await runWith({ [OWN + "current.json"]: JSON.stringify({ folder: "1a2b3c4d", license: OWN_LICENSE }), [OWN + "1a2b3c4d/token.txt"]: "TOKEN-1\n" });
  assert.deepEqual(r.plays.map((a) => a[5]), [OWN_LICENSE], "the account's own address");
  for (const license of ["https://licence.example.com/AcquireLicense", "http://0a1b2c3d.drm-fairplay-licensing.axprod.net/AcquireLicense", "", "https://evil.example/collect?u=https://drm-fairplay-licensing.axprod.net/AcquireLicense"]) {
    r = await runWith({ [OWN + "current.json"]: JSON.stringify({ folder: "1a2b3c4d", license }), [OWN + "1a2b3c4d/token.txt"]: "TOKEN-1\n" });
    assert.deepEqual(r.plays, [], `address ${JSON.stringify(license)}: nothing played`); assert.ok(!r.seen.some((u) => /token\.txt/.test(u)), `and no token fetched for ${JSON.stringify(license)}`);
    assert.ok(r.sets.some(([, id, text]) => id === "o-play" && /refused: its licence address is not Axinom's/.test(text)), `the cell names the refusal, not a missing account: ${JSON.stringify(r.sets)}`);
  }
  // any other folder name is never followed; a folder without a token plays nothing
  for (const folder of ["../../site", "1a2b3c4", "1A2B3C4D", "1a2b3c4d/..", "1a2b3c4d0", "", null]) {
    r = await runWith({ [OWN + "current.json"]: JSON.stringify({ folder }), [OWN + folder + "/token.txt"]: "TOKEN-X" });
    assert.deepEqual(r.plays, [], `folder ${JSON.stringify(folder)} is not followed`);
    assert.ok(!r.seen.some((u) => /token\.txt/.test(u)), `no token is fetched for ${JSON.stringify(folder)}`);
  }
  r = await runWith({ [OWN + "current.json"]: JSON.stringify({ folder: "1a2b3c4d" }) });
  assert.deepEqual(r.plays, [], "no token there: nothing played");
  assert.ok(r.sets.some(([, id, text]) => id === "o-play" && /its token is missing/.test(text)), JSON.stringify(r.sets));
  // a token past the expiry date current.json records: not offered, its token never fetched; one still good: played
  r = await runWith({ [OWN + "current.json"]: JSON.stringify({ folder: "1a2b3c4d", expires: "2026-01-02T03:04:05.000Z" }), [OWN + "1a2b3c4d/token.txt"]: "TOKEN-1\n" });
  assert.deepEqual(r.plays, [], "an expired token: nothing played"); assert.ok(!r.seen.some((u) => /token\.txt/.test(u)), "and its token never fetched");
  assert.ok(r.sets.some(([, id, text]) => id === "o-play" && /its token expired on 2026-01-02/.test(text)), JSON.stringify(r.sets));
  r = await runWith({ [OWN + "current.json"]: JSON.stringify({ folder: "1a2b3c4d", expires: new Date(Date.now() + 30 * 86400000).toISOString() }), [OWN + "1a2b3c4d/token.txt"]: "TOKEN-1\n" });
  assert.equal(r.plays.length, 1, "a token still good: played");
  r = await runWith({ [OWN + "current.json"]: "not json" });
  assert.deepEqual(r.plays, [], "an unreadable current.json: nothing played");
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

// A minimal fragmented MP4 with the boxes checkFairPlay and checkBoxes read: an encrypted H.264 sample entry
// (its 'avcC' giving 4-byte NAL lengths) whose 'tenc' carries Apple's pattern, the key id and (for 'cbcs') a
// constant IV, and fragments, each a 'moof' with its sample table ('trun': sizes, flags saying which samples
// are keyframes, and the offset of the samples) and its sample-encryption box ('senc': per sample, per
// slice, clear bytes then protected ones; by default one slice of 10 clear bytes and `prot` protected),
// then the samples' bytes ('mdat'), laid out NAL unit by NAL unit the way shaka-packager lays them out
// against its records (sampleBytes below). The keyframe flags are written the three ways the standard
// allows: per sample (as shaka-packager writes them), or as the first sample's flags with the rest from the
// fragment's defaults ('tfhd') or from the movie's ('trex').
const box = (type, ...parts) => { const body = Buffer.concat(parts.map((p) => Buffer.isBuffer(p) ? p : Buffer.from(p))); const h = Buffer.alloc(8); h.writeUInt32BE(8 + body.length); h.write(type, 4, "latin1"); return Buffer.concat([h, body]); };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }, u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const NOT_KEY = 0x10000; // sample_is_non_sync_sample
const senc = (slices, ivSize, count = slices.length, flags = 2) => box("senc", Buffer.from([0, 0, 0, flags]), u32(count), ...slices.flatMap((ss) => [Buffer.alloc(ivSize), u16(ss.length), ...ss.flatMap(([c, p]) => [u16(c), u32(p)])]));
// One sample's bytes against its records: in each record's clear run, a NAL unit that is not a slice (an
// SEI), then the slice's own clear head (its length, NAL header and slice header), then its protected bytes,
// ending with the slice. A third number says how many clear bytes are the slice's own (default: 12 when
// the run has room for an SEI before it, else all of it; with no protected bytes, none: the run is all SEI);
// a fourth moves the end the slice's length declares by that many bytes.
// `clearNal` is the NAL header of the clear run's unit that is not a slice (an SEI by default); `idr` writes every
// slice as a keyframe's (NAL type 5) whatever the sample's flags say.
function sampleBytes(records, keyframe, size, { clearNal = 0x06, idr = false } = {}) {
  const parts = [];
  for (const [c, p, own = p > 0 ? (c >= 17 ? 12 : c) : 0, shift = 0] of records) {
    if (c - own > 0) { const sei = Buffer.alloc(c - own); sei.writeUInt32BE(c - own - 4); sei[4] = clearNal; parts.push(sei); }
    if (own + p > 0) { const sl = Buffer.alloc(own + p); sl.writeUInt32BE(own - 4 + p + shift); sl[4] = keyframe || idr ? 0x65 : 0x41; parts.push(sl); }
  }
  const b = Buffer.concat(parts);
  return b.length >= size ? b.subarray(0, size) : Buffer.concat([b, Buffer.alloc(size - b.length)]);
}
function fakeFile({ scheme = "cbcs", kid, iv, perSampleIvSize = 0, fragments = 1, prot = [900, 700], slices = prot.map((p) => [[10, p]]), sizes = slices.map((ss) => ss.reduce((a, [c, p]) => a + c + p, 0)), flags = [0, NOT_KEY], defaults = "per-sample", sencCount = slices.length, sencFlags = 2, trafTail = Buffer.alloc(0), stblTail = Buffer.alloc(0), tencHead = [1, 0, 0, 0, 0, 0x19, 1], avcC = true, clearNal, idr }) {
  const tenc = box("tenc", Buffer.from([...tencHead, perSampleIvSize]), Buffer.from(kid, "hex"), perSampleIvSize ? Buffer.alloc(0) : Buffer.concat([Buffer.from([16]), Buffer.from(iv, "hex")]));
  const sinf = box("sinf", box("frma", "avc1"), box("schm", Buffer.from([0, 0, 0, 0]), scheme, Buffer.from([0, 1, 0, 0])), box("schi", tenc));
  const encv = box("encv", Buffer.alloc(78), ...(avcC ? [box("avcC", Buffer.from([1, 0x4d, 0, 0x28, 0xff, 0xe0, 0]))] : []), sinf);
  const stsd = box("stsd", Buffer.from([0, 0, 0, 0, 0, 0, 0, 1]), encv);
  const trex = box("trex", Buffer.from([0, 0, 0, 0]), u32(1), u32(1), u32(0), u32(0), u32(defaults === "trex" ? flags[1] : 0));
  const moov = box("moov", box("trak", box("mdia", box("minf", box("stbl", stsd, stblTail)))), box("mvex", trex));
  const table = (offset) => defaults === "per-sample"
    ? [box("tfhd", Buffer.from([0, 2, 0, 0]), u32(1)), box("trun", Buffer.from([0, 0, 0x06, 0x01]), u32(sizes.length), u32(offset), ...sizes.flatMap((s, i) => [u32(s), u32(flags[i])]))]
    : [defaults === "tfhd" ? box("tfhd", Buffer.from([0, 2, 0, 0x20]), u32(1), u32(flags[1])) : box("tfhd", Buffer.from([0, 2, 0, 0]), u32(1)),
       box("trun", Buffer.from([0, 0, 0x02, 0x05]), u32(sizes.length), u32(offset), u32(flags[0]), ...sizes.map(u32))];
  // the samples follow their 'moof' in an 'mdat', the data offset counted from the start of the 'moof'
  const moofAt = (offset) => box("moof", box("traf", ...table(offset), senc(slices, perSampleIvSize, sencCount, sencFlags), box("saiz", Buffer.alloc(9)), box("saio", Buffer.alloc(12)), trafTail));
  const isKey = (i) => !((defaults === "per-sample" ? flags[i] : i === 0 ? flags[0] : flags[1]) & NOT_KEY);
  const moof = moofAt(moofAt(0).length + 8), mdat = box("mdat", ...sizes.map((size, i) => sampleBytes(slices[i] || [], isKey(i), size, { clearNal, idr: idr && i > 0 })));
  const frags = Array.from({ length: fragments }, () => Buffer.concat([moof, mdat]));
  return Buffer.concat([moov, ...frags]);
}

test("the check every FairPlay form must pass: Apple's key line with this address, 'cbcs' in Apple's pattern, this key id, this IV, every sample recorded whole and protected, its records following its slices, every slice of every keyframe encrypted", () => {
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
    assert.ok(bad.problems.some((p) => /1 of 1 keyframes have a slice with no encrypted block/.test(p)), `${defaults}: ${JSON.stringify(bad.problems)}`);
  }
  // a keyframe of several slices (measured from shaka-packager with four slices: [706,6343] [12,3904]
  // [13,13486] [13,13370]): every slice is encrypted on its own and can be decoded on its own
  const four = [[[706, 6343], [12, 3904], [13, 13486], [13, 13370]], [[10, 13]]];
  assert.deepEqual(checkFairPlay(playlist, fakeFile({ ...ids, slices: four }), ids).problems, [], "four slices, each encrypted");
  // long clear runs of NAL units that are not slices carry no picture: the encoder's settings note (688
  // bytes), CBR filler (16,639 bytes, measured): accepted, however long
  assert.deepEqual(checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[17000, 6343]], [[16649, 13]]] }), ids).problems, [], "long runs that are not slices");
  // what our encoder writes in a clear run is accepted (an SEI, an access unit delimiter, filler), and slices
  // with no encrypted block up to SAMPLE_OPEN_MAX bytes in a frame (ten of 25 bytes: 250)
  for (const clearNal of [0x06, 0x09, 0x0c]) assert.deepEqual(checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[30, 900]], [[30, 700]]], clearNal }), ids).problems, [], `NAL type ${clearNal}`);
  assert.equal(SAMPLE_OPEN_MAX, 256);
  const ten = checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[10, 900]], Array.from({ length: 10 }, () => [10, 15])] }), ids);
  assert.deepEqual([ten.problems, ten.openBytesMax], [[], 250], "250 bytes in slices with no encrypted block: accepted");
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
    [checkFairPlay(playlist, fakeFile({ ...ids, prot: [15, 900] }), ids), /1 of 1 keyframes have a slice with no encrypted block/],
    [checkFairPlay(playlist, fakeFile({ ...ids, prot: [900, 13, 15], flags: [0, NOT_KEY, 0] }), ids), /1 of 2 keyframes have a slice with no encrypted block/],
    // ONE slice of a keyframe left out of the encryption, while the frame as a whole has plenty: that slice
    // of the picture decodes without the key (the review's case: slice 2 of 4, all 3,916 bytes, put back in the clear)
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[706, 6343], [3916, 0, 3916], [13, 13486], [13, 13370]], [[10, 13]]] }), ids), /1 of 1 keyframes have a slice with no encrypted block/],
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[706, 6343], [3916, 0, 3916], [13, 13486], [13, 13370]], [[10, 13]]] }), ids), /1 of 2 samples carry a slice wholly in the clear/],
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[706, 6343], [12, 15], [13, 13486]], [[10, 13]]] }), ids), /1 of 1 keyframes have a slice with no encrypted block/],
    // a slice wholly in the clear between keyframes too
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[706, 6343]], [[10, 13], [40, 0, 40]]] }), ids), /1 of 2 samples carry a slice wholly in the clear/],
    // a slice's OWN data in the clear beyond its header (900 of its bytes): picture a decoder shows without the
    // key, whatever the frame's other records say (the fourth review's case)
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[912, 6343, 900]], [[10, 13]]] }), ids), /1 of 2 samples have encryption records that do not follow their slices/],
    // a protected range that does not end with its slice, either way; protected bytes that are no slice's
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[706, 6343, 12, 8]], [[10, 13]]] }), ids), /1 of 2 samples have encryption records that do not follow their slices/],
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[706, 6343, 12, -8]], [[10, 13]]] }), ids), /1 of 2 samples have encryption records that do not follow their slices/],
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[706, 6343, 0]], [[10, 13]]] }), ids), /1 of 2 samples have encryption records that do not follow their slices/],
    // not Apple's encryption: another pattern, the track not marked protected, an older 'tenc' with no pattern
    [checkFairPlay(playlist, fakeFile({ ...ids, tencHead: [1, 0, 0, 0, 0, 0x00, 1] }), ids), /the file's encryption is not Apple's/],
    [checkFairPlay(playlist, fakeFile({ ...ids, tencHead: [1, 0, 0, 0, 0, 0x19, 0] }), ids), /the file's encryption is not Apple's/],
    [checkFairPlay(playlist, fakeFile({ ...ids, tencHead: [0, 0, 0, 0, 0, 0x19, 1] }), ids), /the file's encryption is not Apple's/],
    // no H.264 configuration: the slices cannot be read, so nothing is taken on trust
    [checkFairPlay(playlist, fakeFile({ ...ids, avcC: false }), ids), /no H\.264 configuration/],
    // samples placed inside the file but outside its media data (the data offset pointed back at the start)
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("trun"); f.writeInt32BE(-(f.indexOf("moof") - 4), at + 12); return f; })(), ids), /of 2 samples lie outside the file's media data/],
    [checkFairPlay(playlist, fakeFile({ ...ids, flags: [NOT_KEY, NOT_KEY] }), ids), /no sample is marked as a keyframe/],
    // bytes of a sample outside its record would be in the clear
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910, 2710] }), ids), /1 of 2 samples are not covered whole/],
    // a sample with no record at all, and records that do not match the samples
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910, 710, 500], flags: [0, NOT_KEY, 0] }), ids), /different number of encryption records/],
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910, 710, 500], flags: [0, NOT_KEY, 0] }), ids), /1 of 3 samples have no protected bytes/],
    [checkFairPlay(playlist, fakeFile({ ...ids, sizes: [910], flags: [0] }), ids), /different number of encryption records/],
    // a file or a record cut short is named, never read past: the samples' bytes ('mdat') cut, or missing
    // altogether, or the file ending inside the fragment's first box (before its sample table is read)
    [checkFairPlay(playlist, (() => { const f = fakeFile(ids); return f.subarray(0, f.length - 4); })(), ids), /cannot be read: a fragment's media data is cut short/],
    [checkFairPlay(playlist, (() => { const f = fakeFile(ids); return f.subarray(0, f.indexOf("mdat") - 4); })(), ids), /cannot be read: a fragment's media data is cut short/],
    [checkFairPlay(playlist, (() => { const f = fakeFile(ids); return f.subarray(0, f.indexOf("tfhd") + 6); })(), ids), /cannot be read: a fragment's box is cut short/],
    // in a whole file, a box of the fragment running past the fragment's end, and bytes left over at its end
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("saio"); f.writeUInt32BE(f.readUInt32BE(at - 4) + 4, at - 4); return f; })(), ids), /cannot be read: a fragment's box is cut short/],
    [checkFairPlay(playlist, fakeFile({ ...ids, trafTail: Buffer.alloc(4) }), ids), /cannot be read: a fragment's box is cut short/],
    [checkFairPlay(playlist, fakeFile({ ...ids, sencCount: 3 }), ids), /cannot be read: a fragment's encryption record is cut short/],
    // the records' box read as something else: its subsample flag cleared (every sample would read as wholly
    // protected), or a count one short (a record left over)
    [checkFairPlay(playlist, fakeFile({ ...ids, sencFlags: 0 }), ids), /cannot be read: a fragment's encryption records do not fill their box exactly/],
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("senc"); f.writeUInt32BE(1, at + 8); return f; })(), ids), /cannot be read: a fragment's encryption records do not fill their box exactly/],
    // a fragment header or the movie's defaults too short for the fields their flags announce
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("tfhd"); f[at + 7] = 0x3b; return f; })(), ids), /cannot be read: a fragment's fragment header is cut short/],
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("trex"); f.writeUInt32BE(28, at - 4); return f; })(), ids), /cannot be read: the movie's sample defaults are cut short/],
    // a sample count no file could hold is refused, not looped over (records and table entries of no bytes)
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("senc"); f[at + 7] = 0; f.writeUInt32BE(0xffffffff, at + 8); return f; })(), ids), /cannot be read: a fragment lists 4294967295 samples/],
    [checkFairPlay(playlist, (() => { const f = Buffer.from(fakeFile(ids)), at = f.indexOf("trun"); f[at + 6] = 0; f.writeUInt32BE(0xffffffff, at + 8); return f; })(), ids), /cannot be read: a fragment lists 4294967295 samples/],
    // the fifth review's cases. A keyframe's slice (NAL type 5) in a sample flagged as not a keyframe is a
    // keyframe all the same (here with 15 protected bytes: nothing of it encrypted)
    [checkFairPlay(playlist, fakeFile({ ...ids, prot: [900, 15], idr: true }), ids), /1 of 2 keyframes have a slice with no encrypted block/],
    // 400 slices of 15 protected bytes in a frame that is not a keyframe: 10,000 bytes a decoder reads without
    // the key; 11 such slices (275 bytes) are already more than SAMPLE_OPEN_MAX
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[10, 900]], Array.from({ length: 400 }, () => [10, 15])] }), ids), /1 of 2 samples carry more than 256 bytes a decoder reads without the key \(slices with no encrypted block, and the clear heads of the others; most: 10000\)/],
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[10, 900]], Array.from({ length: 11 }, () => [10, 15])] }), ids), /1 of 2 samples carry more than 256 bytes a decoder reads without the key \(slices with no encrypted block, and the clear heads of the others; most: 275\)/],
    // the sixth review's: a keyframe of 400 slices, each encrypted, each with a 64-byte clear head: 25,600 bytes
    // of slice data a decoder reads without the key
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [Array.from({ length: 400 }, () => [64, 16, 64]), [[10, 13]]] }), ids), /1 of 2 samples carry more than 256 bytes a decoder reads without the key \(slices with no encrypted block, and the clear heads of the others; most: 25600\)/],
    // a clear run holding a NAL unit our encoder never writes (20: a coded slice extension, which is picture)
    [checkFairPlay(playlist, fakeFile({ ...ids, slices: [[[30, 900]], [[30, 700]]], clearNal: 0x14 }), ids), /do not follow their slices/],
    // sample groups of encryption settings, in a fragment or in the movie's sample table
    [checkFairPlay(playlist, fakeFile({ ...ids, trafTail: box("sbgp", Buffer.alloc(4), "seig", u32(1), u32(2), u32(1)) }), ids), /sample groups of encryption settings \('seig'\)/],
    [checkFairPlay(playlist, fakeFile({ ...ids, stblTail: box("sgpd", Buffer.from([1, 0, 0, 0]), "seig", u32(20), u32(1), Buffer.alloc(20)) }), ids), /sample groups of encryption settings \('seig'\)/],
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

// A keyframe of several slices: renderClip's own settings (service/lib/pipeline.mjs), plus four slices per
// frame, packaged by packageFairPlay. Every slice of a keyframe must carry an encrypted block (a decoder
// shows each slice on its own); one slice's record marked clear (the review's case, which then decoded to
// part of the picture without the key) is refused.
test("a keyframe of four slices with the real packager: every slice encrypted; one slice's record marked clear is refused (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const dir = await fs.mkdtemp(join(tmp, "slices-"));
  const pic = join(dir, "pic.png");
  await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc2=s=960x1280:d=1", "-frames:v", "1", pic]);
  await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-noautorotate", "-i", pic, "-vf", "loop=loop=29:size=1:start=0,setpts=N/(15*TB),scale=960:1280,format=yuv420p",
    "-r", "15", "-t", "2", "-c:v", "libx264", "-profile:v", "main", "-level", "4.0", "-pix_fmt", "yuv420p", "-g", "15", "-x264-params", "slices=4", "-movflags", "+faststart", join(dir, "clip.mp4")]);
  const ids = newFairPlayIds();
  await packageFairPlay(tools.packager, dir, ids);
  const media = await fs.readFile(join(dir, "fp", "video.m3u8"), "utf8"), data = await fs.readFile(join(dir, "fp", "video.mp4"));
  const good = checkFairPlay(media, data, ids);
  assert.deepEqual(good.problems, [], "the packaged form passes");
  // the first keyframe's record (constant IV, so no IV bytes): four slices, each with an encrypted block
  const at = data.indexOf("senc") - 4, k = data.readUInt16BE(at + 16);
  const slices = Array.from({ length: k }, (_, j) => [data.readUInt16BE(at + 18 + 6 * j), data.readUInt32BE(at + 20 + 6 * j)]);
  assert.equal(k, 4, "four slices: " + JSON.stringify(slices));
  assert.ok(slices.every(([, p]) => p >= 16), "each with an encrypted block: " + JSON.stringify(slices));
  // and its bytes agree with its records, slice by slice (Apple's pattern starts again with each protected range)
  const sliceBytes = await verifyFairPlayBytes(tools.packager, dir, ids);
  assert.deepEqual(sliceBytes.problems, [], "four slices: the byte check passes");
  // slice 2 marked clear in its record: all its bytes counted clear, none protected
  const bad = Buffer.from(data), e = at + 18 + 6;
  bad.writeUInt16BE(slices[1][0] + slices[1][1], e); bad.writeUInt32BE(0, e + 2);
  const r = checkFairPlay(media, bad, ids);
  assert.equal(r.ok, false, "one slice in the clear is refused");
  assert.ok(r.problems.some((p) => /1 of 2 keyframes have a slice with no encrypted block/.test(p)), JSON.stringify(r.problems));
  notice("FairPlay slices", `a keyframe of ${k} slices ${JSON.stringify(slices)}: checkFairPlay ok (${good.keyframesEncrypted} of ${good.keyframes} keyframes); with slice 2 marked clear: ${r.problems.join("; ")}`);
});

// Encodes the check must ACCEPT (the fourth review found two it refused): CBR filler (long runs of filler
// NAL units, no picture), access unit delimiters, heavy B-frame settings, and a 2x2 picture, which renderClip
// now draws at the minimum size so its keyframes have something to encrypt (a solid 2x2 and 16x16 were refused).
test("legitimate encodes pass the check with the real packager: CBR filler, access unit delimiters, heavy B-frames, a 2x2 picture drawn at the minimum size (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const seen = [];
  for (const [name, src, x264] of [
    ["cbr-filler", "testsrc2=s=640x480:d=1", ["-b:v", "2M", "-minrate", "2M", "-maxrate", "2M", "-bufsize", "1M", "-x264-params", "nal-hrd=cbr"]],
    ["aud", "testsrc2=s=640x480:d=1", ["-x264-params", "aud=1"]],
    ["heavy-b", "testsrc2=s=960x1280:d=1", ["-x264-params", "ref=16:bframes=16:weightb=1:weightp=2:b-pyramid=normal"]],
    ["tiny-2x2", "color=c=0x336699:s=2x2:d=1", null],
  ]) {
    const dir = await fs.mkdtemp(join(tmp, name + "-")), pic = join(dir, "pic.png");
    await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", src, "-frames:v", "1", pic]);
    if (x264) await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-i", pic, "-vf", "loop=loop=29:size=1:start=0,setpts=N/(15*TB),format=yuv420p",
      "-r", "15", "-t", "2", "-c:v", "libx264", "-profile:v", "main", "-level", "4.0", "-pix_fmt", "yuv420p", "-g", "15", ...x264, "-movflags", "+faststart", join(dir, "clip.mp4")]);
    else {
      const clip = await renderClip(tools, pic, join(dir, "clip.mp4"));
      assert.deepEqual([clip.width, clip.height], [64, 64], "a 2x2 picture is drawn at 64x64");
    }
    const ids = newFairPlayIds();
    await packageFairPlay(tools.packager, dir, ids);
    const r = checkFairPlay(await fs.readFile(join(dir, "fp", "video.m3u8"), "utf8"), await fs.readFile(join(dir, "fp", "video.mp4")), ids);
    assert.deepEqual(r.problems, [], `${name} passes`);
    seen.push(`${name}: ${r.samples} samples, ${r.keyframesEncrypted} of ${r.keyframes} keyframes encrypted`);
  }
  notice("FairPlay legitimate encodes", seen.join("; "));
});

// A packager that writes Apple's form as asked, then puts every sample's clear bytes back into it, leaving its
// records saying "encrypted": the fault a records check cannot see (the fifth review). Only for the FairPlay call.
async function clearBytesPackager() {
  const f = join(tmp, "packager-clear-bytes");
  await fs.writeFile(f, `#!/usr/bin/env node
const { spawnSync } = require("node:child_process"), fs = require("node:fs");
const real = ${JSON.stringify(tools.packager)}, args = process.argv.slice(2);
const r = spawnSync(real, args, { stdio: "inherit" });
if (r.status !== 0 || !args.includes("cbcs")) process.exit(r.status ?? 1);
const spec = args.find((a) => a.startsWith("in=")), input = spec.match(/^in=([^,]+)/)[1], out = spec.match(/output=([^,]+)/)[1], plain = out + ".plain.mp4";
if (spawnSync(real, ["in=" + input + ",stream=video,output=" + plain, "--segment_duration", "2", "--fragment_duration", "2"], { stdio: "inherit" }).status !== 0) process.exit(1);
import(${JSON.stringify(new URL("../../service/lib/pipeline.mjs", import.meta.url).href)}).then(({ readTrack }) => {
  const enc = fs.readFileSync(out), clear = fs.readFileSync(plain), e = readTrack(enc), c = readTrack(clear);
  e.samples.forEach(({ r }, i) => clear.copy(enc, r.at, c.samples[i].r.at, c.samples[i].r.at + r.size));
  fs.writeFileSync(out, enc); fs.rmSync(plain);
});
`);
  await fs.chmod(f, 0o755);
  return f;
}

// A packager that encrypts Apple's form under another key than the one it was given: the records are all right
// (key id, IV, layout), so only the bytes can tell. Only for the FairPlay call.
async function wrongKeyPackager() {
  const f = join(tmp, "packager-wrong-key");
  await fs.writeFile(f, `#!/usr/bin/env node\nconst { spawnSync } = require("node:child_process");\nconst cbcs = process.argv.includes("cbcs");\nconst args = process.argv.slice(2).map((a) => cbcs && /^label=:key_id=[0-9a-f]{32}:key=[0-9a-f]{32}$/.test(a) ? a.replace(/:key=[0-9a-f]{32}$/, ":key=00112233445566778899aabbccddeeff") : a);\nprocess.exit(spawnSync(${JSON.stringify(tools.packager)}, args, { stdio: "inherit" }).status ?? 1);\n`);
  await fs.chmod(f, 0o755);
  return f;
}

// The byte check every Apple form now passes (the fifth review): the records say which blocks are encrypted, the
// bytes must agree. A real form passes; a block recorded as encrypted but put back to the clip's own bytes, a
// byte of a clear run changed, or a decryption with another key is refused.
test("the byte check: a real form passes; a block recorded as encrypted but left clear, a changed clear byte, or another key's decryption is refused (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const dir = await fs.mkdtemp(join(tmp, "bytes-")), pic = join(dir, "pic.png");
  await exec("ffmpeg", ["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc2=s=640x480:d=1", "-frames:v", "1", pic]);
  await renderClip(tools, pic, join(dir, "clip.mp4"));
  const ids = newFairPlayIds();
  await packageFairPlay(tools.packager, dir, ids);
  const good = await verifyFairPlayBytes(tools.packager, dir, ids);
  assert.deepEqual(good.problems, []);
  assert.ok(good.encryptedBlocks > 0 && good.blocksLeftClear === 0 && good.clearBytesChanged === 0 && good.decryptedWrong === 0, JSON.stringify(good));
  assert.deepEqual((await fs.readdir(dir)).sort(), ["clip.mp4", "fp", "pic.png"], "its working files are removed");
  // the same comparison on the files themselves, then each one changed
  await exec(tools.packager, ["in=clip.mp4,stream=video,output=clear.mp4", "--segment_duration", "2", "--fragment_duration", "2"], { cwd: dir });
  await exec(tools.packager, ["in=fp/video.mp4,stream=video,output=dec.mp4", "--enable_raw_key_decryption", "--keys", `key_id=${ids.kid}:key=${ids.key}`], { cwd: dir });
  const enc = await fs.readFile(join(dir, "fp", "video.mp4")), clear = await fs.readFile(join(dir, "clear.mp4")), dec = await fs.readFile(join(dir, "dec.mp4"));
  assert.deepEqual(checkFairPlayBytes(enc, clear, dec).problems, []);
  assert.deepEqual(checkFairPlayBytes(Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)).problems, ["the form carries no samples"], "three empty files are no form");
  const e = readTrack(enc), c = readTrack(clear), first = e.samples[0], [cl] = first.rec[0];
  const at = first.r.at + cl, cat = c.samples[0].r.at + cl; // the keyframe's first protected byte, in each file
  const leftClear = Buffer.from(enc); clear.copy(leftClear, at, cat, cat + 16);
  const a = checkFairPlayBytes(leftClear, clear, dec);
  assert.ok(a.problems.some((p) => new RegExp(`^1 of ${good.encryptedBlocks} blocks recorded as encrypted are the clip's own bytes`).test(p)), JSON.stringify(a.problems));
  const changed = Buffer.from(enc); changed[at - 1] ^= 0xff; // the last clear byte of the slice's head
  assert.ok(checkFairPlayBytes(changed, clear, dec).problems.some((p) => /^1 bytes recorded as clear differ from the clip's/.test(p)));
  const wrong = await verifyFairPlayBytes(tools.packager, dir, { ...ids, key: newFairPlayIds().key }).catch((x) => ({ problems: ["the packager refused: " + x.message] }));
  assert.ok(wrong.problems.some((p) => /decrypt with the form's own key to something other than the clip|the packager refused/.test(p)), JSON.stringify(wrong.problems));
  notice("FairPlay byte check", `real form: ${good.encryptedBlocks} blocks encrypted, 0 left clear, 0 clear bytes changed, decrypted back exactly; refused: ${a.problems[0]}; another key: ${wrong.problems[0]}`);
});

test("the worker with the Axinom key: a new picture gets its Apple form, its token (sealed) carries the key that decrypts it; the combined view too; a backfill adds the form to an older picture (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const KEY = await deriveKey("a test password, twelve+", toBase64(new Uint8Array(16).fill(7)), 1000);
  const KEY_HEX = await exportKeyHex(KEY);
  const siteDir = await fs.mkdtemp(join(tmp, "site-"));
  const upload = async (file) => { const f = join(tmp, "up-" + Math.random().toString(16).slice(2)); await fs.writeFile(f, await seal(KEY, await fs.readFile(file))); return f; };
  const add = async (id, file, com) => { process.env.WORKER_BLOB_FILE = await upload(file); return worker({ payload: { action: "add", id, name: id + ".png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools, checkKey: acceptKey, com }); };
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
    assert.equal(meta.fairplay.license, AXINOM_FAIRPLAY_LICENSE, "the meta records the licence address the token is for");
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
  const mosaic = (com) => worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: acceptKey, com });
  const mosaicMeta = async () => JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(siteDir, "mosaic", "meta.json.enc")))));
  assert.equal((await mosaic(null)).status, "ready"); assert.equal((await mosaicMeta()).fairplay, null);
  assert.equal((await mosaic(null)).status, "current");
  // ... and given its own form once the key exists (the form alone, from the view's own output: the same pictures
  // are never rebuilt for it); then kept
  assert.deepEqual(await mosaic(COM), { status: "current", count: 2, fairplay: "renewed" }, "the same pictures, but no Apple form: the form added");
  const mm = await mosaicMeta();
  assert.match(mm.fairplay.master, /^fp-[0-9a-f]{8}\/master\.m3u8$/);
  await fs.access(join(siteDir, "mosaic", mm.fairplay.master)); await fs.access(join(siteDir, "mosaic", mm.fairplay.master.split("/")[0], "token.enc"));
  assert.equal((await mosaic(COM)).status, "current");
  // a page's request can never start the backfill (it has its own workflow and queue)
  await assert.rejects(worker({ payload: { key: KEY_HEX, action: "fairplay" }, siteDir, tools, checkKey: acceptKey, com: COM }), /unknown action/);
  // the backfill: B gets its form; A (already has one) is left exactly as it is
  const r = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: acceptKey, com: COM });
  assert.deepEqual({ added: r.added, already: r.already, failed: r.failed }, { added: 1, already: 1, failed: 0 });
  await verify(B, [31, 78, 140], 480, 640);
  const a2 = await verify(A, [39, 174, 96], 640, 480);
  assert.equal(a2.folder, a1.folder); assert.equal(a2.token, a1.token, "a picture that has its form is not repackaged");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === B).fairplay, true, "the list records it");
  // a second backfill changes nothing
  const counts = (r) => ({ added: r.added, already: r.already, failed: r.failed });
  assert.deepEqual(counts(await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: acceptKey, com: COM })), { added: 0, already: 2, failed: 0 });
  // RENEWAL: a token close to its end, or made with another Axinom key, is renewed (a new form), the old one removed
  const metaPath = join(siteDir, "photos", A, "meta.json.enc");
  const m = JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(metaPath))));
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, COM), true);
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, COM, Date.parse(m.fairplay.expires) - (TOKEN_RENEW_DAYS - 1) * 86400000), false, "less than the renewal margin left: not current");
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, { ...COM, id: "11111111-2222-3333-4444-555555555555" }), false, "made with another key: not current");
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, { ...COM, license: OWN_LICENSE }), false, "made for another licence address: not current");
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), m.fairplay, { ...COM, key: nodeRandom(32) }), false, "the same key id with a corrected key value: not current");
  assert.equal(m.fairplay.comKeyCheck, comKeyCheck(COM), "the meta records the key's check value, never the key");
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", A), { ...m.fairplay, comKeyCheck: undefined }, COM), false, "a form with no check value recorded: remade");
  await fs.writeFile(metaPath, await sealText(KEY, JSON.stringify({ ...m, fairplay: { ...m.fairplay, expires: new Date(Date.now() + 3 * 86400000).toISOString() } })));
  assert.deepEqual(counts(await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: acceptKey, com: COM })), { added: 1, already: 1, failed: 0 }, "the expiring one is renewed");
  const a3 = await verify(A, [39, 174, 96], 640, 480);
  assert.notEqual(a3.folder, a1.folder, "a new form"); await assert.rejects(fs.access(join(siteDir, "photos", A, a1.folder)), "the old form is gone");
  const OTHER = { id: "11111111-2222-3333-4444-555555555555", key: nodeRandom(32) };
  const r2 = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: acceptKey, com: OTHER });
  assert.deepEqual(counts(r2), { added: 2, already: 0, failed: 0 }, "another Axinom key: every form is remade under it");
  assert.equal(JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(siteDir, "mosaic", "meta.json.enc"))))).fairplay.comKeyId, OTHER.id, "the combined view too");
  // the account's own licence address set: every form is remade for it, and records it
  const r3 = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: acceptKey, com: { ...OTHER, license: OWN_LICENSE } });
  assert.deepEqual(counts(r3), { added: 2, already: 0, failed: 0 }, "a new licence address: every form is remade for it");
  assert.equal(JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(metaPath)))).fairplay.license, OWN_LICENSE, "and records it");
  assert.equal(JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(siteDir, "mosaic", "meta.json.enc"))))).fairplay.license, OWN_LICENSE, "the combined view too");
  // without the key the backfill refuses plainly
  await assert.rejects(worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: acceptKey, com: null }), /not set/);
  // a picture whose form fails to package is still ready for everything else
  process.env.WORKER_BLOB_FILE = await upload(await solid("grey.png", 320, 240, "0x7f8c8d"));
  const broken = await worker({ payload: { action: "add", id: "c".repeat(24), name: "c.png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools: { ...tools, packager: tools.packager }, checkKey: acceptKey, com: { ...COM, key: Buffer.alloc(31) } });
  assert.equal(broken.status, "ready", "a key the token cannot be made with leaves the picture ready elsewhere");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === "c".repeat(24)).fairplay, false);
  assert.ok(!(await fs.readdir(join(siteDir, "photos", "c".repeat(24)))).some((f) => /^fp/.test(f)), "and no half-made Apple form is left behind");
  // a packager that encrypts Apple's form under another key than the one it was given: the records are all
  // right (key id, IV, layout), so only the bytes can tell; the byte check refuses the form
  process.env.WORKER_BLOB_FILE = await upload(await solid("teal.png", 320, 240, "0x16a085"));
  const logged = [], consoleLog = console.log; let wrongKey;
  console.log = (...a) => { logged.push(a.join(" ")); };
  try { wrongKey = await worker({ payload: { action: "add", id: "d".repeat(24), name: "d.png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools: { ...tools, packager: await wrongKeyPackager() }, checkKey: acceptKey, com: COM }); }
  finally { console.log = consoleLog; }
  assert.equal(wrongKey.status, "ready", "the picture is ready elsewhere");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === "d".repeat(24)).fairplay, false, "but gets no Apple form");
  assert.ok(logged.some((l) => /no FairPlay form for d{24}: the FairPlay form failed its byte check: .*decrypt with the form's own key to something other than the clip/.test(l)), "refused by the byte check: " + logged.filter((l) => /FairPlay/.test(l)).join(" | "));
  assert.ok(!(await fs.readdir(join(siteDir, "photos", "d".repeat(24)))).some((f) => /^fp/.test(f)), "and no Apple form is left behind");
  // the fifth review's case itself: a form whose records say encrypted while its bytes are the clip's own
  process.env.WORKER_BLOB_FILE = await upload(await solid("plum.png", 320, 240, "0x8e44ad"));
  logged.length = 0; console.log = (...a) => { logged.push(a.join(" ")); };
  let leftClear;
  try { leftClear = await worker({ payload: { action: "add", id: "e".repeat(24), name: "e.png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools: { ...tools, packager: await clearBytesPackager() }, checkKey: acceptKey, com: COM }); }
  finally { console.log = consoleLog; }
  assert.equal(leftClear.status, "ready");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === "e".repeat(24)).fairplay, false, "no Apple form for bytes left clear");
  assert.ok(logged.some((l) => /no FairPlay form for e{24}: the FairPlay form failed its byte check: .*blocks recorded as encrypted are the clip's own bytes/.test(l)), "refused by the byte check: " + logged.filter((l) => /FairPlay/.test(l)).join(" | "));
  notice("FairPlay worker", `added with the key: ${A} (its token's key decrypts its form to its colour; the token inside the form's folder); combined view remade with its form; backfill: 1 added, 1 already, 0 failed, then 0/2/0; an expiring token renewed (1/1/0), another Axinom key: 2/0/0; a page request for the backfill refused; a bad key left the picture ready without a form`);
});

// Before any Apple form is made or replaced, the worker asks Axinom whether it accepts our key (a token for a
// throwaway key): a wrong key value, or Axinom out of reach, must never replace a picture's working token. The
// sixth review's case: the weekly backfill (06:17) ran before the card job (06:41) could notice a bad key.
test("the worker asks Axinom before making or replacing any Apple form: a refusal replaces nothing (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const KEY = await deriveKey("a test password, twelve+", toBase64(new Uint8Array(16).fill(5)), 1000), KEY_HEX = await exportKeyHex(KEY);
  const siteDir = await fs.mkdtemp(join(tmp, "gate-"));
  const upload = async (file) => { const f = join(tmp, "up-" + Math.random().toString(16).slice(2)); await fs.writeFile(f, await seal(KEY, await fs.readFile(file))); return f; };
  const asked = [];
  const answer = (accepted, message) => async (com) => { asked.push(com.id); return { accepted, reached: true, status: accepted ? 400 : 403, message }; };
  const refuse = answer(false, "Invalid DRM message. The signature is invalid.");
  const add = async (id, file, checkKey) => { process.env.WORKER_BLOB_FILE = await upload(file); return worker({ payload: { action: "add", id, name: id + ".png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools, checkKey, com: COM }); };
  const metaOf = async (id) => JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(siteDir, "photos", id, "meta.json.enc")))));
  const A = "a".repeat(24), B = "b".repeat(24);
  assert.equal((await add(A, await solid("gate-a.png", 320, 240, "0xd35400"), answer(true, "Invalid license request. (a test)"))).status, "ready");
  const formA = (await metaOf(A)).fairplay;
  assert.ok(formA && formA.master, "A has its Apple form");
  // a new picture while Axinom refuses the key: ready, without an Apple form, the reason in the log
  const logged = [], consoleLog = console.log; console.log = (...a) => { logged.push(a.join(" ")); };
  let rB; try { rB = await add(B, await solid("gate-b.png", 320, 240, "0x2c3e50"), refuse); } finally { console.log = consoleLog; }
  assert.equal(rB.status, "ready");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === B).fairplay, false, "no Apple form for B");
  assert.ok(logged.some((l) => /no FairPlay form for b{24}: Axinom does not accept our key \(key id [0-9a-f-]{36}\): Invalid DRM message\. The signature is invalid\./.test(l)), logged.join(" | "));
  // the backfill with a corrected key value (the same key id) would remake every form; Axinom refuses that key,
  // so the run stops before replacing anything: A keeps its working form
  const corrected = { ...COM, key: nodeRandom(32) };
  asked.length = 0;
  await assert.rejects(worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: refuse, com: corrected }), /Axinom does not accept our key \(key id [0-9a-f-]{36}\): Invalid DRM message\. The signature is invalid\.; no Apple form was made or replaced/);
  assert.equal(asked.length, 1, "asked once");
  assert.deepEqual((await metaOf(A)).fairplay, formA, "A's form is untouched");
  assert.deepEqual((await fs.readdir(join(siteDir, "photos", A))).filter((f) => /^fp/.test(f)), [formA.master.split("/")[0]], "its folder still there, alone");
  // accepted: one question for the whole run, however many forms it makes (A renewed for the new value, B added)
  asked.length = 0;
  const r = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: answer(true, "Invalid license request. (a test)"), com: corrected });
  assert.deepEqual([r.added, r.failed], [2, 0], JSON.stringify(r)); assert.equal(asked.length, 1, "one question for the whole run");
  // nothing to make or replace: Axinom is not asked at all
  asked.length = 0;
  const again = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: refuse, com: corrected });
  assert.deepEqual([again.added, again.already, again.failed, again.mosaic], [0, 2, 0, "current"], JSON.stringify(again)); assert.equal(asked.length, 0, "not asked when every form is good");
  const unreachable = async (com) => { asked.push(com.id); return { accepted: false, reached: false, status: 0, message: "Axinom could not be reached (3 tries): connect ECONNREFUSED (a test)" }; };
  // the combined view, the same pictures, its form to renew for another key value: refused, or Axinom out of reach,
  // the view and its working form are kept (the seventh review: it used to be rebuilt, its form deleted first);
  // accepted, only its form is renewed
  const mosaicMeta = async () => JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(join(siteDir, "mosaic", "meta.json.enc")))));
  const formM = (await mosaicMeta()).fairplay, value2 = { ...COM, key: nodeRandom(32) };
  assert.ok(formM && formM.master, "the combined view has its form");
  for (const gate of [refuse, unreachable]) {
    const m = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: gate, com: value2 });
    assert.deepEqual([m.status, m.fairplay], ["current", "kept"], JSON.stringify(m));
    assert.deepEqual((await mosaicMeta()).fairplay, formM, "its working form kept");
    assert.ok((await fs.readdir(join(siteDir, "mosaic"))).includes(formM.master.split("/")[0]), "and its folder");
  }
  const renewed = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: answer(true, "Invalid license request. (a test)"), com: value2 });
  assert.deepEqual([renewed.status, renewed.fairplay], ["current", "renewed"], JSON.stringify(renewed));
  assert.notEqual((await mosaicMeta()).fairplay.master, formM.master, "the form alone renewed");
  // the backfill with Axinom out of reach: stopped before anything is replaced, said so
  await assert.rejects(worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir, tools, checkKey: unreachable, com: { ...COM, key: nodeRandom(32) } }), /Axinom could not be asked about our key \(key id [0-9a-f-]{36}\): Axinom could not be reached \(3 tries\): connect ECONNREFUSED \(a test\); no Apple form was made or replaced/);
  // a NEW picture with Axinom out of reach: its form replaces nothing, so it is made all the same
  const C = "c".repeat(24);
  logged.length = 0; console.log = (...a) => { logged.push(a.join(" ")); };
  let rC; try { rC = await add(C, await solid("gate-c.png", 320, 240, "0x16a085"), unreachable); } finally { console.log = consoleLog; }
  assert.equal(rC.status, "ready"); assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === C).fairplay, true, "a new picture gets its form when Axinom is only out of reach");
  assert.ok(logged.some((l) => /could not be asked about our key .*; the form for c{24} is made all the same \(it replaces nothing\)/.test(l)), logged.join(" | "));
  // a view of other pictures (C added) is rebuilt: its form is new; Axinom refusing the key, the new view has none
  const rebuilt = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: refuse, com: value2 });
  assert.equal(rebuilt.status, "ready", JSON.stringify(rebuilt)); assert.equal((await mosaicMeta()).fairplay, null, "refused: no form for the new view");
  // asked again with Axinom refusing: a view of the same pictures, with no form, is kept as it is (nothing rebuilt)
  const refusedAgain = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: refuse, com: value2 });
  assert.deepEqual([refusedAgain.status, refusedAgain.fairplay, (await mosaicMeta()).fairplay], ["current", "kept", null], JSON.stringify(refusedAgain));
  // asked again while Axinom is out of reach: its first form is made from the view's own output (it replaces
  // nothing), recorded as made without Axinom's acceptance
  const firstForm = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: unreachable, com: value2 });
  assert.deepEqual([firstForm.status, firstForm.fairplay, (await mosaicMeta()).fairplay.verified], ["current", "renewed", false], JSON.stringify(firstForm));
  // the worker's own default question (the one its command and the backfill's use) goes to Axinom, here a
  // stand-in fetch: refused there, a new picture gets no form
  const realFetch = globalThis.fetch, sent = [], D = "d".repeat(24);
  globalThis.fetch = async (url) => { sent.push(url); return new Response(null, { status: 400, headers: { "X-AxDRM-ErrorMessage": "Invalid DRM message. The signature is invalid." } }); };
  try { process.env.WORKER_BLOB_FILE = await upload(await solid("gate-d.png", 320, 240, "0x7d3c98")); await worker({ payload: { action: "add", id: D, name: "d.png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools, com: COM }); }
  finally { globalThis.fetch = realFetch; }
  assert.deepEqual(sent, [AXINOM_FAIRPLAY_LICENSE], "Axinom asked once, at the key's address");
  assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === D).fairplay, false, "refused by the default question: no form");
  // a view of other pictures (D added) rebuilt while Axinom is out of reach: its new form recorded as made without
  // Axinom's acceptance (its old one goes with its old content)
  assert.equal((await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: unreachable, com: value2 })).status, "ready");
  assert.equal((await mosaicMeta()).fairplay.verified, false, "rebuilt while Axinom could not be asked: unverified");
  // a question that cannot even be put (it throws), and a key that cannot make a token (the worker's own default
  // question, which fails before sending anything): no new form, said plainly, the picture readied all the same
  for (const [id, checkKey, comX, re] of [
    ["e".repeat(24), async () => { throw new Error("boom (a test)"); }, COM, /no FairPlay form for e{24}: our key \(key id [0-9a-f-]{36}\) could not be used: boom \(a test\)/],
    ["f".repeat(24), undefined, { ...COM, key: Buffer.alloc(31) }, /no FairPlay form for f{24}: our key \(key id [0-9a-f-]{36}\) could not be used: Invalid key length/],
  ]) {
    logged.length = 0; console.log = (...a) => { logged.push(a.join(" ")); };
    let r; try { process.env.WORKER_BLOB_FILE = await upload(await solid(`gate-${id[0]}.png`, 320, 240, "0x95a5a6")); r = await worker({ payload: { action: "add", id, name: id + ".png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools, ...(checkKey ? { checkKey } : {}), com: comX }); }
    finally { console.log = consoleLog; }
    assert.equal(r.status, "ready", JSON.stringify(r));
    assert.equal((await readGallery(siteDir, KEY)).photos.find((x) => x.id === id).fairplay, false);
    assert.ok(logged.some((l) => re.test(l)), logged.join(" | ")); assert.ok(!logged.some((l) => /made all the same/.test(l)), "never said to be made");
  }
  // a form made while Axinom could not be asked is recorded as such, and is not current: it is renewed once Axinom
  // can be asked, so a wrong key value is found out (the backfill stops, red) instead of passing as current
  const metaC = await metaOf(C);
  assert.equal(metaC.fairplay.verified, false, "C's form was made while Axinom could not be asked");
  assert.equal(await fairPlayCurrent(join(siteDir, "photos", C), metaC.fairplay, COM), false, "so it is not current");
  // THE RULE on the combined view, with a picture REALLY left out: its key id damaged in the list, as
  // site/test/site.test.mjs does, so the view draws the others and names it as left out (the ninth review: the test
  // before this one faked that state, and the code it passed failed the real case)
  const F = "f".repeat(24), readyIds = async () => (await readGallery(siteDir, KEY)).photos.filter((x) => x.status === "ready").map((x) => x.id);
  const g0 = await readGallery(siteDir, KEY);
  g0.photos.find((x) => x.id === F).prKidGuid = "00000000-0000-0000-0000-000000000000";
  await fs.writeFile(join(siteDir, "gallery.json.enc"), await sealText(KEY, JSON.stringify(g0)));
  const value3 = { ...COM, key: nodeRandom(32) }, accept = answer(true, "Invalid license request. (a test)");
  const made = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: accept, com: value3 });
  assert.deepEqual([made.status, made.skipped], ["ready", 1], JSON.stringify(made));
  const withForm = await mosaicMeta();
  assert.deepEqual(withForm.skipped.map((x) => x.id), [F]); assert.ok(withForm.fairplay && withForm.fairplay.verified === true, JSON.stringify(withForm.fairplay));
  assert.equal(mosaicCurrent(withForm, await readyIds()), true, "the page counts it as current");
  // the page's "Try again" with another key value: refused, out of reach, or no usable key at all: kept as it is
  const value4 = { ...COM, key: nodeRandom(32) };
  for (const [gate, comX] of [[refuse, value4], [unreachable, value4], [null, null]]) {
    const m = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, ...(gate ? { checkKey: gate } : {}), com: comX });
    assert.deepEqual([m.status, m.fairplay], ["current", "kept"], JSON.stringify(m));
    assert.deepEqual((await mosaicMeta()).fairplay, withForm.fairplay, "its working form kept");
    assert.ok((await fs.readdir(join(siteDir, "mosaic"))).includes(withForm.fairplay.master.split("/")[0]), "and its folder");
  }
  // accepted: rebuilt (F still damaged, so still left out), with a new form
  const retried = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: accept, com: value4 });
  assert.deepEqual([retried.status, retried.skipped], ["ready", 1], JSON.stringify(retried));
  const afterRetry = await mosaicMeta();
  assert.ok(afterRetry.fairplay.verified === true && afterRetry.fairplay.master !== withForm.fairplay.master, "accepted: a new form");
  // the left-out picture deleted by the owner: the view draws exactly the ready pictures; the stale entry is dropped
  // from its record, nothing rebuilt, its form kept, Axinom not asked; the page then counts it as current
  await worker({ payload: { action: "delete", id: F, key: KEY_HEX }, siteDir, tools });
  asked.length = 0;
  const cleaned = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: refuse, com: value4 });
  assert.equal(cleaned.status, "current", JSON.stringify(cleaned));
  const afterClean = await mosaicMeta();
  assert.deepEqual([afterClean.skipped, afterClean.fairplay.master, asked.length], [[], afterRetry.fairplay.master, 0]);
  assert.equal(mosaicCurrent(afterClean, await readyIds()), true, "the page counts it as current");
  // its own output unreadable and its form for another key value: refused, kept; accepted, rebuilt
  await fs.writeFile(join(siteDir, "mosaic", "video-playready.mp4.enc"), Buffer.from("not a sealed file"));
  const value5 = { ...COM, key: nodeRandom(32) };
  const keptBroken = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: refuse, com: value5 });
  assert.deepEqual([keptBroken.status, keptBroken.fairplay, (await mosaicMeta()).fairplay.master], ["current", "kept", afterRetry.fairplay.master], JSON.stringify(keptBroken));
  const repairedWithForm = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: accept, com: value5 });
  assert.equal(repairedWithForm.status, "ready", JSON.stringify(repairedWithForm));
  const after = await mosaicMeta();
  assert.ok(after.fairplay.master !== afterRetry.fairplay.master && after.fairplay.verified === true, "accepted: rebuilt, with a new form");
  // a view with no form whose own output cannot be read back is rebuilt (it has no form to lose)
  await fs.writeFile(join(siteDir, "mosaic", "meta.json.enc"), await sealText(KEY, JSON.stringify({ ...after, fairplay: null })));
  await fs.writeFile(join(siteDir, "mosaic", "video-playready.mp4.enc"), Buffer.from("not a sealed file"));
  const repaired = await worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools, checkKey: accept, com: value5 });
  assert.equal(repaired.status, "ready", JSON.stringify(repaired)); assert.ok((await mosaicMeta()).fairplay.master, "rebuilt, with its form");
  // the backfill making a missing combined view while Axinom refuses the key: counted, not "done"
  await fs.rm(join(siteDir, "mosaic"), { recursive: true, force: true });
  const fresh = await fs.mkdtemp(join(tmp, "gate2-"));
  for (const f of ["gallery.json.enc"]) await fs.copyFile(join(siteDir, f), join(fresh, f));
  const g = await readGallery(fresh, KEY); g.photos = g.photos.filter((x) => x.id === A); await fs.writeFile(join(fresh, "gallery.json.enc"), await sealText(KEY, JSON.stringify(g)));
  await fs.cp(join(siteDir, "photos", A), join(fresh, "photos", A), { recursive: true });
  const aNow = await metaOf(A), keyA = aNow.fairplay.comKeyCheck === comKeyCheck(value2) ? value2 : corrected;
  const bf = await worker({ payload: { key: KEY_HEX }, action: "fairplay", siteDir: fresh, tools, checkKey: refuse, com: keyA });
  assert.deepEqual([bf.already, bf.failed, bf.mosaic, bf.status], [1, 1, "ready without its Apple form", "partial"], JSON.stringify(bf));
});

// A packager that fails only Apple's form (its 'cbcs' call); every other call goes to the real one.
async function failFairPlayPackager() {
  const f = join(tmp, "packager-fails-fairplay");
  await fs.writeFile(f, `#!/usr/bin/env node\nconst { spawnSync } = require("node:child_process");\nif (process.argv.includes("cbcs")) { console.error("Apple's form could not be packaged (a test)"); process.exit(1); }\nprocess.exit(spawnSync(${JSON.stringify(tools.packager)}, process.argv.slice(2), { stdio: "inherit" }).status ?? 1);\n`);
  await fs.chmod(f, 0o755);
  return f;
}

// The tenth review. (1) A renewal of the combined view's form that fails for any reason but the view's own output being
// unreadable keeps the view and its form (a rebuild used to delete the form first and, the packaging failing again,
// make none). (2) Every answer that keeps the view is written into its record with the reason, for the page (its "Try
// again" said "being remade" while nothing was). (3) What no test caught: a form made without Axinom's acceptance
// counts as a form; a real left-out entry beside a stale one; a picture the view DRAWS deleted while Axinom refuses
// or no key is set. (4) A kept view's count is the pictures it draws.
test("the combined view: a failed renewal keeps its form; every kept answer is recorded with its reason; a deleted picture always goes (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const KEY = await deriveKey("a test password, twelve+", toBase64(new Uint8Array(16).fill(11)), 1000), KEY_HEX = await exportKeyHex(KEY);
  const siteDir = await fs.mkdtemp(join(tmp, "keep-"));
  const upload = async (file) => { const f = join(tmp, "up-" + Math.random().toString(16).slice(2)); await fs.writeFile(f, await seal(KEY, await fs.readFile(file))); return f; };
  const add = async (id, color) => { process.env.WORKER_BLOB_FILE = await upload(await solid(`keep-${id[0]}.png`, 320, 240, color)); return worker({ payload: { action: "add", id, name: id[0] + ".png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools, checkKey: acceptKey, com: COM }); };
  const answer = (accepted, reached, message) => async () => ({ accepted, reached, status: reached ? (accepted ? 400 : 403) : 0, message });
  const accept = answer(true, true, "Invalid license request. (a test)"), refuse = answer(false, true, "Invalid DRM message. The signature is invalid.");
  const unreachable = answer(false, false, "Axinom could not be reached (3 tries): connect ECONNREFUSED (a test)");
  const mosaic = (checkKey, com, tl = tools) => worker({ payload: { key: KEY_HEX }, action: "mosaic", siteDir, tools: tl, ...(checkKey ? { checkKey } : {}), com });
  const metaPath = join(siteDir, "mosaic", "meta.json.enc");
  const mosaicMeta = async () => JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(metaPath))));
  const readyIds = async () => (await readGallery(siteDir, KEY)).photos.filter((x) => x.status === "ready").map((x) => x.id);
  const damage = async (id) => { const g = await readGallery(siteDir, KEY); g.photos.find((x) => x.id === id).prKidGuid = "00000000-0000-0000-0000-000000000000"; await fs.writeFile(join(siteDir, "gallery.json.enc"), await sealText(KEY, JSON.stringify(g))); };
  const formKept = async (form, what) => { assert.deepEqual((await mosaicMeta()).fairplay, form, what + ": its form kept"); await fs.access(join(siteDir, "mosaic", form.master)); };
  const keptJustNow = async (why) => { const k = (await mosaicMeta()).kept; assert.ok(k && Date.parse(k.at) > Date.now() - 120000, "recorded just now: " + JSON.stringify(k)); assert.match(k.why, why); };
  const A = "a".repeat(24), B = "b".repeat(24), C = "c".repeat(24), F = "f".repeat(24), G = "e".repeat(24);
  for (const [id, color] of [[A, "0xc0392b"], [B, "0x2980b9"]]) assert.equal((await add(id, color)).status, "ready");
  const failing = { ...tools, packager: await failFairPlayPackager() };

  // (1) a form made while Axinom could not be asked (unverified), renewed now that Axinom accepts the key, the
  // packaging failing: the view and its form kept, the failure said and recorded
  assert.equal((await mosaic(unreachable, COM)).status, "ready");
  const unverified = (await mosaicMeta()).fairplay;
  assert.equal(unverified.verified, false);
  const r1 = await mosaic(accept, COM, failing);
  assert.deepEqual([r1.status, r1.fairplay, r1.count], ["current", "failed", 2], JSON.stringify(r1));
  await formKept(unverified, "a failed renewal of an unverified form");
  await keptJustNow(/its new Apple form could not be made/);
  // ... and a verified one with ten days left (less than the renewal margin); refused, kept too
  assert.equal((await mosaic(accept, COM)).fairplay, "renewed");
  assert.equal((await mosaicMeta()).kept, undefined, "a renewal that worked leaves no 'kept' note behind");
  const m = await mosaicMeta();
  await fs.writeFile(metaPath, await sealText(KEY, JSON.stringify({ ...m, fairplay: { ...m.fairplay, expires: new Date(Date.now() + 10 * 86400000).toISOString() } })));
  const tenDays = (await mosaicMeta()).fairplay;
  assert.equal(tenDays.verified, true);
  const r2 = await mosaic(accept, COM, failing);
  assert.deepEqual([r2.status, r2.fairplay], ["current", "failed"], JSON.stringify(r2));
  await formKept(tenDays, "a failed renewal of a verified form with ten days left");
  const r2b = await mosaic(refuse, COM);
  assert.deepEqual([r2b.status, r2b.fairplay], ["current", "kept"], JSON.stringify(r2b));
  await formKept(tenDays, "a refused renewal");
  await keptJustNow(/its Apple form was not renewed: Axinom did not accept our key/);

  // (2) a picture REALLY left out (its key id damaged in the list), the view's new form unverified: the page's "Try
  // again" refused, out of reach, or with no key: kept as it is, its form untouched, the reason recorded; the count
  // is the pictures it draws
  assert.equal((await add(F, "0x16a085")).status, "ready");
  await damage(F);
  const r3 = await mosaic(unreachable, COM); // F joins: a view of other pictures, rebuilt; its new form made all the same
  assert.deepEqual([r3.status, r3.skipped], ["ready", 1], JSON.stringify(r3));
  const leftOutForm = (await mosaicMeta()).fairplay;
  assert.equal(leftOutForm.verified, false);
  for (const [gate, com, why] of [[refuse, COM, /rebuilding it would remove its Apple form, and Axinom did not accept our key/], [unreachable, COM, /rebuilding it would remove its Apple form, and Axinom could not be asked about our key/], [null, null, /rebuilding it would remove its Apple form, and no Axinom key is set/]]) {
    const r = await mosaic(gate, com);
    assert.deepEqual([r.status, r.fairplay, r.count], ["current", "kept", 2], JSON.stringify(r));
    await formKept(leftOutForm, "an unverified form, Try again: " + why);
    await keptJustNow(why);
  }

  // (3) a second left-out picture G, then deleted by the owner: only G's entry goes from the record; F's stays, the
  // form kept (Axinom refusing), the page counting the view as current; asked again, still kept
  assert.equal((await add(G, "0x8e44ad")).status, "ready");
  await damage(G);
  assert.equal((await mosaic(accept, COM)).status, "ready"); // G joins: rebuilt, with a verified form
  const twoLeft = await mosaicMeta();
  assert.deepEqual(twoLeft.skipped.map((x) => x.id).sort(), [F, G].sort());
  await worker({ payload: { action: "delete", id: G, key: KEY_HEX }, siteDir, tools });
  for (let i = 0; i < 2; i++) {
    const r = await mosaic(refuse, COM);
    assert.deepEqual([r.status, r.fairplay], ["current", "kept"], JSON.stringify(r));
    const now = await mosaicMeta();
    assert.deepEqual(now.skipped.map((x) => x.id), [F], "the real left-out entry stays, the stale one goes");
    assert.deepEqual(now.fairplay, twoLeft.fairplay, "its form kept");
    assert.equal(mosaicCurrent(now, await readyIds()), true, "the page counts it as current");
  }

  // (4) a picture the view DRAWS deleted, with no key at all or while Axinom refuses the key: the view is rebuilt
  // without it whatever Axinom says (a deleted picture never stays visible)
  await worker({ payload: { action: "delete", id: B, key: KEY_HEX }, siteDir, tools });
  const r4 = await mosaic(null, null);
  assert.equal(r4.status, "ready", JSON.stringify(r4));
  assert.deepEqual((await mosaicMeta()).ids, [A], "no key: rebuilt without the deleted picture");
  assert.equal((await add(C, "0xf39c12")).status, "ready");
  assert.equal((await mosaic(accept, COM)).status, "ready"); // C joins, with a form
  assert.ok((await mosaicMeta()).fairplay, "the view has a form again");
  await worker({ payload: { action: "delete", id: C, key: KEY_HEX }, siteDir, tools });
  const r5 = await mosaic(refuse, COM);
  assert.equal(r5.status, "ready", JSON.stringify(r5));
  assert.deepEqual((await mosaicMeta()).ids, [A], "Axinom refusing: rebuilt without the deleted picture");
  notice("FairPlay combined view kept", "a failed renewal (unverified; verified with 10 days left) kept its form; Try again refused / out of reach / no key kept an unverified form, each recorded with its reason; a stale left-out entry dropped beside a real one; a deleted drawn picture rebuilt out with no key and while refused");
});

// The card job's command, run as the job runs it (a child process of tools/fairplay-card.mjs with the Axinom key
// in its environment), with Axinom's answer stood in for (a module loaded first replaces fetch): accepted, it
// ends well; refused, or out of reach, it ends red (exit code 1) with Axinom's words, and never prints the key.
test("the card job's command asks Axinom about its token and ends red on a refusal or when Axinom is out of reach (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const stub = join(tmp, "stub-axinom.mjs");
  await fs.writeFile(stub, `const mode = process.env.STUB_AXINOM;
globalThis.fetch = async (url, init) => {
  if (mode === "down") throw Object.assign(new TypeError("fetch failed"), { cause: new Error("connect ECONNREFUSED (a test)") });
  const message = mode === "accept" ? "Invalid license request. Supported versions are 1, 2 or 3, but used version is 0." : "Invalid DRM message. The signature is invalid.";
  return new Response(null, { status: 400, headers: { "X-AxDRM-ErrorMessage": message } });
};
`);
  const out = await fs.mkdtemp(join(tmp, "cli-card-")), own = await fs.mkdtemp(join(tmp, "cli-own-"));
  // a RELATIVE packager path: the card is packaged in a work folder, so it runs only if the command runs the path it checked
  let rel = relative(process.cwd(), await checkPackager(tools.packager)); if (!rel.includes("/")) rel = "./" + rel;
  const env = { ...process.env, AXINOM_COM_KEY_ID: COM.id, AXINOM_COM_KEY: COM.key.toString("base64"), PACKAGER_BIN: rel };
  const go = (mode) => { const r = spawnSync(process.execPath, ["--import", pathToFileURL(stub).href, join(REPO, "tools", "fairplay-card.mjs"), "--out", out, "--own", own], { encoding: "utf8", env: { ...env, STUB_AXINOM: mode } }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; };
  const noKey = (r) => { for (const v of [COM.key.toString("base64"), COM.key.toString("hex")]) assert.ok(!r.out.includes(v), "the key is never printed"); };
  let r = go("accept");
  assert.equal(r.code, 0, r.out); noKey(r);
  assert.match(r.out, new RegExp(`Axinom accepts the own card's token: key id ${COM.id} and its key value are a pair it knows`));
  assert.ok(JSON.parse(await fs.readFile(join(own, "current.json"), "utf8")).folder, "the own card was made");
  r = go("refuse"); // the card is current now: still asked
  assert.equal(r.code, 1, r.out); noKey(r);
  assert.match(r.out, new RegExp(`Axinom REFUSED the own card's token \\(key id ${COM.id}\\): Invalid DRM message\\. The signature is invalid\\.`));
  r = go("down");
  assert.equal(r.code, 1, r.out); noKey(r);
  assert.match(r.out, new RegExp(`Axinom could not be asked about the own card's token \\(key id ${COM.id}\\): Axinom could not be reached \\(3 tries\\): connect ECONNREFUSED \\(a test\\)`));
});

// Axinom refuses a licence with HTTP 400 or 403 and its reason in a header; Shaka hands the page that response as
// an error (6007 wrapping 1001, the headers in data[3]), never through the response filter. Each page reads the
// reason with its own code (read from the page, never copied) and puts it in the licence cell.
test("the pages put Axinom's reason for a refused licence in the licence cell, read from the player's error", async () => {
  const WHY = "License denied. The DRM message references the ID of an unknown communication key.";
  const httpError = { category: 1, code: 1001, data: ["https://x.drm-fairplay-licensing.axprod.net/AcquireLicense", 403, "", { "x-axdrm-errormessage": WHY }, 2] };
  const licenceError = { category: 6, code: 6007, data: [httpError] };
  const helpersOf = (page) => page.match(/^ *const axinomSays = .*$/m)[0] + "\n" + page.match(/^ *const axinomReason = .*$/m)[0];
  for (const f of ["web/research/drm/index.html", "site/view.html", "site/all.html"]) {
    const page = await fs.readFile(join(REPO, f), "utf8");
    const axinomReason = new Function(`${helpersOf(page)}\nreturn axinomReason;`)();
    assert.equal(axinomReason(licenceError), WHY, `${f}: a licence error wrapping the HTTP error`);
    assert.equal(axinomReason(httpError), WHY, `${f}: the HTTP error itself`);
    assert.equal(axinomReason({ code: 6007, data: [{ code: 1001, data: ["u", 500, "", {}] }] }), "", `${f}: no reason without the header`);
    assert.equal(axinomReason({}), "", `${f}: nothing`);
    // the route-1 page and the views built from it: the error listener and the failed load both fill the cell
    const line = page.match(/^ *const refused = \(d\) => \{ const why = fp \? axinomReason\(d\) : ""; if \(why\) set\("r-lic", `refused by Axinom: \$\{why\}`, "bad"\); return why; \};$/m);
    assert.ok(line, `${f}: a refusal goes in the licence cell`);
    const sets = [];
    new Function("fp", "axinomReason", "set", `${line[0]}\nreturn refused;`)({}, axinomReason, (id, text) => sets.push([id, text]))(licenceError);
    assert.deepEqual(sets, [["r-lic", "refused by Axinom: " + WHY]], f);
    assert.match(page, /player\.addEventListener\("error", \(e\) => \{ refused\(\(e && e\.detail\) \|\| \{\}\);/, `${f}: from the player's error event`);
    assert.match(page, /\} catch \(e\) \{\n\s+refused\(e\);\n\s+log\(`\$\{tierName\}: not available here/, `${f}: and from a failed load`);
  }
  // Apple's test on the route-1 page: its own protectedPlay, run with a stand-in player that fails the way Shaka does
  const page = await fs.readFile(join(REPO, "web/research/drm/index.html"), "utf8");
  const from = page.indexOf("    async function protectedPlay("), to = page.indexOf("\n    await protectedPlay(", from);
  assert.ok(from > 0 && to > from, "protectedPlay is where this test reads it");
  for (const how of ["the load fails", "an error event"]) {
    const sets = [];
    const shaka = { net: { NetworkingEngine: { RequestType: { LICENSE: 2 } } }, Player: class {
      constructor() { this.on = {}; } async attach() {} configure() {}
      getNetworkingEngine() { return { registerRequestFilter() {}, registerResponseFilter() {} }; }
      addEventListener(type, f) { this.on[type] = f; }
      async load() { if (how === "an error event") { this.on.error({ detail: licenceError }); return; } throw licenceError; }
      drmInfo() { return null; } } };
    const protectedPlay = new Function("shaka", "$", "AXINOM_CERT", "alog", "set", "watch", "AXINOM_PUBLIC_TOKEN", "AXINOM_LICENSE", `${helpersOf(page)}\n${page.slice(from, to)}\nreturn protectedPlay;`)(
      shaka, () => ({ play: () => Promise.resolve() }), "cert", () => {}, (id, text) => sets.push([id, text]), () => {}, "T", "https://drm-fairplay-licensing.axprod.net/AcquireLicense");
    await protectedPlay("vo", "o", "u", "our card, our account (protected)");
    assert.ok(sets.some(([id, text]) => id === "o-lic" && text === "refused by Axinom: " + WHY), `${how}: the licence cell names Axinom's reason: ${JSON.stringify(sets)}`);
  }
  // "obtained" is written for a licence response, and for nothing else the player fetches
  const responseFilters = [], sets = [];
  const shaka2 = { net: { NetworkingEngine: { RequestType: { LICENSE: 2 } } }, Player: class {
    async attach() {} configure() {} addEventListener() {} async load() {} drmInfo() { return { keySystem: "com.apple.fps" }; }
    getNetworkingEngine() { return { registerRequestFilter() {}, registerResponseFilter(f) { responseFilters.push(f); } }; } } };
  await new Function("shaka", "$", "AXINOM_CERT", "alog", "set", "watch", "AXINOM_PUBLIC_TOKEN", "AXINOM_LICENSE", `${helpersOf(page)}\n${page.slice(from, to)}\nreturn protectedPlay;`)(
    shaka2, () => ({ play: () => Promise.resolve() }), "cert", () => {}, (id, text) => sets.push([id, text]), () => {}, "T", "https://drm-fairplay-licensing.axprod.net/AcquireLicense")("vo", "o", "u", "x");
  responseFilters[0](1, { data: new ArrayBuffer(5) }); responseFilters[0](0, { data: new ArrayBuffer(6) });
  assert.ok(!sets.some(([id]) => id === "o-lic"), "Apple's test: no licence line for a manifest or a segment");
  responseFilters[0](2, { data: new ArrayBuffer(7) });
  assert.deepEqual(sets.filter(([id]) => id === "o-lic"), [["o-lic", "obtained, 7 bytes"]], "Apple's test: obtained, for the licence");
  for (const f of ["web/research/drm/index.html", "site/view.html", "site/all.html"]) {
    // the page's own player (tryOne, at four spaces); Apple's test has its own, read above
    const head = "\n    player.getNetworkingEngine().registerResponseFilter(", pg = await fs.readFile(join(REPO, f), "utf8"), at = pg.indexOf(head), end = pg.indexOf("\n    });", at + 1);
    assert.ok(at > 0 && end > at && pg.indexOf(head, at + 1) < 0, `${f}: its response filter is where this test reads it, once`);
    const got = [], filter = new Function("shaka", "set", "log", "tierName", `return ${pg.slice(at + head.length, end)}\n    };`)(shaka2, (id, text) => got.push([id, text]), () => {}, "t");
    filter(1, { data: new ArrayBuffer(5) }); filter(0, { data: new ArrayBuffer(6) });
    assert.deepEqual(got, [], `${f}: no licence line for a manifest or a segment`);
    filter(2, { data: new ArrayBuffer(9) });
    assert.deepEqual(got, [["r-lic", "obtained, 9 bytes"]], `${f}: obtained, for the licence`);
  }
});

// A licence token goes only with a licence request (the seventeenth review: nothing held that, for Apple's test or for
// the page's own player): every other request a player makes (a playlist, a segment, the certificate) carries none
test("a licence token is added to licence requests only, by Apple's test and by the page's own player", async () => {
  const LICENSE = 2, OTHERS = [0, 1, 3, 4, 5, 6, 7];
  // requests as the player makes them, with an address (the eighteenth review: a filter that decided by the address
  // passed requests with none): the token goes with the licence REQUEST TYPE, whatever the address, and with no other
  const URIS = ["https://drm-fairplay-licensing.axprod.net/AcquireLicense", "https://0a1b2c3d.drm-fairplay-licensing.axprod.net/AcquireLicense",
    "https://tools.axinom.com/FPScert/fairplay.cer", "https://media.axprod.net/TestVectors/Hls/protected_hls_1080p_h264_singlekey/manifest.m3u8", "card-fairplay/video.mp4", "skd://4060a865-8878-4267-9cbf-91ae5bae1e72"];
  const ask = (f, type, uri) => { const r = { headers: {}, uris: [uri], method: type === LICENSE ? "POST" : "GET" }; f(type, r); return r.headers; };
  const page = await fs.readFile(join(REPO, "web/research/drm/index.html"), "utf8");
  const helpers = page.match(/^ *const axinomSays = .*$/m)[0] + "\n" + page.match(/^ *const axinomReason = .*$/m)[0];
  // Apple's test (the route-1 page): its own protectedPlay, with a stand-in player that keeps the filter it is given
  const from = page.indexOf("    async function protectedPlay("), to = page.indexOf("\n    await protectedPlay(", from);
  assert.ok(from > 0 && to > from, "protectedPlay is where this test reads it");
  const filters = [];
  const shaka = { net: { NetworkingEngine: { RequestType: { LICENSE } } }, Player: class { async attach() {} configure() {} addEventListener() {} async load() {} drmInfo() { return null; }
    getNetworkingEngine() { return { registerRequestFilter(f) { filters.push(f); }, registerResponseFilter() {} }; } } };
  const protectedPlay = new Function("shaka", "$", "AXINOM_CERT", "alog", "set", "watch", "AXINOM_PUBLIC_TOKEN", "AXINOM_LICENSE", `${helpers}\n${page.slice(from, to)}\nreturn protectedPlay;`)(
    shaka, () => ({ play: () => Promise.resolve() }), "cert", () => {}, () => {}, () => {}, "PUBLIC.TOKEN", "https://drm-fairplay-licensing.axprod.net/AcquireLicense");
  await protectedPlay("vo", "o", "u", "x", "OWN.TOKEN");
  await protectedPlay("vp", "p", "u", "y");
  assert.equal(filters.length, 2, "one request filter per player");
  for (const [f, token] of [[filters[0], "OWN.TOKEN"], [filters[1], "PUBLIC.TOKEN"]]) for (const uri of URIS) {
    for (const type of OTHERS) assert.deepEqual(ask(f, type, uri), {}, `Apple's test, request type ${type} to ${uri}: no token`);
    assert.deepEqual(ask(f, LICENSE, uri), { "X-AxDRM-Message": token }, `Apple's test, a licence request to ${uri}: the token given`);
  }
  // the page's own player (tryOne), on the route-1 page and on the two pages built from it
  for (const f of ["web/research/drm/index.html", "site/view.html", "site/all.html"]) {
    const pg = await fs.readFile(join(REPO, f), "utf8"), head = "    if (fp) player.getNetworkingEngine().registerRequestFilter(", at = pg.indexOf(head), end = pg.indexOf("\n    });", at);
    assert.ok(at > 0 && end > at && pg.indexOf(head, at + 1) < 0, `${f}: its request filter is where this test reads it, once`);
    const got = [];
    new Function("fp", "player", "shaka", "log", "tierName", pg.slice(at, end) + "\n    });")({ token: "THE.CLIPS.TOKEN" }, { getNetworkingEngine: () => ({ registerRequestFilter: (fn) => got.push(fn) }) }, shaka, () => {}, "t");
    assert.equal(got.length, 1, f);
    for (const uri of URIS) {
      for (const type of OTHERS) assert.deepEqual(ask(got[0], type, uri), {}, `${f}, request type ${type} to ${uri}: no token`);
      assert.deepEqual(ask(got[0], LICENSE, uri), { "X-AxDRM-Message": "THE.CLIPS.TOKEN" }, `${f}, a licence request to ${uri}: the clip's token`);
    }
  }
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
  assert.ok(info.byteCheck.encryptedBlocks > 0 && info.byteCheck.blocksLeftClear === 0 && info.byteCheck.decryptedWrong === 0, "the card passes the byte check: " + JSON.stringify(info.byteCheck));
  await assert.rejects(buildFairPlayCard({ tools: { ...tools, packager: await clearBytesPackager() }, outDir: await fs.mkdtemp(join(tmp, "card-clear-")) }), /the card's FairPlay form failed its byte check: .*blocks recorded as encrypted are the clip's own bytes/, "a card whose bytes were left clear is refused by the byte check");
  await assert.rejects(buildFairPlayCard({ tools: { ...tools, packager: await wrongKeyPackager() }, outDir: await fs.mkdtemp(join(tmp, "card-wrong-")) }), /the card's FairPlay form failed its byte check: .*decrypt with the form's own key to something other than the clip/, "a card encrypted under another key is refused by the byte check");
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
  assert.equal(await ownCardCurrent(root, { ...COM, key: nodeRandom(32) }), false, "the same key id with a corrected key value: remade");
  assert.equal(JSON.parse(await fs.readFile(join(root, "current.json"), "utf8")).license, AXINOM_FAIRPLAY_LICENSE, "current.json records the licence address the token is for");
  assert.equal(await ownCardCurrent(root, { ...COM, license: OWN_LICENSE }), false, "another licence address: remade");
  assert.equal(await ownCardCurrent(root, COM, Date.parse(own.expires) - 13 * 86400000), false, "13 days left: remade");
  const renewed = await buildOwnCard({ tools, root, com: COM });
  assert.notEqual(renewed.folder, own.folder); assert.deepEqual((await fs.readdir(root)).sort(), ["current.json", renewed.folder].sort(), "a renewal is a fresh folder; the old one is gone");
  notice("FairPlay own card", `${own.keyUri}; token by the (test) account ${COM.id}; decryptCheck ${JSON.stringify(own.decryptCheck)}`);
});

// THE BACKFILL'S ENTRY, run as the workflow runs it (a child process, the real site/backfill.mjs) on a
// scratch site: the picture key is masked before anything else is printed and appears nowhere else; a
// password that does not open the gallery is a named error, not a quiet green run; a missing Axinom key is
// an error when started by hand and nothing to do on the weekly run. It runs with the real packager: the entry checks
// the packager it would run before anything else touches the site (the next test).
test("the backfill's entry: the picture key masked first and nowhere else; a wrong password or a missing key named; the weekly run without a key does nothing (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const PW = "a test password, twelve+", SALT = toBase64(new Uint8Array(16).fill(9));
  const site = await fs.mkdtemp(join(tmp, "bf-"));
  await fs.writeFile(join(site, "config.json"), JSON.stringify({ salt: SALT, iterations: 1000 }));
  const want = await exportKeyHex(await derivePhotoKey(await deriveKey(PW, SALT, 1000)));
  const env = { ...process.env, SITE_DIR: site, SITE_PASSWORD: PW, AXINOM_COM_KEY_ID: COM.id, AXINOM_COM_KEY: COM.key.toString("base64"), BACKFILL_RESULT: join(site, "result.json"), PACKAGER_BIN: tools.packager, GITHUB_EVENT_NAME: "workflow_dispatch" };
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
  // a picture that needs its form, and Axinom refusing our key (a stand-in fetch loaded first): stopped before
  // anything is replaced, named on the run's page, a result left for the workflow; the key never printed
  const photoKey = await derivePhotoKey(await deriveKey(PW, SALT, 1000)), F = "f".repeat(24);
  await fs.writeFile(join(site, "gallery.json.enc"), await sealText(photoKey, JSON.stringify({ photos: [{ id: F, name: "f.png", status: "ready", prKidGuid: "00000000-0000-0000-0000-000000000001", fairplay: false }] })));
  await fs.mkdir(join(site, "photos", F), { recursive: true });
  await fs.writeFile(join(site, "photos", F, "meta.json.enc"), await sealText(photoKey, JSON.stringify({ id: F, fairplay: null })));
  const stub = join(tmp, "stub-refuse.mjs");
  await fs.writeFile(stub, `globalThis.fetch = async () => new Response(null, { status: 400, headers: { "X-AxDRM-ErrorMessage": "Invalid DRM message. The signature is invalid." } });\n`);
  const s2 = spawnSync(process.execPath, ["--import", pathToFileURL(stub).href, join(REPO, "site", "backfill.mjs")], { encoding: "utf8", env });
  const out2 = (s2.stdout || "") + (s2.stderr || "");
  assert.equal(s2.status, 1, out2); masked(out2);
  assert.match(out2, /::error title=Apple backfill::Axinom does not accept our key \(key id [0-9a-f-]{36}\): Invalid DRM message\. The signature is invalid\.; no Apple form was made or replaced/);
  assert.equal(JSON.parse(await fs.readFile(join(site, "result.json"), "utf8")).status, "stopped");
  assert.ok(!out2.includes(COM.key.toString("base64")), "the Axinom key never printed");
});

// The eleventh review. (1) Every answer to a page's request carries the request's id (meta.answered, the last ten,
// newest first), whatever the answer; the job's own runs add none; an id that is not 16 hex is refused. (2) A rebuild of
// the SAME pictures is made beside the view and swapped in only whole: one that came out without an Apple form, while
// the view has a working one, leaves the view as it was (its form used to be deleted first and the view committed with
// none, unwarned); a view of OTHER pictures is replaced all the same, and the job warns. (3) Only the view's own output
// being unreadable sends a renewal to a rebuild: a failed render, a new form that fails its check, or a program that
// cannot be started keep the view as it is. (4) A form whose token has expired is not a working form: nothing waits on
// Axinom to replace it. (5) "Last tried at" is the keep's own time. (6) A form whose copy fails leaves no half-made
// folder to be published.
test("the combined view answers each request by its id; a rebuild of the same pictures is swapped in only whole; only an unreadable output is rebuilt; an expired form is not kept for (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const KEY = await deriveKey("a test password, twelve+", toBase64(new Uint8Array(16).fill(12)), 1000), KEY_HEX = await exportKeyHex(KEY);
  const siteDir = await fs.mkdtemp(join(tmp, "ask-"));
  const upload = async (file) => { const f = join(tmp, "up-" + Math.random().toString(16).slice(2)); await fs.writeFile(f, await seal(KEY, await fs.readFile(file))); return f; };
  const add = async (id, color, tl = tools) => { process.env.WORKER_BLOB_FILE = await upload(await solid(`ask-${id[0]}.png`, 320, 240, color)); return worker({ payload: { action: "add", id, name: id[0] + ".png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: KEY_HEX }, siteDir, tools: tl, checkKey: acceptKey, com: COM }); };
  const answer = (accepted, reached, message) => async () => ({ accepted, reached, status: reached ? (accepted ? 400 : 403) : 0, message });
  const accept = answer(true, true, "Invalid license request. (a test)"), refuse = answer(false, true, "Invalid DRM message. The signature is invalid.");
  const unreachable = answer(false, false, "Axinom could not be reached (3 tries): connect ECONNREFUSED (a test)");
  const mosaic = (checkKey, ask, tl = tools, checkTool) => worker({ payload: { key: KEY_HEX, ...(ask !== undefined ? { ask } : {}) }, action: "mosaic", siteDir, tools: tl, checkKey, com: COM, ...(checkTool ? { checkTool } : {}) });
  const metaPath = join(siteDir, "mosaic", "meta.json.enc");
  const mosaicMeta = async () => JSON.parse(await openText(KEY, new Uint8Array(await fs.readFile(metaPath))));
  const setMeta = async (over) => fs.writeFile(metaPath, await sealText(KEY, JSON.stringify({ ...(await mosaicMeta()), ...over })));
  const formExpires = async (ms) => setMeta({ fairplay: { ...(await mosaicMeta()).fairplay, expires: new Date(Date.now() + ms).toISOString() } });
  const damage = async (id) => { const g = await readGallery(siteDir, KEY); g.photos.find((x) => x.id === id).prKidGuid = "00000000-0000-0000-0000-000000000000"; await fs.writeFile(join(siteDir, "gallery.json.enc"), await sealText(KEY, JSON.stringify(g))); };
  const noSideBuild = async () => assert.ok(!(await fs.readdir(siteDir)).includes(".mosaic-next"), "nothing half-built is left beside the view");
  const ask = (n) => n.toString(16).padStart(16, "0");
  const A = "a".repeat(24), B = "b".repeat(24), C = "c".repeat(24), D = "d".repeat(24), E = "e".repeat(24), G = "9".repeat(24);
  for (const [id, color] of [[A, "0xc0392b"], [B, "0x2980b9"]]) assert.equal((await add(id, color)).status, "ready");
  const failing = { ...tools, packager: await failFairPlayPackager() };

  // (1) the request id: refused unless 16 hex; written with every kind of answer, newest first; the job's own runs add none
  for (const bad of ["XYZ", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", 1234567890123456]) await assert.rejects(mosaic(accept, bad), /bad request id/, String(bad));
  // the job's packager check, asked by the view just before it first packages: the path it RETURNS is the one run, for a
  // rebuild (its clip and its Apple form) and for a renewal of its form (the fourteenth review: discarding it passed every
  // test; the fifteenth: a form run by the path given failed, was only logged, and the view still answered "ready"). The
  // path given here cannot run; the check answers with the real packager's.
  const GIVEN = { ...tools, packager: "/nonexistent/the-path-given" }, asked = [];
  const CHECKED = async (p) => { asked.push(p); return tools.packager; };
  const given1 = await mosaic(accept, ask(1), GIVEN, CHECKED);
  assert.deepEqual([given1.status, given1.fairplay], ["ready", true], "the rebuild's clip and its Apple form, both by the path returned");
  assert.deepEqual((await mosaicMeta()).answered, [ask(1)], "a rebuild carries the id");
  assert.equal((await mosaic(accept, ask(2))).status, "current");
  assert.deepEqual((await mosaicMeta()).answered, [ask(2), ask(1)], "unchanged: the answer is still written");
  assert.equal((await mosaic(accept)).status, "current");
  assert.deepEqual((await mosaicMeta()).answered, [ask(2), ask(1)], "the job's own run adds none");
  await formExpires(10 * 86400000);
  assert.equal((await mosaic(accept, ask(3), GIVEN, CHECKED)).fairplay, "renewed");
  assert.deepEqual(asked, [GIVEN.packager, GIVEN.packager], "asked once by the rebuild and once by the renewal, with the path given");
  assert.deepEqual((await mosaicMeta()).answered.slice(0, 2), [ask(3), ask(2)], "a renewal carries the id");
  await formExpires(10 * 86400000);
  const f1 = await mosaic(accept, ask(4), failing);
  assert.deepEqual([f1.status, f1.fairplay], ["current", "failed"], JSON.stringify(f1));
  assert.equal((await mosaicMeta()).answered[0], ask(4), "a failed renewal carries the id");
  // (5) "Last tried at" is the time of the keep, never the view's build time (the build time set far back first)
  await setMeta({ builtAt: "2020-01-02T03:04:05.000Z" });
  const r1 = await mosaic(refuse, ask(5));
  assert.deepEqual([r1.status, r1.fairplay], ["current", "kept"], JSON.stringify(r1));
  const kept = await mosaicMeta();
  assert.equal(kept.answered[0], ask(5), "a kept answer carries the id");
  assert.ok(Math.abs(Date.parse(kept.kept.at) - Date.now()) < 120000 && kept.kept.at !== kept.builtAt, "kept at the time of the keep: " + JSON.stringify([kept.kept, kept.builtAt]));
  // the list keeps the last ten; an id answered twice is listed once
  for (let i = 6; i <= 17; i++) await mosaic(refuse, ask(i));
  await mosaic(refuse, ask(16));
  assert.deepEqual((await mosaicMeta()).answered, [16, 17, 15, 14, 13, 12, 11, 10, 9, 8].map(ask));
  // the job's own runs (no request) add nothing, whatever their answer: kept, or a renewal (a rebuild: below)
  const own = (await mosaicMeta()).answered;
  assert.deepEqual([(await mosaic(refuse)).fairplay, (await mosaicMeta()).answered], ["kept", own], "a kept answer of the job's own adds nothing");
  await formExpires(10 * 86400000);
  assert.deepEqual([(await mosaic(accept)).fairplay, (await mosaicMeta()).answered], ["renewed", own], "a renewal of the job's own adds nothing");

  // (2) a picture REALLY left out, the view with a verified form; "Try again" with Axinom accepting rebuilds the same
  // pictures, and Apple's packaging fails in the rebuild: the view is kept whole, its form with it, the failure said
  assert.equal((await add(C, "0x16a085")).status, "ready");
  await damage(C);
  assert.equal((await mosaic(accept, ask(20))).status, "ready");
  const whole = await mosaicMeta();
  assert.deepEqual([whole.skipped.map((x) => x.id), whole.fairplay.verified], [[C], true]);
  const r2 = await mosaic(accept, ask(21), failing);
  assert.deepEqual([r2.status, r2.fairplay, r2.count], ["current", "failed", 2], JSON.stringify(r2));
  const after2 = await mosaicMeta();
  assert.deepEqual([after2.builtAt, after2.ids, after2.fairplay], [whole.builtAt, whole.ids, whole.fairplay], "the view kept whole, with its form");
  await fs.access(join(siteDir, "mosaic", whole.fairplay.master));
  assert.match(after2.kept.why, /its rebuild made no Apple form \(.*Apple's form could not be packaged \(a test\).*\); the current view and its form stay/);
  assert.equal(after2.answered[0], ask(21)); await noSideBuild();
  assert.ok(resultLines(r2, { com: COM, action: "mosaic" }).some((l) => /^::warning title=Apple form::/.test(l)), "and the job warns");
  // the same rebuild without the failure: swapped in whole, a new verified form, C still left out, the old form gone with the old view
  const r3 = await mosaic(accept, ask(22));
  assert.deepEqual([r3.status, r3.skipped], ["ready", 1], JSON.stringify(r3));
  const rebuilt = await mosaicMeta();
  assert.ok(rebuilt.fairplay.verified && rebuilt.fairplay.master !== whole.fairplay.master && rebuilt.answered[0] === ask(22), JSON.stringify(rebuilt.fairplay));
  assert.deepEqual((await fs.readdir(join(siteDir, "mosaic"))).filter((f) => /^fp-/.test(f)), [rebuilt.fairplay.master.split("/")[0]]);
  await noSideBuild();
  // Try again, then the left-out picture deleted before the job runs: the answer is the stale entry dropped with nothing
  // else to do (its form is current), and it carries the request's id (written on that path alone)
  await worker({ payload: { action: "delete", id: C, key: KEY_HEX }, siteDir, tools });
  const r3b = await mosaic(accept, ask(23));
  const after3b = await mosaicMeta();
  assert.deepEqual([r3b.status, after3b.skipped, after3b.answered[0], after3b.builtAt], ["current", [], ask(23), rebuilt.builtAt], JSON.stringify(r3b));
  // a view of OTHER pictures (D added) whose Apple packaging fails: swapped in without a form (its old content must go), warned
  assert.equal((await add(D, "0x8e44ad")).status, "ready");
  const beforeR4 = (await mosaicMeta()).answered;
  const r4 = await mosaic(accept, undefined, failing);
  assert.deepEqual([r4.status, r4.fairplay], ["ready", false], JSON.stringify(r4));
  const other = await mosaicMeta();
  assert.ok(other.ids.includes(D) && other.fairplay === null, JSON.stringify(other.ids));
  assert.deepEqual(other.answered, beforeR4, "a rebuild of the job's own adds nothing");
  assert.ok(other.answered.every((x) => /^[0-9a-f]{16}$/.test(x)), "and the list holds request ids only: " + JSON.stringify(other.answered));
  assert.ok(resultLines(r4, { com: COM, action: "mosaic" }).some((l) => /^::warning title=Apple form::the combined view was made without its Apple form/.test(l)));
  await noSideBuild();

  // (3) only the view's own output unreadable sends a renewal to a rebuild (C is gone, so nothing is left out and only the
  // form is renewed from here on)
  assert.equal((await mosaic(accept)).fairplay, "renewed");
  const keepsView = async (tl, re, what) => {
    await formExpires(10 * 86400000);
    const before = await mosaicMeta();
    const r = await mosaic(accept, undefined, tl);
    assert.deepEqual([r.status, r.fairplay], ["current", "failed"], what + ": " + JSON.stringify(r));
    const now = await mosaicMeta();
    assert.deepEqual([now.builtAt, now.fairplay], [before.builtAt, before.fairplay], what + ": not rebuilt, its form kept");
    assert.match(now.kept.why, re, what);
  };
  const script = async (name, body) => { const f = join(tmp, name); await fs.writeFile(f, `#!/usr/bin/env node\nconst { spawnSync } = require("node:child_process"); const fs = require("node:fs"); const path = require("node:path");\n${body}\n`); await fs.chmod(f, 0o755); return f; };
  // a failed render of the new form's clip (ffmpeg fails only when it encodes)
  const ffFails = await script("ffmpeg-fails-encode", `if (process.argv.includes("libx264")) { console.error("the clip could not be rendered (a test)"); process.exit(1); }\nprocess.exit(spawnSync("ffmpeg", process.argv.slice(2), { stdio: "inherit" }).status ?? 1);`);
  await keepsView({ ...tools, ffmpeg: ffFails }, /its new Apple form could not be made \(.*the clip could not be rendered \(a test\)/, "a failed render");
  // a new form that fails its check (the key line taken out of its playlist after packaging)
  const afterApple = (then) => `const s = spawnSync(${JSON.stringify(tools.packager)}, process.argv.slice(2), { stdio: "inherit" }).status ?? 1;\nconst i = process.argv.indexOf("--hls_master_playlist_output");\nif (!s && i > 0) { const master = path.resolve(process.argv[i + 1]); ${then} }\nprocess.exit(s);`;
  const noKeyLine = await script("packager-drops-key-line", afterApple(`const p = path.join(path.dirname(master), "video.m3u8"); fs.writeFileSync(p, fs.readFileSync(p, "utf8").split("\\n").filter((l) => !l.startsWith("#EXT-X-KEY")).join("\\n"));`));
  await keepsView({ ...tools, packager: noKeyLine }, /its new Apple form could not be made \(the FairPlay form failed its check: /, "a form that fails its check");
  // a program that cannot be started at all (the view's own output is fine)
  await keepsView({ ...tools, ffmpeg: "/nonexistent/ffmpeg" }, /its new Apple form could not be made \(.*ENOENT/, "ffmpeg not there");
  // the view's own output missing (a file, not a program): unreadable, so rebuilt (Axinom accepting), swapped in whole
  await formExpires(10 * 86400000);
  await fs.rm(join(siteDir, "mosaic", "video-playready.mp4.enc"));
  // ... and when that rebuild fails after its new files were begun beside the view (a manifest gone after packaging),
  // the old view stays exactly as it was and nothing half-made is left beside it
  const before5 = await mosaicMeta();
  const dropsManifest = await script("packager-drops-manifest", `const s = spawnSync(${JSON.stringify(tools.packager)}, process.argv.slice(2), { stdio: "inherit" }).status ?? 1;\nif (!s && process.argv.includes("playready.mpd")) fs.rmSync("playready.mpd");\nprocess.exit(s);`);
  await assert.rejects(mosaic(accept, ask(29), { ...tools, packager: dropsManifest }), /playready\.mpd/);
  assert.deepEqual(await mosaicMeta(), before5, "the old view stays as it was"); await noSideBuild();
  const r5 = await mosaic(accept, ask(30));
  assert.equal(r5.status, "ready", JSON.stringify(r5)); assert.ok((await mosaicMeta()).fairplay.verified); await noSideBuild();

  // (4) a form whose token has expired is not a working form: Axinom out of reach, a new one is made (unverified)
  await formExpires(-86400000);
  const r6 = await mosaic(unreachable, ask(31));
  assert.deepEqual([r6.status, r6.fairplay], ["current", "renewed"], JSON.stringify(r6));
  assert.equal((await mosaicMeta()).fairplay.verified, false);
  // ... and with a picture left out, "Try again" is rebuilt while Axinom refuses (the dead form goes; no new one)
  assert.equal((await add(E, "0xf39c12")).status, "ready"); await damage(E);
  assert.equal((await mosaic(accept)).status, "ready");
  await formExpires(-86400000);
  const r7 = await mosaic(refuse, ask(32));
  assert.deepEqual([r7.status, r7.fairplay], ["ready", false], JSON.stringify(r7));
  assert.equal((await mosaicMeta()).fairplay, null, "the dead form went with the old view");
  // a left-out picture deleted (a stale entry), and the rebuild then failing (the thirteenth review): the record's clean-up
  // stays (the job commits it) but answers no request; only a run that finishes answers (the page waits ten minutes at most)
  const H = "8".repeat(24);
  assert.equal((await add(H, "0x2c3e50")).status, "ready"); await damage(H);
  assert.equal((await mosaic(accept)).status, "ready");
  assert.deepEqual((await mosaicMeta()).skipped.map((x) => x.id).sort(), [E, H].sort());
  await worker({ payload: { action: "delete", id: H, key: KEY_HEX }, siteDir, tools });
  const beforeStale = await mosaicMeta();
  await assert.rejects(mosaic(accept, ask(33), { ...tools, ffmpeg: "/nonexistent/ffmpeg" }), /no picture could be read back/);
  const stale = await mosaicMeta();
  assert.deepEqual([stale.skipped.map((x) => x.id), stale.answered, stale.builtAt], [[E], beforeStale.answered, beforeStale.builtAt], "the stale entry dropped, no request answered, the view itself unchanged");

  // a picture the view DRAWS deleted, and the rebuild then failing (no picture can be read back: ffmpeg cannot be
  // started): the old view is gone all the same (its content must not stay on the site), and nothing half-built is left
  await worker({ payload: { action: "delete", id: D, key: KEY_HEX }, siteDir, tools });
  await assert.rejects(mosaic(accept, undefined, { ...tools, ffmpeg: "/nonexistent/ffmpeg" }), /no picture could be read back/);
  await assert.rejects(fs.access(join(siteDir, "mosaic")), "the old view is gone");
  await noSideBuild();

  // (6) a form whose copy fails (its master playlist gone after packaging): no half-made folder is left to publish
  const noMaster = await script("packager-drops-master", afterApple("fs.rmSync(master);"));
  const rg = await add(G, "0x7f8c8d", { ...tools, packager: noMaster });
  assert.deepEqual([rg.status, rg.fairplay], ["ready", false], JSON.stringify(rg));
  assert.deepEqual((await fs.readdir(join(siteDir, "photos", G))).filter((f) => /^fp/.test(f)), [], "no Apple form, and nothing half-made left behind");
  assert.ok(resultLines(rg, { com: COM, action: "add" }).some((l) => /^::warning title=Apple form::the picture was made without its Apple form/.test(l)));
  // (7) the site's job command as the workflow runs it (the real packager; Axinom's answer stood in for, refusing):
  // G's arrival makes a view of other pictures, made without a form, and the command's last lines say so
  const refuseStub = join(tmp, "stub-ask-refuse.mjs"), evt = join(tmp, "ask-event.json");
  await fs.writeFile(refuseStub, `globalThis.fetch = async () => new Response(null, { status: 400, headers: { "X-AxDRM-ErrorMessage": "Invalid DRM message. The signature is invalid." } });\n`);
  await fs.writeFile(evt, JSON.stringify({ client_payload: { action: "mosaic", key: KEY_HEX, ask: ask(40) } }));
  const cli = spawnSync(process.execPath, ["--import", pathToFileURL(refuseStub).href, join(REPO, "site", "worker.mjs")], { encoding: "utf8", env: { ...process.env, GITHUB_EVENT_PATH: evt, SITE_DIR: siteDir, PACKAGER_BIN: tools.packager, WORKER_ACTION: "mosaic", AXINOM_COM_KEY_ID: COM.id, AXINOM_COM_KEY: COM.key.toString("base64") } });
  const cliOut = (cli.stdout || "") + (cli.stderr || "");
  assert.equal(cli.status, 0, cliOut);
  assert.match(cliOut, /^result: ready \(3 picture\(s\)\); Apple form: false$/m);
  assert.match(cliOut, /^::warning title=Apple form::the combined view was made without its Apple form \(see the log above\); Apple devices are held back until it has one$/m);
  assert.equal((await mosaicMeta()).answered[0], ask(40), "the command passes the request's id on");
  // (8) the thirteenth review: the combined view's job checks the packager just before it first runs it, the renewal of
  // the view's form included. E deleted (a stale entry: the view then holds exactly the ready pictures, with no form yet);
  // another packager file is refused before it is ever run, the job ends red, the view stays (its record cleaned)
  await worker({ payload: { action: "delete", id: E, key: KEY_HEX }, siteDir, tools });
  const acceptStub = join(tmp, "stub-ask-accept.mjs"), ranMark = join(tmp, "renewal-wrong-ran"), wrongPk = join(tmp, "renewal-wrong-packager");
  await fs.writeFile(acceptStub, `globalThis.fetch = async () => new Response(null, { status: 400, headers: { "X-AxDRM-ErrorMessage": "Invalid license request. Supported versions are 1, 2 or 3, but used version is 0." } });\n`);
  await fs.writeFile(wrongPk, `#!/bin/sh\ntouch ${JSON.stringify(ranMark)}\necho 'packager version v3.9.3'\n`); await fs.chmod(wrongPk, 0o755);
  const before8 = await mosaicMeta();
  await fs.writeFile(evt, JSON.stringify({ client_payload: { action: "mosaic", key: KEY_HEX, ask: ask(41) } }));
  const c8 = spawnSync(process.execPath, ["--import", pathToFileURL(acceptStub).href, join(REPO, "site", "worker.mjs")], { encoding: "utf8", env: { ...process.env, GITHUB_EVENT_PATH: evt, SITE_DIR: siteDir, PACKAGER_BIN: wrongPk, WORKER_ACTION: "mosaic", AXINOM_COM_KEY_ID: COM.id, AXINOM_COM_KEY: COM.key.toString("base64") } });
  const c8Out = (c8.stdout || "") + (c8.stderr || "");
  assert.equal(c8.status, 1, c8Out); assert.match(c8Out, /^::error title=Packager::the packager at \S+ is not the pinned shaka-packager v3\.9\.3/m);
  await assert.rejects(fs.access(ranMark), "the other file was never run");
  const after8 = await mosaicMeta();
  assert.deepEqual([after8.builtAt, after8.ids, after8.fairplay, after8.skipped, after8.answered], [before8.builtAt, before8.ids, null, [], before8.answered], "the view stays, its record cleaned, no request answered");
  notice("FairPlay eleventh review", "request ids on every answer (last ten); a failed same-pictures rebuild kept the view whole; render / check / missing-program failures kept the view; a missing output rebuilt; an expired form renewed while Axinom was out of reach and rebuilt while it refused; a failed copy left nothing");
});

// The job's last lines (site/worker.mjs, resultLines): a warning on the run's page whenever the combined view or a
// picture ends without the Apple form it should have; none for a view kept as it is (said in the result line and on the page)
test("the job's last lines: a warning whenever the combined view or a picture ends without its Apple form; none for a view kept as it is", () => {
  assert.deepEqual(resultLines({ status: "current", count: 2, fairplay: "failed" }, { com: COM, action: "mosaic" }), ["result: current (2 picture(s)); Apple form: failed", "::warning title=Apple form::the combined view's new Apple form could not be made; its current one is kept (see the log above)"]);
  assert.deepEqual(resultLines({ status: "current", count: 2, fairplay: "kept" }, { com: COM, action: "mosaic" }), ["result: current (2 picture(s)); Apple form: kept"], "kept as it is: said, not warned");
  assert.deepEqual(resultLines({ status: "ready", count: 3, skipped: 0, fairplay: false }, { com: COM, action: "mosaic" }), ["result: ready (3 picture(s)); Apple form: false", "::warning title=Apple form::the combined view was made without its Apple form (see the log above); Apple devices are held back until it has one"]);
  assert.deepEqual(resultLines({ status: "ready", error: null, fairplay: false }, { com: COM, action: "add" }), ["result: ready; Apple form: false", "::warning title=Apple form::the picture was made without its Apple form (see the log above); Apple devices are held back until it has one"]);
  for (const [r, o] of [[{ status: "ready", count: 3, fairplay: false }, { com: null, action: "mosaic" }], [{ status: "ready", count: 3, fairplay: true }, { com: COM, action: "mosaic" }], [{ status: "current", count: 3 }, { com: COM, action: "mosaic" }], [{ status: "current", count: 3, fairplay: "renewed" }, { com: COM, action: "mosaic" }], [{ status: "deleted" }, { com: COM, action: "delete" }], [{ status: "failed", error: "x" }, { com: COM, action: "add" }]])
    assert.ok(!resultLines(r, o).some((l) => /^::warning/.test(l)), JSON.stringify(r));
});

// THE RUN-TIME CHECK (the eleventh review's answer to a text guard stepped around five times): every program of ours that
// runs the packager on a picture or the card asks checkPackager first, by the file's SHA-256, however the file got
// there. One pin everywhere: the module, the guard, every download's check line.
test("only the pinned shaka-packager runs: checked by its SHA-256 each time; another file, or none, refused and named before anything is touched", async () => {
  const guard = await fs.readFile(join(REPO, "tools", "check-workflow-links.mjs"), "utf8");
  assert.equal(guard.match(/const PACKAGER_SHA256 = "([0-9a-f]{64})"/)[1], PACKAGER_SHA256, "the guard pins the same build");
  const wf = join(REPO, ".github", "workflows"); let lines = 0;
  for (const f of [...(await fs.readdir(wf)).map((x) => join(wf, x)), join(REPO, "service", "Dockerfile")])
    for (const m of (await fs.readFile(f, "utf8")).matchAll(/echo "([0-9a-f]{64})  [^"]*packager" \| sha256sum -c -/g)) { assert.equal(m[1], PACKAGER_SHA256, f); lines++; }
  assert.equal(lines, 9, "every check line names the same build, one after each of the 9 downloads (the runner and the tests check the file again where they run it: the next test)");
  const wrong = join(tmp, "not-the-packager"); await fs.writeFile(wrong, "#!/bin/sh\necho 'packager version v3.9.3'\n"); await fs.chmod(wrong, 0o755);
  const REFUSED = /is not the pinned shaka-packager v3\.9\.3 \(sha256 [0-9a-f]{16}…, pinned 7a3cf35ad146fd78…\): refused/;
  await assert.rejects(checkPackager(wrong), REFUSED);
  await assert.rejects(checkPackager("/nonexistent/packager"), /the packager "\/nonexistent\/packager" was not found/);
  // a bare name is looked up on the PATH, as the shell would run it
  const onPath = await fs.mkdtemp(join(tmp, "path-")); await fs.copyFile(wrong, join(onPath, "packager")); await fs.chmod(join(onPath, "packager"), 0o755);
  const savedPath = process.env.PATH; process.env.PATH = onPath + delimiter + savedPath;
  try { await assert.rejects(checkPackager("packager"), (e) => e.message.includes(`the packager at ${join(onPath, "packager")} is not the pinned`)); } finally { process.env.PATH = savedPath; }
  // ... as the shell looks it up: in PATH order, the first executable FILE (a file that cannot run, or a folder, is passed
  // over), an empty entry meaning the current folder, a relative entry read from it; the path found is absolute
  const pd = async (name, mode, text) => { const d = await fs.mkdtemp(join(tmp, name)); if (mode === "dir") await fs.mkdir(join(d, "packager")); else { await fs.writeFile(join(d, "packager"), text); await fs.chmod(join(d, "packager"), mode); } return d; };
  const noExec = await pd("p-noexec-", 0o644, "#!/bin/sh\necho A\n"), folder = await pd("p-dir-", "dir"), first = await pd("p-first-", 0o755, "#!/bin/sh\necho C\n"), later = await pd("p-later-", 0o755, "#!/bin/sh\necho D\n");
  const relBase = await fs.mkdtemp(join(tmp, "p-rel-")); await fs.mkdir(join(relBase, "rel")); await fs.writeFile(join(relBase, "rel", "packager"), "#!/bin/sh\necho R\n"); await fs.chmod(join(relBase, "rel", "packager"), 0o755);
  const named = async (PATH, cwd) => { const p = process.env.PATH, c = process.cwd(); process.env.PATH = PATH; if (cwd) process.chdir(cwd);
    try { return await checkPackager("packager").then(() => "accepted", (e) => e.message); } finally { process.env.PATH = p; process.chdir(c); } };
  const at = (file) => (m) => m.startsWith(`the packager at ${file} is not the pinned`);
  assert.ok(at(join(first, "packager"))(await named([noExec, folder, first, later].join(delimiter))), "the first executable file on the PATH, not one that cannot run, a folder, or a later one");
  assert.ok(at(join(first, "packager"))(await named(["", later].join(delimiter), first)), "an empty entry is the current folder");
  assert.ok(at(join(relBase, "rel", "packager"))(await named(["rel", later].join(delimiter), relBase)), "a relative entry is read from the current folder, and named absolute");
  // asked every time, never remembered: the real build passes, and the same path changed afterwards is refused
  let real = null; try { await exec(tools.packager, ["--version"]); real = tools.packager; } catch {}
  if (real) {
    const copy = join(tmp, "packager-copy"); await fs.copyFile(await checkPackager(real), copy); await fs.chmod(copy, 0o755);
    assert.equal(await checkPackager(copy), copy);
    await fs.appendFile(copy, "x");
    await assert.rejects(checkPackager(copy), REFUSED);
  } else if (process.env.REQUIRE_PACKAGER === "1") assert.fail("shaka-packager is required here");
  // each program, run as its job runs it, refuses another file (or none) before it touches anything
  const PW = "a test password, twelve+", SALT = toBase64(new Uint8Array(16).fill(13));
  const photoKey = await derivePhotoKey(await deriveKey(PW, SALT, 1000)), keyHex = await exportKeyHex(photoKey);
  const site = await fs.mkdtemp(join(tmp, "pin-")), P = "7".repeat(24);
  await fs.writeFile(join(site, "config.json"), JSON.stringify({ salt: SALT, iterations: 1000 }));
  await fs.writeFile(join(site, "gallery.json.enc"), await sealText(photoKey, JSON.stringify({ photos: [{ id: P, name: "p.png", status: "ready", prKidGuid: "00000000-0000-0000-0000-000000000001", fairplay: false }] })));
  await fs.mkdir(join(site, "photos", P), { recursive: true });
  await fs.writeFile(join(site, "photos", P, "meta.json.enc"), await sealText(photoKey, JSON.stringify({ id: P, fairplay: null })));
  const snapshot = async (d) => { const out = {}; const walk = async (x) => { for (const e of await fs.readdir(x, { withFileTypes: true })) { const p = join(x, e.name); if (e.isDirectory()) await walk(p); else out[p.slice(d.length)] = createHash("sha256").update(await fs.readFile(p)).digest("hex"); } }; await walk(d); return out; };
  const before = await snapshot(site), evt = join(tmp, "pin-event.json"), refuseStub = join(tmp, "stub-pin-refuse.mjs");
  await fs.writeFile(refuseStub, `globalThis.fetch = async () => new Response(null, { status: 400, headers: { "X-AxDRM-ErrorMessage": "Invalid DRM message. The signature is invalid." } });\n`);
  const go = (args, env) => { const r = spawnSync(process.execPath, args, { encoding: "utf8", env: { ...process.env, AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "", WORKER_ACTION: "", ...env } }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; };
  for (const [bin, re] of [[wrong, REFUSED], ["/nonexistent/packager", /the packager "\/nonexistent\/packager" was not found/]]) {
    for (const [action, env] of [["add", {}], ["mosaic", {}], ["delete", { WORKER_ACTION: "mosaic" }]]) {
      await fs.writeFile(evt, JSON.stringify({ client_payload: { action, id: P, key: keyHex, blobSha: "a".repeat(40), name: "p.png" } }));
      const r = go([join(REPO, "site", "worker.mjs")], { GITHUB_EVENT_PATH: evt, SITE_DIR: site, PACKAGER_BIN: bin, ...env });
      assert.equal(r.code, 1, r.out); assert.match(r.out, /::error title=Packager::/); assert.match(r.out, re); assert.ok(!/^result:/m.test(r.out), "nothing was run");
    }
    const b = go(["--import", pathToFileURL(refuseStub).href, join(REPO, "site", "backfill.mjs")], { SITE_DIR: site, SITE_PASSWORD: PW, AXINOM_COM_KEY_ID: COM.id, AXINOM_COM_KEY: COM.key.toString("base64"), PACKAGER_BIN: bin, GITHUB_EVENT_NAME: "workflow_dispatch", BACKFILL_RESULT: "" });
    assert.equal(b.code, 1, b.out); assert.match(b.out, /::error title=Apple backfill::/); assert.match(b.out, re);
    const out = await fs.mkdtemp(join(tmp, "pin-card-"));
    const c = go([join(REPO, "tools", "fairplay-card.mjs"), "--out", out, "--own", join(out, "own")], { PACKAGER_BIN: bin });
    assert.equal(c.code, 1, c.out); assert.match(c.out, /::error title=Packager::/); assert.match(c.out, re);
    assert.deepEqual(await fs.readdir(out), [], "the card job wrote nothing");
  }
  assert.deepEqual(await snapshot(site), before, "nothing on the site was touched");
  // a deletion runs no packager and is never held up by one
  await fs.writeFile(evt, JSON.stringify({ client_payload: { action: "delete", id: P, key: keyHex } }));
  const d = go([join(REPO, "site", "worker.mjs")], { GITHUB_EVENT_PATH: evt, SITE_DIR: site, PACKAGER_BIN: wrong });
  assert.equal(d.code, 0, d.out); assert.match(d.out, /^result: deleted$/m); await assert.rejects(fs.access(join(site, "photos", P)));
  // a program given a RELATIVE path runs the very file it checked, though its packaging runs in another folder (the
  // twelfth review: the check read one file and the run, from the work folder, looked for another)
  if (real) {
    const base = await fs.mkdtemp(join(tmp, "rel-run-")), relSite = await fs.mkdtemp(join(tmp, "rel-site-")), blob = join(tmp, "rel-blob");
    await fs.mkdir(join(base, "bin")); await fs.copyFile(await checkPackager(real), join(base, "bin", "packager")); await fs.chmod(join(base, "bin", "packager"), 0o755);
    await fs.writeFile(blob, await seal(photoKey, await fs.readFile(await solid("rel.png", 320, 240, "0x2980b9"))));
    await fs.writeFile(evt, JSON.stringify({ client_payload: { action: "add", id: "8".repeat(24), name: "rel.png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: keyHex } }));
    const rr = spawnSync(process.execPath, [join(REPO, "site", "worker.mjs")], { cwd: base, encoding: "utf8", env: { ...process.env, AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "", WORKER_ACTION: "", GITHUB_EVENT_PATH: evt, SITE_DIR: relSite, PACKAGER_BIN: "bin/packager", WORKER_BLOB_FILE: blob } });
    const ro = (rr.stdout || "") + (rr.stderr || "");
    assert.equal(rr.status, 0, ro); assert.match(ro, /^result: ready$/m, "the picture was packaged by the file checked: " + ro.slice(-400));
    // an error inside the job is named on the run's page, and the job ends red
    await fs.writeFile(evt, JSON.stringify({ client_payload: { action: "mosaic", key: keyHex, ask: "XYZ" } }));
    const re = spawnSync(process.execPath, [join(REPO, "site", "worker.mjs")], { encoding: "utf8", env: { ...process.env, AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "", WORKER_ACTION: "", GITHUB_EVENT_PATH: evt, SITE_DIR: relSite, PACKAGER_BIN: real } });
    assert.equal(re.status, 1, re.stdout + re.stderr); assert.match(re.stdout, /^::error title=Site job::bad request id$/m);
  }
  // the backfill, given the same RELATIVE path, makes that picture's Apple form (Axinom stood in for, accepting the key): it
  // runs the very file it checked though it packages in another folder (the twelfth round read only its source line)
  if (real) {
    const base = await fs.mkdtemp(join(tmp, "rel-bf-")), relSite = await fs.mkdtemp(join(tmp, "rel-bf-site-")), blob = join(tmp, "rel-bf-blob"), Q = "6".repeat(24);
    await fs.mkdir(join(base, "bin")); await fs.copyFile(await checkPackager(real), join(base, "bin", "packager")); await fs.chmod(join(base, "bin", "packager"), 0o755);
    await fs.writeFile(join(relSite, "config.json"), JSON.stringify({ salt: SALT, iterations: 1000 }));
    await fs.writeFile(blob, await seal(photoKey, await fs.readFile(await solid("rel-bf.png", 320, 240, "0x27ae60"))));
    await fs.writeFile(evt, JSON.stringify({ client_payload: { action: "add", id: Q, name: "q.png", type: "image/png", bytes: 1, blobSha: "a".repeat(40), key: keyHex } }));
    const added = spawnSync(process.execPath, [join(REPO, "site", "worker.mjs")], { cwd: base, encoding: "utf8", env: { ...process.env, AXINOM_COM_KEY_ID: "", AXINOM_COM_KEY: "", WORKER_ACTION: "", GITHUB_EVENT_PATH: evt, SITE_DIR: relSite, PACKAGER_BIN: "bin/packager", WORKER_BLOB_FILE: blob } });
    assert.equal(added.status, 0, (added.stdout || "") + (added.stderr || ""));
    const acceptStub = join(tmp, "stub-pin-accept.mjs");
    await fs.writeFile(acceptStub, `globalThis.fetch = async () => new Response(null, { status: 400, headers: { "X-AxDRM-ErrorMessage": "Invalid license request. Supported versions are 1, 2 or 3, but used version is 0." } });\n`);
    const bf = spawnSync(process.execPath, ["--import", pathToFileURL(acceptStub).href, join(REPO, "site", "backfill.mjs")], { cwd: base, encoding: "utf8", env: { ...process.env, SITE_DIR: relSite, SITE_PASSWORD: PW, AXINOM_COM_KEY_ID: COM.id, AXINOM_COM_KEY: COM.key.toString("base64"), PACKAGER_BIN: "bin/packager", GITHUB_EVENT_NAME: "workflow_dispatch", BACKFILL_RESULT: join(base, "result.json") } });
    const bo = (bf.stdout || "") + (bf.stderr || "");
    assert.equal(bf.status, 0, bo.slice(-800));
    assert.equal(JSON.parse(await fs.readFile(join(base, "result.json"), "utf8")).added, 1, bo.slice(-800));
    assert.ok((await fs.readdir(join(relSite, "photos", Q))).some((f) => /^fp-/.test(f)), "the picture has its Apple form, packaged by the file checked");
  }
});

// THE RUNS OUTSIDE OUR PROGRAMS (the thirteenth review): a workflow runs the packager through tools/run-packager.mjs
// (tools/check-workflow-links.mjs refuses the ordinary other ways), and the tests run only the file they checked as they start.
// Both check the file by its SHA-256 at that moment and never run another.
test("the workflows' runner and the tests check the packager before they run it, and run only the file checked (needs shaka-packager)", async (t) => {
  if (!(await havePackager(t))) return;
  const RUNNER = join(REPO, "tools", "run-packager.mjs"), marker = join(tmp, "wrong-ran"), wrong = join(tmp, "wrong-packager");
  await fs.writeFile(wrong, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\necho 'packager version v3.9.3'\n`); await fs.chmod(wrong, 0o755);
  const go = (args, opts = {}) => { const r = spawnSync(process.execPath, [RUNNER, ...args], { encoding: "utf8", ...opts }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; };
  // another file: refused and named, never run; none there, or none given: refused
  let r = go([wrong, "--version"]);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /^::error title=Packager::the packager at \S+ is not the pinned shaka-packager v3\.9\.3/m);
  r = go(["/nonexistent/packager", "--version"]); assert.equal(r.code, 1, r.out); assert.match(r.out, /^::error title=Packager::the packager "\/nonexistent\/packager" was not found$/m);
  r = go([]); assert.equal(r.code, 2, r.out); assert.match(r.out, /^::error title=Packager::usage/m);
  // the pinned file, given by a RELATIVE path from another folder: run with the arguments as given, its exit code passed on
  const base = await fs.mkdtemp(join(tmp, "runner-")); await fs.mkdir(join(base, "bin")); await fs.copyFile(tools.packager, join(base, "bin", "packager")); await fs.chmod(join(base, "bin", "packager"), 0o755);
  r = go(["bin/packager", "--version"], { cwd: base });
  assert.equal(r.code, 0, r.out); assert.match(r.out, /packager version v3\.9\.3/);
  const own = spawnSync(tools.packager, ["--no-such-flag"], { encoding: "utf8" });
  r = go(["bin/packager", "--no-such-flag"], { cwd: base });
  assert.ok(own.status > 0 && r.code === own.status, `the packager's own exit code (${own.status}) passed on: ${r.code}`);
  // each test file that runs the packager checks it as it starts: given another file it ends the run before any test
  // (REQUIRE_PACKAGER=1, as CI runs them), and that file is never run
  const env = { ...process.env, PACKAGER_BIN: wrong, REQUIRE_PACKAGER: "1" }; delete env.NODE_TEST_CONTEXT;
  for (const [cwd, file] of [[REPO, "site/test/site.test.mjs"], [REPO, "site/test/fairplay.test.mjs"], [join(REPO, "service"), "test/pipeline.test.mjs"]]) {
    const x = spawnSync(process.execPath, ["--test", "--test-name-pattern", "^no test has this name$", file], { cwd, encoding: "utf8", env });
    const out = (x.stdout || "") + (x.stderr || "");
    assert.notEqual(x.status, 0, `${file} refuses another packager: ${out.slice(-400)}`); assert.match(out, /is not the pinned shaka-packager v3\.9\.3/, file);
  }
  await assert.rejects(fs.access(marker), "the other file was never run");
  // ... and every file under site/test and service/test, of any kind, subfolders included, whose text holds the name
  // PACKAGER_BIN is listed, with what it does with it and a fingerprint of EVERY LINE that holds the name: a new file
  // that names it, or any line naming it added, removed or changed in a listed file, fails here until the list is
  // brought up to date, and so is read again (the fourteenth review: the CI steps' own check lines, which held any such
  // file, are gone; the fifteenth: only one way of reading it was looked for; the sixteenth: a list of names let a listed
  // file gain an unchecked reader; the seventeenth: a count of uses let one be swapped for another; the eighteenth: a
  // .mts helper or a shell script was not read). It reads the name as written: one built from parts
  // (process.env["PACKAGER" + "_BIN"]) is not seen, and is for review; so is a file outside these two folders.
  const NAMES = {
    "site/test/site.test.mjs": ["63f1cff7064ce706", "checks it as it loads (above)"],
    "site/test/fairplay.test.mjs": ["100261b61e7b4b0f", "checks it as it loads (above); sets it for the programs it runs, which check it"],
    "service/test/pipeline.test.mjs": ["63f1cff7064ce706", "checks it as it loads (above)"],
    "service/test/helpers.mjs": ["d9df89b37273dec5", "checks it, and hands the app only the checked path (or a name that runs nothing)"],
    "site/test/jobs.test.mjs": ["1aff2a2b273ca84c", "sets it for the real worker, which checks it"],
    "site/test/pages.test.mjs": ["7d87c1b3516e031e", "workflow text for the guard; runs nothing"],
  };
  const named = {};
  for (const dir of ["site/test", "service/test"])
    for (const f of await fs.readdir(join(REPO, dir), { recursive: true })) {
      if (f.split(/[\\/]/).includes("node_modules") || !(await fs.stat(join(REPO, dir, f))).isFile()) continue;
      const lines = (await fs.readFile(join(REPO, dir, f), "utf8")).split("\n").filter((l) => l.includes("PACKAGER_BIN")).map((l) => l.trim());
      if (lines.length) named[`${dir}/${f.split("\\").join("/")}`] = { print: createHash("sha256").update(lines.join("\n")).digest("hex").slice(0, 16), lines };
    }
  assert.deepEqual(Object.fromEntries(Object.entries(named).map(([f, v]) => [f, v.print])), Object.fromEntries(Object.entries(NAMES).map(([f, [print]]) => [f, print])),
    "every test file that names PACKAGER_BIN is listed with the fingerprint of the lines that name it; read them, then update the list:\n" + Object.entries(named).map(([f, v]) => `${f} ${v.print}:\n  ${v.lines.join("\n  ")}`).join("\n"));
});

after(async () => { await fs.rm(tmp, { recursive: true, force: true }); });
