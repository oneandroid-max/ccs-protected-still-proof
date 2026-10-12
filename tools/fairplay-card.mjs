// Route 1's TEST CARD in Apple's FairPlay form, packaged by the SAME code that packages the owner's
// pictures (service/lib/pipeline.mjs: packageFairPlay, then checkFairPlay), but under Axinom's PUBLIC test
// key (site/axinom.mjs, AXINOM_PUBLIC_TEST), which Axinom's public licence token unlocks on any Apple
// device. So a screenshot on a real iPhone, iPad or Mac can prove our packaging plays through Axinom's
// licence service, and whether it comes out black, before any account exists. The card is public by
// design: anyone can decrypt it with the published key, which is why no picture of the owner's ever
// goes through this file.
// The clear card is the committed PlayReady card decrypted with its own public test key (the same frames
// as the card's other forms). The FairPlay form is then decrypted again two independent ways (ffmpeg and
// shaka-packager), and both must give back exactly the clear card's first frame; undecrypted, it must not.
// THE OWN-ACCOUNT FORM: with the Axinom evaluation key in the environment (AXINOM_COM_KEY_ID,
// AXINOM_COM_KEY), the card is also packaged exactly as a picture is (a fresh random key) with a licence
// token minted by OUR account, in card-fairplay-own/ (the token in clear, token.txt: it unlocks only this
// public card). So a real Apple device can prove the account's own tokens before any picture is shown
// there. It is remade only when missing, made with another key, or within 14 days of its token's end,
// each time into a freshly named folder (card-fairplay-own/<8 hex>/), with current.json naming it, so a
// browser's cached copy can never pair an older video with a newer token (Pages caches ten minutes).
//   node tools/fairplay-card.mjs                 writes web/research/drm/card-fairplay/ (and -own/)
//   node tools/fairplay-card.mjs --out <dir>     writes the public form there instead (tests)
//   ... --own <dir>                              with the Axinom key set, the own-account form there (tests)
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { packageFairPlay, checkFairPlay, verifyFairPlayBytes, checkBoxes, probe } from "../service/lib/pipeline.mjs";
import { run } from "../service/lib/util.mjs";
import { AXINOM_PUBLIC_TEST, AXINOM_FAIRPLAY_LICENSE, kidToUuid, newFairPlayIds, mintToken, readCommunicationKey, readAxinomSettings, checkTokenWithAxinom, tokenSignedWith } from "../site/axinom.mjs";
import { derivePlayReadyTestKey } from "./playready-test-key.mjs";
import { checkPackager } from "../service/lib/packager-pin.mjs";

const REPO = fileURLToPath(new URL("../", import.meta.url));
export const CARD_KID = "5cfcb567f2f19d08a30b20483d92e930"; // the card's own key id (drm-card.yml, CARD_KID)
// a fixed IV, so the card's key address stays the same from one packaging to the next
export const CARD_FP_IV = createHash("sha256").update("ccs-proof fairplay test card").digest("hex").slice(0, 32);
export const cardFairPlayIds = () => ({ kid: AXINOM_PUBLIC_TEST.kid, key: AXINOM_PUBLIC_TEST.key, iv: CARD_FP_IV, keyUri: `skd://${kidToUuid(AXINOM_PUBLIC_TEST.kid)}:${CARD_FP_IV.toUpperCase()}` });
const FILES = ["master.m3u8", "video.m3u8", "video.mp4"];

// The first frame of a video as raw RGB bytes; ffmpeg stops at the first decoding error.
async function firstFrame(tools, file, extra = []) {
  const raw = file + ".rgb";
  try {
    await run(tools.ffmpeg, ["-hide_banner", "-loglevel", "error", "-xerror", "-y", ...extra, "-i", file, "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", raw]);
    return await fs.readFile(raw);
  } finally { await fs.rm(raw, { force: true }); }
}
// The largest difference between two frames, channel by channel (0 = identical; Infinity = other sizes).
export const largestDifference = (a, b) => { if (a.length !== b.length) return Infinity; let m = 0; for (let i = 0; i < a.length; i++) { const d = Math.abs(a[i] - b[i]); if (d > m) m = d; } return m; };

export async function buildFairPlayCard({ tools, outDir, cardFile = join(REPO, "web", "research", "drm", "card-playready.mp4"), com = null }) {
  const work = await fs.mkdtemp(join(tmpdir(), "fp-card-"));
  try {
    // 1. the clear card, from the PlayReady card and its own public test key (stream copied, not re-encoded)
    const kids = checkBoxes(await fs.readFile(cardFile)).kids;
    if (kids.length !== 1 || kids[0] !== CARD_KID) throw new Error(`the PlayReady card carries key id(s) ${kids.join(", ") || "none"}, not the card's own ${CARD_KID}`);
    await run(tools.ffmpeg, ["-hide_banner", "-loglevel", "error", "-xerror", "-y", "-decryption_key", derivePlayReadyTestKey(CARD_KID), "-i", cardFile, "-map", "0:v:0", "-c", "copy", "-movflags", "+faststart", join(work, "clip.mp4")]);
    const clear = await firstFrame(tools, join(work, "clip.mp4"));
    const size = await probe(tools.ffprobe, join(work, "clip.mp4"));
    // 2. Apple's form, by the code that packages the owner's pictures
    const ids = com ? newFairPlayIds() : cardFairPlayIds();
    await packageFairPlay(tools.packager, work, ids, { fixedClock: !com }); // the public form: the same bytes every time
    const data = await fs.readFile(join(work, "fp", "video.mp4"));
    const check = checkFairPlay(await fs.readFile(join(work, "fp", "video.m3u8"), "utf8"), data, ids);
    if (!check.ok) throw new Error("the card's FairPlay form failed its check: " + check.problems.join("; "));
    const bytes = await verifyFairPlayBytes(tools.packager, work, ids); // the same byte check a picture's form passes
    if (!bytes.ok) throw new Error("the card's FairPlay form failed its byte check: " + bytes.problems.join("; "));
    // 3. decrypted back two independent ways it must be exactly the clear card; undecrypted it must not
    const byFfmpeg = await firstFrame(tools, join(work, "fp", "video.mp4"), ["-decryption_key", ids.key]);
    await run(tools.packager, [`in=${join(work, "fp", "video.mp4")},stream=video,output=${join(work, "decrypted.mp4")}`, "--enable_raw_key_decryption", "--keys", `key_id=${ids.kid}:key=${ids.key}`]);
    const byPackager = await firstFrame(tools, join(work, "decrypted.mp4"));
    let undecrypted = "decoding refused";
    try { const f = await firstFrame(tools, join(work, "fp", "video.mp4")); undecrypted = !f.length ? "no frame decoded" : f.length === clear.length ? largestDifference(f, clear) : `a frame of another size (${f.length} bytes, the card's is ${clear.length})`; } catch {}
    const decryptCheck = { ffmpeg: largestDifference(byFfmpeg, clear), shakaPackager: largestDifference(byPackager, clear), undecrypted };
    if (decryptCheck.ffmpeg !== 0 || decryptCheck.shakaPackager !== 0) throw new Error(`decrypted, the FairPlay form is not the clear card (largest difference: ffmpeg ${decryptCheck.ffmpeg}, shaka-packager ${decryptCheck.shakaPackager})`);
    if (typeof undecrypted === "number" && undecrypted < 40) throw new Error(`undecrypted, the FairPlay form still shows the card (largest difference ${undecrypted}): its samples are not encrypted`);
    // 4. written out, with what it is
    const { stdout } = await run(tools.packager, ["--version"]);
    await fs.rm(outDir, { recursive: true, force: true });
    await fs.mkdir(outDir, { recursive: true });
    for (const f of FILES) await fs.copyFile(join(work, "fp", f), join(outDir, f));
    let token = null, expires = null;
    if (com) {
      token = mintToken(com, ids.kid, ids.key);
      expires = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")).expiration_date;
      await fs.writeFile(join(outDir, "token.txt"), token + "\n");
    }
    const info = {
      content: "the route-1 test card (public by design; never a picture of the owner's)",
      key: com ? "a random key of its own, as a picture gets; the licence token (token.txt) is minted by our Axinom account and unlocks only this card"
        : "Axinom's PUBLIC test key (site/axinom.mjs, AXINOM_PUBLIC_TEST), unlocked by Axinom's public licence token",
      kid: kidToUuid(ids.kid), iv: ids.iv, keyUri: ids.keyUri, scheme: check.scheme, samples: check.samples, samplesEncrypted: check.samplesEncrypted,
      width: size.width, height: size.height, bytes: data.length, decryptCheck, packager: stdout.trim(),
      ...(com ? { comKeyId: com.id, expires, license: com.license || AXINOM_FAIRPLAY_LICENSE } : {}),
    };
    await fs.writeFile(join(outDir, "info.json"), JSON.stringify(info, null, 2) + "\n");
    return { ...info, byteCheck: { encryptedBlocks: bytes.encryptedBlocks, blocksLeftClear: bytes.blocksLeftClear, clearBytesChanged: bytes.clearBytesChanged, decryptedWrong: bytes.decryptedWrong } }; // printed, not written (the public card's files stay as they were)
  } finally {
    await fs.rm(work, { recursive: true, force: true });
  }
}

// The own-account form, in `root` (card-fairplay-own/): a fresh folder each time, current.json naming it,
// older folders removed once current.json points to the new one.
export async function buildOwnCard({ tools, root, com }) {
  const folder = randomBytes(4).toString("hex");
  const info = await buildFairPlayCard({ tools, outDir: join(root, folder), com });
  await fs.writeFile(join(root, "current.json"), JSON.stringify({ folder, keyUri: info.keyUri, comKeyId: info.comKeyId, expires: info.expires, license: info.license }, null, 2) + "\n");
  for (const d of await fs.readdir(root)) if (/^[0-9a-f]{8}$/.test(d) && d !== folder) await fs.rm(join(root, d), { recursive: true, force: true });
  return { folder, ...info };
}
// Whether the own-account form in `root` is still good for this key (same account and licence address, its
// token signed with this key's value, so a corrected value remakes it, 14+ days left).
export async function ownCardCurrent(root, com, now = Date.now()) {
  try {
    const cur = JSON.parse(await fs.readFile(join(root, "current.json"), "utf8"));
    if (!/^[0-9a-f]{8}$/.test(String(cur.folder))) return false;
    for (const f of [...FILES, "token.txt", "info.json"]) await fs.access(join(root, cur.folder, f));
    if (!tokenSignedWith((await fs.readFile(join(root, cur.folder, "token.txt"), "utf8")).trim(), com.key)) return false;
    return String(cur.comKeyId || "").toLowerCase() === com.id.toLowerCase() && (cur.license || AXINOM_FAIRPLAY_LICENSE) === (com.license || AXINOM_FAIRPLAY_LICENSE) && Date.parse(cur.expires) > now + 14 * 86400000;
  } catch { return false; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const at = process.argv.indexOf("--out");
  const outDir = at > 0 ? process.argv[at + 1] : join(REPO, "web", "research", "drm", "card-fairplay");
  const tools = { ffmpeg: process.env.FFMPEG_BIN || "ffmpeg", ffprobe: process.env.FFPROBE_BIN || "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
  // only the pinned build packages the card: any other file ends the job red, named on the run's page, before anything is written
  try { tools.packager = await checkPackager(tools.packager); } catch (e) { console.log(`::error title=Packager::${e.message}`); process.exit(1); }
  console.log(JSON.stringify(await buildFairPlayCard({ tools, outDir }), null, 2));
  const ownAt = process.argv.indexOf("--own");
  if (at < 0 || ownAt > 0) {
    const ownDir = ownAt > 0 ? process.argv[ownAt + 1] : join(REPO, "web", "research", "drm", "card-fairplay-own");
    if (!process.env.AXINOM_COM_KEY_ID && !process.env.AXINOM_COM_KEY) console.log("the Axinom key is not set: no own-account form of the card");
    else {
      const com = readCommunicationKey(process.env.AXINOM_COM_KEY_ID, process.env.AXINOM_COM_KEY, (await readAxinomSettings(join(REPO, "site"))).fairplayLicense); // fails plainly when malformed
      if (await ownCardCurrent(ownDir, com)) console.log("the own-account form of the card is current: unchanged");
      else { await fs.mkdir(ownDir, { recursive: true }); console.log(JSON.stringify(await buildOwnCard({ tools, root: ownDir, com }), null, 2)); }
      // Axinom asked, from here, whether it accepts the card's token: the key id and the key value as a pair (not
      // the address: any prefix answers alike). A refusal, or Axinom out of reach after its retries, stops the job
      // (red, nothing committed) with Axinom's own words; the key is never printed.
      const cur = JSON.parse(await fs.readFile(join(ownDir, "current.json"), "utf8"));
      const answer = await checkTokenWithAxinom((await fs.readFile(join(ownDir, cur.folder, "token.txt"), "utf8")).trim(), com.license);
      if (!answer.reached) { console.log(`Axinom could not be asked about the own card's token (key id ${com.id}): ${answer.message}`); process.exitCode = 1; }
      else if (!answer.accepted) { console.log(`Axinom REFUSED the own card's token (key id ${com.id}): ${answer.message}`); process.exitCode = 1; }
      else console.log(`Axinom accepts the own card's token: key id ${com.id} and its key value are a pair it knows (its answer to a dummy request: "${answer.message}"). That proves the key pair only; a device proves the rest.`);
    }
  }
}
