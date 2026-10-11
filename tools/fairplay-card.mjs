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
//   node tools/fairplay-card.mjs                 writes web/research/drm/card-fairplay/
//   node tools/fairplay-card.mjs --out <dir>     writes there instead
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { packageFairPlay, checkFairPlay, checkBoxes, probe } from "../service/lib/pipeline.mjs";
import { run } from "../service/lib/util.mjs";
import { AXINOM_PUBLIC_TEST, kidToUuid } from "../site/axinom.mjs";
import { derivePlayReadyTestKey } from "./playready-test-key.mjs";

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

export async function buildFairPlayCard({ tools, outDir, cardFile = join(REPO, "web", "research", "drm", "card-playready.mp4") }) {
  const work = await fs.mkdtemp(join(tmpdir(), "fp-card-"));
  try {
    // 1. the clear card, from the PlayReady card and its own public test key (stream copied, not re-encoded)
    const kids = checkBoxes(await fs.readFile(cardFile)).kids;
    if (kids.length !== 1 || kids[0] !== CARD_KID) throw new Error(`the PlayReady card carries key id(s) ${kids.join(", ") || "none"}, not the card's own ${CARD_KID}`);
    await run(tools.ffmpeg, ["-hide_banner", "-loglevel", "error", "-xerror", "-y", "-decryption_key", derivePlayReadyTestKey(CARD_KID), "-i", cardFile, "-map", "0:v:0", "-c", "copy", "-movflags", "+faststart", join(work, "clip.mp4")]);
    const clear = await firstFrame(tools, join(work, "clip.mp4"));
    const size = await probe(tools.ffprobe, join(work, "clip.mp4"));
    // 2. Apple's form, by the code that packages the owner's pictures
    const ids = cardFairPlayIds();
    await packageFairPlay(tools.packager, work, ids);
    const data = await fs.readFile(join(work, "fp", "video.mp4"));
    const check = checkFairPlay(await fs.readFile(join(work, "fp", "video.m3u8"), "utf8"), data, ids);
    if (!check.ok) throw new Error("the card's FairPlay form failed its check: " + check.problems.join("; "));
    // 3. decrypted back two independent ways it must be exactly the clear card; undecrypted it must not
    const byFfmpeg = await firstFrame(tools, join(work, "fp", "video.mp4"), ["-decryption_key", ids.key]);
    await run(tools.packager, [`in=${join(work, "fp", "video.mp4")},stream=video,output=${join(work, "decrypted.mp4")}`, "--enable_raw_key_decryption", "--keys", `key_id=${ids.kid}:key=${ids.key}`]);
    const byPackager = await firstFrame(tools, join(work, "decrypted.mp4"));
    let undecrypted = "decoding refused";
    try { const f = await firstFrame(tools, join(work, "fp", "video.mp4")); undecrypted = f.length === clear.length ? largestDifference(f, clear) : `a frame of another size (${f.length} bytes, the card's is ${clear.length})`; } catch {}
    const decryptCheck = { ffmpeg: largestDifference(byFfmpeg, clear), shakaPackager: largestDifference(byPackager, clear), undecrypted };
    if (decryptCheck.ffmpeg !== 0 || decryptCheck.shakaPackager !== 0) throw new Error(`decrypted, the FairPlay form is not the clear card (largest difference: ffmpeg ${decryptCheck.ffmpeg}, shaka-packager ${decryptCheck.shakaPackager})`);
    if (typeof undecrypted === "number" && undecrypted < 40) throw new Error(`undecrypted, the FairPlay form still shows the card (largest difference ${undecrypted}): its samples are not encrypted`);
    // 4. written out, with what it is
    const { stdout } = await run(tools.packager, ["--version"]);
    await fs.rm(outDir, { recursive: true, force: true });
    await fs.mkdir(outDir, { recursive: true });
    for (const f of FILES) await fs.copyFile(join(work, "fp", f), join(outDir, f));
    const info = {
      content: "the route-1 test card (public by design; never a picture of the owner's)",
      key: "Axinom's PUBLIC test key (site/axinom.mjs, AXINOM_PUBLIC_TEST), unlocked by Axinom's public licence token",
      kid: kidToUuid(ids.kid), iv: ids.iv, keyUri: ids.keyUri, scheme: check.scheme,
      width: size.width, height: size.height, bytes: data.length, decryptCheck, packager: stdout.trim(),
    };
    await fs.writeFile(join(outDir, "info.json"), JSON.stringify(info, null, 2) + "\n");
    return info;
  } finally {
    await fs.rm(work, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const at = process.argv.indexOf("--out");
  const outDir = at > 0 ? process.argv[at + 1] : join(REPO, "web", "research", "drm", "card-fairplay");
  const tools = { ffmpeg: process.env.FFMPEG_BIN || "ffmpeg", ffprobe: process.env.FFPROBE_BIN || "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
  console.log(JSON.stringify(await buildFairPlayCard({ tools, outDir }), null, 2));
}
