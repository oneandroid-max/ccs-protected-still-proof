// The Apple backfill's entry (site-fairplay.yml: by hand, and weekly so licence tokens are renewed before
// they run out). Derives the picture key from the site password exactly as the page does (site/config.json's
// salt and rounds, then the one-way picture key), masks it in the run's log before anything else is
// printed, and runs the worker's "fairplay" action: Apple's form for every ready picture that lacks a good
// one, then the combined view. Writes the counts to BACKFILL_RESULT (a file), so the workflow can commit
// what succeeded and still fail visibly when a picture did not. SITE_DIR names another site folder (tests).
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveKey, derivePhotoKey, exportKeyHex, open } from "./crypto.js";
import { run } from "./worker.mjs";
import { readCommunicationKey, readAxinomSettings } from "./axinom.mjs";

// a missing or malformed secret, or a password that opens nothing, is named on the run's page (an error
// annotation), not only in its log; a weekly run without the Axinom key set simply has nothing to do
const stop = (why) => { console.log(`::error title=Apple backfill::${why}`); process.exit(1); };
const siteDir = process.env.SITE_DIR || fileURLToPath(new URL("./", import.meta.url));
if (!process.env.SITE_PASSWORD) stop("SITE_PASSWORD is not set");
if (process.env.GITHUB_EVENT_NAME === "schedule" && !process.env.AXINOM_COM_KEY_ID && !process.env.AXINOM_COM_KEY) {
  console.log("::notice title=Apple backfill::the Axinom key is not set yet: nothing to renew");
  if (process.env.BACKFILL_RESULT) await fs.writeFile(process.env.BACKFILL_RESULT, JSON.stringify({ status: "skipped", added: 0, already: 0, failed: 0 }));
  process.exit(0);
}
let com;
try { com = readCommunicationKey(process.env.AXINOM_COM_KEY_ID, process.env.AXINOM_COM_KEY, (await readAxinomSettings(siteDir)).fairplayLicense); } catch (e) { stop(e.message); }
const cfg = JSON.parse(await fs.readFile(join(siteDir, "config.json"), "utf8"));
const photoKey = await derivePhotoKey(await deriveKey(process.env.SITE_PASSWORD, cfg.salt, cfg.iterations));
const key = await exportKeyHex(photoKey);
console.log(`::add-mask::${key}`);
// the password must open the gallery: otherwise every picture would be skipped and the run would look done
let sealed = null;
try { sealed = new Uint8Array(await fs.readFile(join(siteDir, "gallery.json.enc"))); } catch {}
if (sealed) { try { await open(photoKey, sealed); } catch { stop("SITE_PASSWORD does not open the gallery (was the site's password changed? update the secret)"); } }
const tools = { ffmpeg: process.env.FFMPEG_BIN || "ffmpeg", ffprobe: process.env.FFPROBE_BIN || "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
// a run that stops (Axinom refusing our key, or out of reach, before anything is replaced) is named on the run's
// page too, and leaves a result the workflow can read
let r;
try { r = await run({ payload: { key }, action: "fairplay", siteDir, tools, com }); }
catch (e) {
  if (process.env.BACKFILL_RESULT) await fs.writeFile(process.env.BACKFILL_RESULT, JSON.stringify({ status: "stopped", added: 0, already: 0, failed: 0, error: String(e.message || e).slice(0, 400) }));
  stop(String(e.message || e).slice(0, 400));
}
console.log(`::notice title=Apple backfill::${r.status} — ${r.added || 0} added or renewed, ${r.already || 0} already good, ${r.failed || 0} failed; combined view ${r.mosaic || "none"}`);
if (process.env.BACKFILL_RESULT) await fs.writeFile(process.env.BACKFILL_RESULT, JSON.stringify(r));
