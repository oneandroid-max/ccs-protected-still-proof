// The Apple backfill's entry (site-fairplay.yml, started by hand). Derives the picture key from the site
// password exactly as the page does (site/config.json's salt and rounds, then the one-way picture key),
// masks it in the run's log before anything else, and runs the worker's "fairplay" action: Apple's form
// for every ready picture that lacks it, then the combined view. Writes the counts to BACKFILL_RESULT
// (a file), so the workflow can commit what succeeded and still fail visibly when a picture did not.
import { promises as fs } from "node:fs";
import { fileURLToPath } from "node:url";
import { deriveKey, derivePhotoKey, exportKeyHex } from "./crypto.js";
import { run } from "./worker.mjs";
import { readCommunicationKey } from "./axinom.mjs";

// a missing or malformed secret is named on the run's page (an error annotation), not only in its log
const stop = (why) => { console.log(`::error title=Apple backfill::${why}`); process.exit(1); };
if (!process.env.SITE_PASSWORD) stop("SITE_PASSWORD is not set");
let com;
try { com = readCommunicationKey(process.env.AXINOM_COM_KEY_ID, process.env.AXINOM_COM_KEY); } catch (e) { stop(e.message); }
const cfg = JSON.parse(await fs.readFile(new URL("./config.json", import.meta.url), "utf8"));
const key = await exportKeyHex(await derivePhotoKey(await deriveKey(process.env.SITE_PASSWORD, cfg.salt, cfg.iterations)));
console.log(`::add-mask::${key}`);
const tools = { ffmpeg: process.env.FFMPEG_BIN || "ffmpeg", ffprobe: process.env.FFPROBE_BIN || "ffprobe", packager: process.env.PACKAGER_BIN || "packager" };
const r = await run({ payload: { key }, action: "fairplay", siteDir: fileURLToPath(new URL("./", import.meta.url)), tools, com });
console.log(`::notice title=Apple backfill::${r.status} — ${r.added || 0} added, ${r.already || 0} already had it, ${r.failed || 0} failed; combined view ${r.mosaic || "none"}`);
if (process.env.BACKFILL_RESULT) await fs.writeFile(process.env.BACKFILL_RESULT, JSON.stringify(r));
