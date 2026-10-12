// The one way a workflow runs shaka-packager: `node tools/run-packager.mjs <path> [arguments…]`. It checks the file by
// its SHA-256 at that moment (service/lib/packager-pin.mjs), then runs exactly the file it checked, with the arguments
// as given (no shell in between), and ends with its exit code. A file that is not the pinned build, or none, is named on
// the run's page and never run. tools/check-workflow-links.mjs refuses a workflow that names the packager file anywhere
// else but its pinned download, its check line, `chmod +x <path>` and PACKAGER_BIN.
import { spawnSync } from "node:child_process";
import { checkPackager } from "../service/lib/packager-pin.mjs";

const [bin, ...args] = process.argv.slice(2);
if (!bin) { console.log("::error title=Packager::usage: node tools/run-packager.mjs <path to the packager> [arguments…]"); process.exit(2); }
let path;
try { path = await checkPackager(bin); } catch (e) { console.log(`::error title=Packager::${e.message}`); process.exit(1); }
const r = spawnSync(path, args, { stdio: "inherit" });
if (r.error) { console.log(`::error title=Packager::${path} could not be run: ${r.error.message}`); process.exit(1); }
process.exit(r.status ?? 1); // killed by a signal: a failure
