// The gallery's record: one JSON file (written atomically) plus an append-only log of views.
// Layout under DATA_DIR:
//   state.json                 { photos: [ { id, name, bytes, type, ext, width, height, orientation,
//                                            status, error, createdAt, readyAt, prKid, prKidGuid, wvContentId } ] }
//   views.jsonl                one line per licence request (who, which photo, which system, result)
//   photos/<id>/original.<ext>, clip.mp4, video-widevine.mp4, widevine.mpd, video-playready.mp4, playready.mpd
import { promises as fs } from "node:fs";
import { join } from "node:path";

export class Store {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.statePath = join(dataDir, "state.json");
    this.viewsPath = join(dataDir, "views.jsonl");
    this.photosDir = join(dataDir, "photos");
    this.state = { photos: [] };
    this.writing = Promise.resolve();
  }
  async init() {
    await fs.mkdir(this.photosDir, { recursive: true });
    try { this.state = JSON.parse(await fs.readFile(this.statePath, "utf8")); } catch { this.state = { photos: [] }; }
    if (!Array.isArray(this.state.photos)) this.state.photos = [];
    // a restart interrupts any processing: those photos go back to the queue
    for (const p of this.state.photos) if (p.status === "processing") p.status = "queued";
    await this.save();
  }
  save() {
    const data = JSON.stringify(this.state, null, 2) + "\n";
    const tmp = this.statePath + ".tmp";
    this.writing = this.writing.then(() => fs.writeFile(tmp, data).then(() => fs.rename(tmp, this.statePath)));
    return this.writing;
  }
  photos() { return this.state.photos; }
  get(id) { return this.state.photos.find((p) => p.id === id) || null; }
  dir(id) { return join(this.photosDir, id); }
  async add(rec) { this.state.photos.push(rec); await fs.mkdir(this.dir(rec.id), { recursive: true }); await this.save(); return rec; }
  async update(id, patch) { const p = this.get(id); if (!p) return null; Object.assign(p, patch); await this.save(); return p; }
  async remove(id) {
    const i = this.state.photos.findIndex((p) => p.id === id);
    if (i < 0) return false;
    this.state.photos.splice(i, 1);
    await this.save();
    await fs.rm(this.dir(id), { recursive: true, force: true });
    return true;
  }
  async logView(entry) {
    await fs.appendFile(this.viewsPath, JSON.stringify(entry) + "\n");
  }
  async views(limit = 200) {
    let text = "";
    try { text = await fs.readFile(this.viewsPath, "utf8"); } catch { return []; }
    return text.trim().split("\n").filter(Boolean).slice(-limit).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  }
}
