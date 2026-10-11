// Runs before the protected-view page's own script: reads the key from this browser's session, fetches
// the encrypted files from the site, decrypts them in memory, and serves them to the player through an
// in-memory "mem://" scheme, so the public site only ever carries encrypted bytes and the player sees
// the same files the proof page plays. Two pages use it: view.html (one picture, ?id=) and all.html
// (window.__ccsMode = "all": the combined view of every ready picture, site/mosaic/, built by the job).
import { importKeyHex, open, openText } from "./crypto.js?v=aeb9bfd1fe59";

const FILES = ["widevine.mpd", "video-widevine.mp4", "playready.mpd", "video-playready.mp4"];

// Honors an HTTP Range header ("bytes=a-b", inclusive, or "bytes=a-") against an in-memory file.
export function sliceRange(data, range) {
  if (!range) return data;
  const m = /^bytes=(\d*)-(\d*)$/.exec(String(range));
  if (!m) return data;
  const start = m[1] === "" ? Math.max(0, data.length - Number(m[2])) : Number(m[1]);
  const end = m[1] === "" || m[2] === "" ? data.length - 1 : Math.min(Number(m[2]), data.length - 1);
  if (start > end) return new Uint8Array(0);
  return data.subarray(start, end + 1);
}

export function registerMemScheme(shaka, files) {
  shaka.net.NetworkingEngine.registerScheme("mem", (uri, request) => {
    const name = uri.replace(/^mem:\/\/photo\//, "").split("?")[0];
    const data = files[name];
    if (!data) return shaka.util.AbortableOperation.failed(new shaka.util.Error(shaka.util.Error.Severity.CRITICAL, shaka.util.Error.Category.NETWORK, shaka.util.Error.Code.BAD_HTTP_STATUS, uri, 404, null, {}, request.type));
    const out = sliceRange(data, request.headers && (request.headers.Range || request.headers.range));
    return shaka.util.AbortableOperation.completed({ uri, originalUri: uri, data: out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength), headers: {}, status: 200 });
  });
}

// Which picture a point on the video falls on. The video is drawn "contain" inside its box (black bars
// on two sides), so the point is mapped from the box to the frame first. Returns the tile or null.
export function tileAt(meta, box, px, py) {
  const s = Math.min(box.width / meta.width, box.height / meta.height);
  if (!(s > 0)) return null;
  const x = (px - (box.width - meta.width * s) / 2) / s, y = (py - (box.height - meta.height * s) / 2) / s;
  return meta.tiles.find((t) => x >= t.x && x < t.x + t.w && y >= t.y && y < t.y + t.h) || null;
}

async function fetchSealed(path, missing) {
  const r = await fetch(path + "?v=" + Date.now(), { cache: "no-store" });
  if (r.status === 404) throw new Error(missing);
  if (!r.ok) throw new Error(`the site answered ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

// The combined view's own additions: the pictures first (right under the title, so a phone shows them
// on opening, above the readout), a tap on a picture opens it alone, and the list of what is where.
function wireAll(meta) {
  const v = document.getElementById("v"), stage = document.getElementById("stage");
  document.getElementById("title").after(stage);
  stage.style.aspectRatio = `${meta.width} / ${meta.height}`;
  stage.style.maxHeight = "85vh";
  v.style.cursor = "pointer";
  v.addEventListener("click", (e) => {
    const r = v.getBoundingClientRect();
    const t = tileAt(meta, r, e.clientX - r.left, e.clientY - r.top);
    if (t) location.href = "view.html?id=" + t.id;
  });
  // full screen makes every picture larger (on a phone held upright the pictures then fill the screen)
  const full = document.createElement("button"); full.id = "fullscreen"; full.textContent = "Full screen";
  full.addEventListener("click", () => { const f = stage.requestFullscreen || stage.webkitRequestFullscreen; if (f) f.call(stage); });
  document.addEventListener("fullscreenchange", () => { stage.style.maxHeight = document.fullscreenElement === stage ? "none" : "85vh"; });
  const bar = document.createElement("p"); bar.className = "row"; bar.appendChild(full);
  const h = document.createElement("h2"); h.textContent = "What is in this view (tap a picture to open it on its own)";
  const ol = document.createElement("ol"); ol.id = "tiles";
  for (const t of meta.tiles) {
    const li = document.createElement("li"), a = document.createElement("a");
    a.href = "view.html?id=" + t.id; a.textContent = t.name; li.appendChild(a); ol.appendChild(li);
  }
  const when = document.createElement("p"); when.id = "built";
  when.textContent = `Left to right, top to bottom. Combined ${meta.builtAt.replace("T", " ").slice(0, 16)} UTC.`
    + (meta.skipped && meta.skipped.length ? ` Left out (could not be read back): ${meta.skipped.map((s) => s.name).join(", ")}.` : "");
  stage.after(bar, h, ol, when);
  // where each picture sits (sizes and ids only), for a walker that taps the way a person does
  window.__ccsMosaic = { width: meta.width, height: meta.height, tiles: meta.tiles.map(({ id, x, y, w, h }) => ({ id, x, y, w, h })) };
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  (async () => {
    const ALL = window.__ccsMode === "all";
    const params = new URLSearchParams(location.search);
    const id = params.get("id") || "";
    let st = null;
    try { st = JSON.parse(sessionStorage.getItem("ccs-site") || "null"); } catch {}
    if (!ALL && !/^[0-9a-f]{24}$/.test(id)) { location.replace("index.html"); return; }
    if (!st || !st.photoKeyHex || !st.at || Date.now() - st.at > 4 * 60 * 60 * 1000) { location.replace("index.html?then=" + (ALL ? "all" : encodeURIComponent(id))); return; }
    try {
      const key = await importKeyHex(st.photoKeyHex);
      const base = ALL ? "mosaic/" : `photos/${id}/`;
      const missing = ALL ? "the combined view is not on the site yet (it is made about two minutes after a picture is ready; your pictures page shows when)"
        : "this picture is not on the site yet (publishing takes about a minute after the job; try again shortly)";
      const meta = JSON.parse(await openText(key, await fetchSealed(base + "meta.json.enc", missing)));
      const files = {};
      for (const f of FILES) files[f] = await open(key, await fetchSealed(base + f + ".enc", missing));
      registerMemScheme(window.shaka, files);
      if (ALL) wireAll(meta);
      const n = ALL ? meta.tiles.length : 0;
      window.__ccsResolve(ALL
        ? { id: "all", title: `All your pictures, protected (${n})`, content: `your pictures: all ${n}, combined into one protected video`, prKidGuid: meta.prKidGuid, width: meta.width, height: meta.height }
        : { id, title: "Protected view: " + meta.name, content: "your picture: " + meta.name, prKidGuid: meta.prKidGuid, width: meta.width, height: meta.height });
    } catch (e) {
      const msg = document.getElementById("msg"); if (msg) msg.textContent = (ALL ? "The combined view could not be opened: " : "This picture could not be opened: ") + e.message;
      for (const k of ["r-ks", "r-expect"]) { const el = document.getElementById(k); if (el) { el.textContent = "not opened — " + e.message; el.className = "bad"; } }
    }
  })();
}
