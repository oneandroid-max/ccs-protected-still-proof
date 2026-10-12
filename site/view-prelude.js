// Runs before the protected-view page's own script: reads the key from this browser's session, fetches
// the encrypted files from the site, decrypts them in memory, and serves them to the player through an
// in-memory "mem://" scheme, so the public site only ever carries encrypted bytes and the player sees
// the same files the proof page plays. Two pages use it: view.html (one picture, ?id=) and the one page,
// index.html (window.__ccsMode = "home": the combined view of every ready picture, site/mosaic/, built by the
// job, under the page's own sign-in and gallery, site/gallery.js; until 2026-10-12 a page of its own, all.html).
// Apple's FairPlay form is the one exception to "from memory": Safari's own player fetches it by address,
// so its files are served as they are (their samples are encrypted under a key that only the picture's
// licence token carries, encrypted for the licence service), and only the token (token.enc, in the same
// folder) is sealed.
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

async function fetchSealed(path, missing, orNull = false) {
  const r = await fetch(path + "?v=" + Date.now(), { cache: "no-store" });
  if (r.status === 404 && orNull) return null;
  if (r.status === 404) throw new Error(missing);
  if (!r.ok) throw new Error(`the site answered ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

// The one page's own arrangement: the pictures right under the top line, above the gallery and the readout (a phone
// shows them on opening); a tap on a picture opens it alone; full screen; when the view was combined and what was left
// out. With no combined view yet, the box where it will play stands there with the page's message in it.
function wireHome(meta) {
  const v = document.getElementById("v"), stage = document.getElementById("stage");
  document.getElementById("gallery").before(stage);
  if (!meta) { stage.style.maxHeight = "40vh"; return; }
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
  const when = document.createElement("p"); when.id = "built";
  when.textContent = `Left to right, top to bottom; tap a picture to open it on its own. Combined ${meta.builtAt.replace("T", " ").slice(0, 16)} UTC.`
    + (meta.skipped && meta.skipped.length ? ` Left out (could not be read back): ${meta.skipped.map((s) => s.name).join(", ")}.` : "");
  stage.after(bar, when);
  // where each picture sits (sizes and ids only), for a walker that taps the way a person does
  window.__ccsMosaic = { width: meta.width, height: meta.height, tiles: meta.tiles.map(({ id, x, y, w, h }) => ({ id, x, y, w, h })) };
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  // Back or Forward may hand a page back from the browser's memory, with its protected video paused or
  // its frame released: load it afresh instead, so it plays again under the same rule from the start
  window.addEventListener("pageshow", (e) => { if (e.persisted) location.reload(); });
  (async () => {
    const HOME = window.__ccsMode === "home";
    const params = new URLSearchParams(location.search);
    const id = params.get("id") || "";
    let st = null;
    if (HOME) st = await window.__ccsSession; // the one page: its own sign-in (gallery.js) hands the session over
    else {
      try { st = JSON.parse(sessionStorage.getItem("ccs-site") || "null"); } catch {}
      if (!/^[0-9a-f]{24}$/.test(id)) { location.replace("index.html"); return; }
      if (!st || !st.photoKeyHex || !st.at || Date.now() - st.at > 4 * 60 * 60 * 1000) { location.replace("index.html?then=" + encodeURIComponent(id)); return; }
    }
    try {
      const key = await importKeyHex(st.photoKeyHex);
      const base = HOME ? "mosaic/" : `photos/${id}/`;
      const missing = "this picture is not on the site yet (publishing takes about a minute after the job; try again shortly)";
      const sealed = await fetchSealed(base + "meta.json.enc", missing, HOME);
      if (!sealed) {
        // the one page before its combined view is made: the page says so where the view will play, and plays nothing
        wireHome(null);
        window.__ccsPlaying = null;
        window.__ccsResolve({ id: "all", title: "Your pictures, protected", content: "your pictures (none combined yet)", prKidGuid: "", width: 0, height: 0, fairplay: null,
          none: "Your pictures show here, all at once, once one is ready and they are combined into one protected view (about two minutes after it is ready). Add pictures below." });
        return;
      }
      const meta = JSON.parse(await openText(key, sealed));
      const files = {};
      for (const f of FILES) files[f] = await open(key, await fetchSealed(base + f + ".enc", missing));
      registerMemScheme(window.shaka, files);
      // the Apple form, when the job made one; a fault here touches Apple devices only, and is shown there
      let fairplay = null;
      if (meta.fairplay) {
        try {
          if (!/^fp-[0-9a-f]{8}\/master\.m3u8$/.test(String(meta.fairplay.master))) throw new Error("its address is not one the job writes");
          // a token past the expiry date the job recorded for it can license nothing: the form is not offered (the job treats it as dead too)
          if (Date.parse(meta.fairplay.expires) <= Date.now()) throw new Error(`its licence token expired on ${String(meta.fairplay.expires).slice(0, 10)}`);
          const token = await openText(key, await fetchSealed(base + meta.fairplay.master.split("/")[0] + "/token.enc", "its licence token is not on the site yet"));
          fairplay = { manifest: new URL(base + meta.fairplay.master, location.href).href, token, ...(meta.fairplay.license !== undefined ? { license: String(meta.fairplay.license) } : {}) };
        } catch (e) { fairplay = { error: e.message }; }
      }
      if (HOME) { wireHome(meta); window.__ccsPlaying = meta.builtAt || null; }
      const n = HOME ? meta.tiles.length : 0;
      window.__ccsResolve(HOME
        ? { id: "all", title: `Your pictures, protected (${n})`, content: `your pictures: all ${n}, combined into one protected video`, prKidGuid: meta.prKidGuid, width: meta.width, height: meta.height, fairplay }
        : { id, title: "Protected view: " + meta.name, content: "your picture: " + meta.name, prKidGuid: meta.prKidGuid, width: meta.width, height: meta.height, fairplay });
    } catch (e) {
      const msg = document.getElementById("msg"); if (msg) msg.textContent = (HOME ? "The combined view could not be opened: " : "This picture could not be opened: ") + e.message;
      for (const k of ["r-ks", "r-expect"]) { const el = document.getElementById(k); if (el) { el.textContent = "not opened — " + e.message; el.className = "bad"; } }
    }
  })();
}
