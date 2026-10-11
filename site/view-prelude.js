// Runs before the protected-view page's own script: reads the key from this browser's session, fetches
// the picture's encrypted files from the site, decrypts them in memory, and serves them to the player
// through an in-memory "mem://" scheme, so the public site only ever carries encrypted bytes and the
// player sees the same files the proof page plays.
import { importKeyHex, open, openText } from "./crypto.js";

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

async function fetchSealed(path) {
  const r = await fetch(path + "?v=" + Date.now(), { cache: "no-store" });
  if (r.status === 404) throw new Error("this picture is not on the site yet (publishing takes about a minute after the job; try again shortly)");
  if (!r.ok) throw new Error(`the site answered ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  (async () => {
    const params = new URLSearchParams(location.search);
    const id = params.get("id") || "";
    let st = null;
    try { st = JSON.parse(sessionStorage.getItem("ccs-site") || "null"); } catch {}
    if (!/^[0-9a-f]{24}$/.test(id)) { location.replace("index.html"); return; }
    if (!st) { location.replace("index.html?then=" + encodeURIComponent(id)); return; }
    try {
      const key = await importKeyHex(st.keyHex);
      const meta = JSON.parse(await openText(key, await fetchSealed(`photos/${id}/meta.json.enc`)));
      const files = {};
      for (const f of FILES) files[f] = await open(key, await fetchSealed(`photos/${id}/${f}.enc`));
      registerMemScheme(window.shaka, files);
      window.__ccsResolve({ id, name: meta.name, prKidGuid: meta.prKidGuid, width: meta.width, height: meta.height });
    } catch (e) {
      const msg = document.getElementById("msg"); if (msg) msg.textContent = "This picture could not be opened: " + e.message;
      for (const k of ["r-ks", "r-expect"]) { const el = document.getElementById(k); if (el) { el.textContent = "not opened — " + e.message; el.className = "bad"; } }
    }
  })();
}
