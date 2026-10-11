// The three pages of the test site. The protected view is the proof's own route-1 page
// (web/research/drm/index.html) with its manifests, licence addresses and title substituted; every
// substitution must match exactly once, so a change to that page that breaks the view fails loudly at
// start-up (and in the tests) instead of serving a page that silently plays nothing.
import { escapeHtml } from "./util.mjs";

export const PAGES_BASE = "https://oneandroid-max.github.io/ccs-protected-still-proof/web/research/drm/";
// The public test card (drm-card.yml): its keys are public by design, so its licences may pass through.
export const CARD = { prKid: "5cfcb567f2f19d08a30b20483d92e930", prKidGuid: "5CFCB567-F2F1-9D08-A30B-20483D92E930" };

const STYLE = `
  body { font-family: system-ui, sans-serif; margin: 0 auto; padding: 16px; max-width: 920px; line-height: 1.5; color: #1b1a17; background: #f6f4ef; }
  h1 { font-size: 1.2rem; } h2 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: #6b665c; margin: 18px 0 6px; }
  p, li { max-width: 65ch; } .muted { color: #6b665c; } .bad { color: #a83a2b; } .ok { color: #1d6b3a; font-weight: 600; }
  input[type=text], input[type=password] { font: inherit; padding: 10px 12px; border: 1px solid #d9d4c8; border-radius: 8px; width: 100%; max-width: 360px; box-sizing: border-box; background: #fff; }
  label { display: block; margin: 12px 0 4px; font-size: 0.9rem; color: #6b665c; }
  button, .btn { font: inherit; padding: 8px 14px; border-radius: 999px; border: 1px solid #d9d4c8; background: #fff; cursor: pointer; text-decoration: none; color: inherit; display: inline-block; }
  button.primary, .btn.primary { background: #1f4e8c; color: #fff; border-color: #1f4e8c; font-weight: 600; }
  button.danger { color: #a83a2b; }
  .card { background: #fff; border: 1px solid #d9d4c8; border-radius: 10px; padding: 12px 14px; margin: 10px 0; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .bar { height: 6px; background: #e8e4da; border-radius: 3px; overflow: hidden; margin-top: 6px; } .bar > i { display: block; height: 100%; background: #1f4e8c; width: 0; }
  code { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.85rem; }
`;

const shell = (nonce, title, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title><style nonce="${nonce}">${STYLE}</style></head><body>${body}</body></html>`;

export function loginPage({ nonce, error }) {
  const msg = error === "locked" ? `<p class="bad">Too many wrong attempts. Wait 15 minutes, then try again.</p>`
    : error === "1" ? `<p class="bad">That username or password is not right.</p>` : "";
  return shell(nonce, "CCS proof test site — sign in", `
<h1>CCS proof test site</h1>
<p class="muted">Enter the password to upload pictures and test the protected view on your devices.</p>
${msg}
<form method="post" action="/login" autocomplete="on">
  <label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required autofocus>
  <p><button class="primary" type="submit">Enter</button></p>
</form>`);
}

export function galleryPage({ nonce, maxPhotos }) {
  return shell(nonce, "CCS proof test site — your pictures", `
<div class="row" style="justify-content:space-between"><h1 style="margin:0">Your test pictures</h1>
<form method="post" action="/logout"><button type="submit">Sign out</button></form></div>
<p class="muted">Upload up to ${maxPhotos} pictures (JPEG, PNG or WebP, 25 MB each). Each one is prepared for the browser's protected path and opens in the same viewer as the proof page. Nothing on this page shows a picture: the only place one is drawn is its protected view.</p>
<div class="card">
  <div class="row"><input id="files" type="file" accept="image/jpeg,image/png,image/webp" multiple> <span id="slots" class="muted"></span></div>
  <div id="uploads"></div>
</div>
<div id="tools" class="muted"></div>
<h2>Pictures</h2>
<div id="list"><p class="muted">Loading…</p></div>
<script nonce="${nonce}">
(() => {
  const $ = (id) => document.getElementById(id);
  const H = { "x-proof": "1" };
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const kb = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.round(n / 1024) + " KB";
  const word = { queued: "waiting its turn", processing: "being prepared…", ready: "ready", failed: "failed" };
  let timer = null;
  async function load() {
    clearTimeout(timer);
    const r = await fetch("/api/photos", { headers: H, cache: "no-store" });
    if (r.status === 401) { location.href = "/login"; return; }
    const d = await r.json();
    render(d);
    if (d.photos.some((p) => p.status === "queued" || p.status === "processing")) timer = setTimeout(load, 2000);
  }
  function render(d) {
    const used = d.photos.length;
    $("slots").textContent = used + " of " + d.maxPhotos + " slots used";
    $("files").disabled = used >= d.maxPhotos;
    $("tools").textContent = d.tools && d.tools.problem ? "HOLD: this server cannot prepare pictures — " + d.tools.problem : "";
    if (!d.photos.length) { $("list").innerHTML = '<p class="muted">No pictures yet. Choose some above.</p>'; return; }
    $("list").innerHTML = d.photos.map((p) => {
      const st = p.status === "ready" ? '<span class="ok">ready</span>' : p.status === "failed" ? '<span class="bad">failed: ' + esc(p.error || "") + "</span>" : '<span class="muted">' + word[p.status] + "</span>";
      const dims = p.width ? " · " + p.width + "×" + p.height : "";
      const links = p.status === "ready" ? '<div class="row" style="margin-top:8px"><a class="btn primary" href="/view/' + p.id + '">Open the protected view</a>'
        + '<a class="btn" href="/view/' + p.id + '?levels=software">Software test (card)</a><a class="btn" href="/view/' + p.id + '?levels=clearkey">Control (card)</a></div>' : "";
      return '<div class="card"><div class="row" style="justify-content:space-between"><strong>' + esc(p.name) + '</strong><button class="danger" data-del="' + p.id + '">Delete</button></div>'
        + '<div class="muted">' + kb(p.bytes) + dims + " · " + st + " · licences issued: " + (d.views[p.id] || 0) + "</div>" + links + "</div>";
    }).join("");
    for (const b of $("list").querySelectorAll("button[data-del]")) b.addEventListener("click", async () => {
      if (!confirm("Delete this picture? Its protected view stops working at once.")) return;
      await fetch("/api/photos/" + b.dataset.del, { method: "DELETE", headers: H }); load();
    });
  }
  $("files").addEventListener("change", async () => {
    const files = [...$("files").files]; $("files").value = "";
    for (const f of files) await upload(f);
    load();
  });
  function upload(f) {
    return new Promise((done) => {
      const box = document.createElement("div"); box.innerHTML = "<div>" + esc(f.name) + ' <span class="muted"></span></div><div class="bar"><i></i></div>';
      $("uploads").appendChild(box);
      const note = box.querySelector("span"), bar = box.querySelector("i");
      const x = new XMLHttpRequest(); x.open("PUT", "/api/photos");
      x.setRequestHeader("x-proof", "1"); x.setRequestHeader("x-filename", encodeURIComponent(f.name)); x.setRequestHeader("content-type", f.type || "application/octet-stream");
      x.upload.onprogress = (e) => { if (e.lengthComputable) bar.style.width = Math.round(100 * e.loaded / e.total) + "%"; };
      x.onload = () => { bar.style.width = "100%"; if (x.status === 201) { note.textContent = "uploaded — preparing"; setTimeout(() => box.remove(), 4000); } else { let m = ""; try { m = JSON.parse(x.responseText).error; } catch {} note.textContent = "refused: " + (m || x.status); note.className = "bad"; } done(); };
      x.onerror = () => { note.textContent = "upload failed (network)"; note.className = "bad"; done(); };
      x.send(f);
    });
  }
  load();
})();
</script>`);
}

export function preparingPage({ nonce, name, status, error }) {
  const line = status === "failed" ? `<p class="bad">This picture could not be prepared: ${escapeHtml(error || "unknown reason")}</p>`
    : `<p>This picture is ${status === "processing" ? "being prepared" : "waiting its turn"}. This page refreshes on its own.</p><meta http-equiv="refresh" content="3">`;
  return shell(nonce, "Protected view", `<h1>${escapeHtml(name)}</h1>${line}<p><a class="btn" href="/app">Back to your pictures</a></p>`);
}

// Replaces `from` with `to` exactly once, or throws naming the piece that no longer matches.
function once(html, from, to, label) {
  const first = html.indexOf(from);
  if (first < 0 || html.indexOf(from, first + 1) >= 0) throw new Error(`the route-1 page no longer matches the view template at: ${label}`);
  return html.slice(0, first) + to + html.slice(first + from.length);
}

// Builds the protected-view renderer from the route-1 page's HTML.
export function buildViewTemplate(indexHtml) {
  let t = indexHtml;
  t = once(t, "<title>Route 1: the browser's protected video path</title>", "<title>Protected view</title>", "title");
  t = once(t, "<style>", '<style nonce="__NONCE__">', "style");
  t = once(t, "<h1>Route 1: the browser's own protected video path</h1>", "<h1>Protected view: __NAME__</h1>", "heading");
  t = once(t, '<script src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/5.2.10/shaka-player.compiled.min.js" integrity="sha384-ZWp1oeFexKioXrhPcPdQ6INqt3fK8DsBJbWzlRdMokbapQn4fKqwPVPox7JNY7wJ" crossorigin="anonymous"></script>',
    '<script nonce="__NONCE__" src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/5.2.10/shaka-player.compiled.min.js" integrity="sha384-ZWp1oeFexKioXrhPcPdQ6INqt3fK8DsBJbWzlRdMokbapQn4fKqwPVPox7JNY7wJ" crossorigin="anonymous"></script>', "player script");
  t = once(t, "<script>\n(async () => {", '<script nonce="__NONCE__">\n(async () => {', "page script");
  t = once(t, 'name: "the photo", widevine: "widevine.mpd", playready: "playready.mpd", prKid: "9E0FFABA-46A8-1DEC-DC6F-CE6F0CAFA51A"',
    'name: "your picture: __NAME_JS__", widevine: "/media/__ID__/widevine.mpd", playready: "/media/__ID__/playready.mpd", prKid: "__PRKID__"', "photo clip");
  t = once(t, 'widevine: "card-widevine.mpd", playready: "card-playready.mpd"',
    `widevine: "${PAGES_BASE}card-widevine.mpd", playready: "${PAGES_BASE}card-playready.mpd"`, "card clip");
  t = once(t, "cfg.drm.servers[ks] = `https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(kid:${CLIP.prKid},sl:${t.sl})`;",
    "cfg.drm.servers[ks] = `/licence/playready?photo=__ID__&kid=${CLIP.prKid}&sl=${t.sl}`;", "playready licence address");
  t = once(t, 'cfg.drm.servers["com.widevine.alpha"] = "https://cwip-shaka-proxy.appspot.com/no_auth";',
    'cfg.drm.servers["com.widevine.alpha"] = "/licence/widevine?photo=__ID__";', "widevine licence address");
  t = once(t, '<p><a href="../">Back to the list of candidates</a> · <a href="../../../widevine/">the first Widevine proof (2026-10-09)</a></p>',
    '<p><a href="/app">Back to your pictures</a></p>', "footer");
  return function render({ id, name, prKidGuid, nonce }) {
    if (!/^[0-9a-f]{8,64}$/.test(id)) throw new Error("bad id");
    if (!/^[0-9A-F-]{36}$/.test(prKidGuid)) throw new Error("bad key id");
    const values = {
      ID: id, PRKID: prKidGuid, NONCE: nonce,
      NAME_JS: JSON.stringify(String(name)).slice(1, -1).replace(/<\//g, "<\\/"),
      NAME: escapeHtml(name),
    };
    // one pass, so a substituted value (a picture's name, say) is never scanned for placeholders itself
    return t.replace(/__(ID|PRKID|NONCE|NAME_JS|NAME)__/g, (_, k) => values[k]);
  };
}
