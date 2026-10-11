// The test site's browser side. The password unlocks an encrypted GitHub access key (config.json);
// with it the page lists the gallery, uploads pictures as ENCRYPTED blobs (never readable by GitHub or
// the public), and asks a GitHub Action to prepare each one. Two keys come from the password: the
// password key, which only unseals the access key and never leaves this browser, and the picture key
// (derived one-way from it), which encrypts uploads and outputs and rides each job request to GitHub.
// Nothing here talks to any server but GitHub's own API and this site.
import { deriveKey, derivePhotoKey, exportKeyHex, importKeyHex, seal, openText, toBase64, fromBase64, toHex, randomBytes } from "./crypto.js";

export const REPO = "oneandroid-max/ccs-protected-still-proof";
export const API = "https://api.github.com";
export const MAX_PHOTOS = 10;
export const MAX_BYTES = 25 * 1024 * 1024;
export const SESSION_TTL = 4 * 60 * 60 * 1000;   // the keys and the access key leave this tab after four hours
export const STALL_MS = 6 * 60 * 1000;           // a job that has not answered in six minutes is reported as stalled
export const PENDING_MAX = 60 * 60 * 1000;
const STORE = "ccs-site", PENDING = "ccs-pending";

export const session = {
  get() {
    let s = null;
    try { s = JSON.parse(sessionStorage.getItem(STORE) || "null"); } catch {}
    if (!s || !s.keyHex || !s.photoKeyHex || !s.token || !s.at || Date.now() - s.at > SESSION_TTL) { if (s) session.clear(); return null; }
    return s;
  },
  set(v) { sessionStorage.setItem(STORE, JSON.stringify(v)); },
  clear() { sessionStorage.removeItem(STORE); sessionStorage.removeItem(PENDING); },
};
// Pictures this tab has asked GitHub about and not yet seen answered: adds wait until the id appears
// in the gallery, deletes wait until it disappears.
export const pending = {
  get() { try { return JSON.parse(sessionStorage.getItem(PENDING) || "[]"); } catch { return []; } },
  set(v) { sessionStorage.setItem(PENDING, JSON.stringify(v)); },
  add(p) { pending.set([...pending.get().filter((x) => x.id !== p.id), p]); },
  prune(galleryIds) { pending.set(pending.get().filter((p) => Date.now() - p.startedAt < PENDING_MAX && (p.deleting ? galleryIds.has(p.id) : !galleryIds.has(p.id)))); },
};

export async function loadConfig() {
  const r = await fetch("config.json?v=" + Date.now(), { cache: "no-store" });
  if (!r.ok) throw new Error("config.json is missing from the site");
  return r.json();
}

export function api(token, method, path, body, accept) {
  const headers = { Authorization: `Bearer ${token}`, Accept: accept || "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (body) headers["Content-Type"] = "application/json";
  return fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store" });
}

// Checks that an access key reaches the repository and can really write to it (a harmless orphan blob).
export async function checkToken(token) {
  const r = await api(token, "GET", `/repos/${REPO}`);
  if (r.status === 401) throw new Error("GitHub does not accept this access key (expired or revoked)");
  if (!r.ok) throw new Error(`GitHub answered ${r.status}`);
  const w = await api(token, "POST", `/repos/${REPO}/git/blobs`, { content: "ccs-site write check", encoding: "utf-8" });
  if (w.status === 403 || w.status === 404) throw new Error("this access key cannot write to the repository (it needs Contents: read and write)");
  if (!w.ok) throw new Error(`GitHub answered ${w.status} to a write check`);
  return r.json();
}

export async function unlock(password) {
  const cfg = await loadConfig();
  if (!cfg.tokenEnc) throw new Error("the site has not been set up yet (open setup.html first)");
  const key = await deriveKey(password, cfg.salt, cfg.iterations);
  let token;
  try { token = await openText(key, fromBase64(cfg.tokenEnc)); } catch { throw new Error("wrong password"); }
  await checkToken(token);
  const st = { keyHex: await exportKeyHex(key), photoKeyHex: await exportKeyHex(await derivePhotoKey(key)), token, at: Date.now() };
  session.set(st);
  return st;
}

export async function gallery(st) {
  const key = await importKeyHex(st.photoKeyHex);
  const r = await api(st.token, "GET", `/repos/${REPO}/contents/site/gallery.json.enc?ref=main&t=${Date.now()}`, null, "application/vnd.github.raw+json");
  if (r.status === 404) return { photos: [], foreign: false };
  if (!r.ok) throw new Error(`GitHub answered ${r.status} for the gallery`);
  try { return { ...JSON.parse(await openText(key, new Uint8Array(await r.arrayBuffer()))), foreign: false }; }
  catch { return { photos: [], foreign: true }; } // written under another password: nothing readable, but uploads still work
}

// The picture's type from its first bytes, never from its name.
export function sniff(u8) {
  if (u8.length >= 3 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) return "image/jpeg";
  if (u8.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((b, i) => u8[i] === b)) return "image/png";
  if (u8.length >= 12 && String.fromCharCode(...u8.subarray(0, 4)) === "RIFF" && String.fromCharCode(...u8.subarray(8, 12)) === "WEBP") return "image/webp";
  return null;
}

async function dispatch(st, payload) {
  const d = await api(st.token, "POST", `/repos/${REPO}/dispatches`, { event_type: "photo", client_payload: { ...payload, key: st.photoKeyHex } });
  if (d.status !== 204) throw new Error(`GitHub did not start the job (${d.status})`);
}

export async function upload(st, file, count) {
  if (count >= MAX_PHOTOS) throw new Error(`the gallery holds at most ${MAX_PHOTOS} pictures; delete one first`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const type = sniff(bytes);
  if (!type) throw new Error("only JPEG, PNG or WebP pictures are accepted");
  if (bytes.length > MAX_BYTES) throw new Error("a picture may be at most 25 MB");
  const key = await importKeyHex(st.photoKeyHex);
  const sealed = await seal(key, bytes);
  const id = toHex(randomBytes(12));
  const blob = await api(st.token, "POST", `/repos/${REPO}/git/blobs`, { content: toBase64(sealed), encoding: "base64" });
  if (!blob.ok) throw new Error(`GitHub refused the upload (${blob.status})`);
  const { sha } = await blob.json();
  const name = String(file.name || "picture").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 120) || "picture";
  const p = { id, name, type, bytes: bytes.length, blobSha: sha, startedAt: Date.now() };
  await dispatch(st, { action: "add", id, name, type, bytes: bytes.length, blobSha: sha });
  pending.add(p);
  return p;
}

// Asks GitHub again for a picture whose job never answered (the encrypted upload is still there).
export async function retry(st, p) {
  if (p.deleting) await dispatch(st, { action: "delete", id: p.id });
  else await dispatch(st, { action: "add", id: p.id, name: p.name, type: p.type, bytes: p.bytes, blobSha: p.blobSha });
  pending.add({ ...p, startedAt: Date.now() });
}

export async function remove(st, id) {
  await dispatch(st, { action: "delete", id });
  pending.add({ id, name: "", bytes: 0, startedAt: Date.now(), deleting: true });
}

// The combined view (every ready picture in one protected video, site/mosaic/, made by the job after
// each change): its sealed layout as published on the live site, or null when there is none yet or it
// was made under another password.
export async function mosaicMeta(st) {
  const r = await fetch(`mosaic/meta.json.enc?v=${Date.now()}`, { cache: "no-store" });
  if (!r.ok) return null;
  try { return JSON.parse(await openText(await importKeyHex(st.photoKeyHex), new Uint8Array(await r.arrayBuffer()))); } catch { return null; }
}
// Whether the combined view holds exactly the pictures that are ready now (left-out ones count as held).
export function mosaicCurrent(meta, readyIds) {
  if (!meta || !Array.isArray(meta.ids)) return false;
  const held = new Set([...meta.ids, ...(meta.skipped || []).map((x) => x.id)]);
  return held.size === readyIds.length && readyIds.every((id) => held.has(id));
}
// Asks GitHub to (re)make the combined view; the time is kept so a page does not ask again too soon.
export const MOSAIC_ASK_GAP = 8 * 60 * 1000;
export async function askMosaic(st) {
  await dispatch(st, { action: "mosaic" });
  sessionStorage.setItem("ccs-mosaic-asked", String(Date.now()));
}
export function mosaicAskedAt() { return Number(sessionStorage.getItem("ccs-mosaic-asked") || 0); }

// Whether the prepared files have reached the live site (Pages publishes about a minute after the Action).
export async function published(id) {
  const r = await fetch(`photos/${id}/widevine.mpd.enc?v=${Date.now()}`, { method: "HEAD", cache: "no-store" });
  return r.ok;
}
