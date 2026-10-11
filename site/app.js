// The test site's browser side. The password unlocks an encrypted GitHub access key (config.json);
// with it the page lists the gallery, uploads pictures as ENCRYPTED blobs (never readable by GitHub or
// the public), and asks a GitHub Action to prepare each one. Everything the Action writes back is
// encrypted under the same password-derived key, so the public repository never holds a readable
// picture. Nothing here talks to any server but GitHub's own API and this site.
import { deriveKey, exportKeyHex, importKeyHex, seal, openText, toBase64, fromBase64, toHex, randomBytes } from "./crypto.js";

export const REPO = "oneandroid-max/ccs-protected-still-proof";
export const API = "https://api.github.com";
export const MAX_PHOTOS = 10;
export const MAX_BYTES = 25 * 1024 * 1024;
const STORE = "ccs-site", PENDING = "ccs-pending";

export const session = {
  get() { try { return JSON.parse(sessionStorage.getItem(STORE) || "null"); } catch { return null; } },
  set(v) { sessionStorage.setItem(STORE, JSON.stringify(v)); },
  clear() { sessionStorage.removeItem(STORE); sessionStorage.removeItem(PENDING); },
};
export const pending = {
  get() { try { return JSON.parse(sessionStorage.getItem(PENDING) || "[]"); } catch { return []; } },
  set(v) { sessionStorage.setItem(PENDING, JSON.stringify(v)); },
  add(p) { pending.set([...pending.get(), p]); },
  prune(galleryIds) { pending.set(pending.get().filter((p) => !galleryIds.has(p.id) && Date.now() - p.startedAt < 30 * 60 * 1000)); },
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

// Checks that an access key reaches the repository and can write to it.
export async function checkToken(token) {
  const r = await api(token, "GET", `/repos/${REPO}`);
  if (r.status === 401) throw new Error("GitHub does not accept this access key (expired or revoked)");
  if (!r.ok) throw new Error(`GitHub answered ${r.status}`);
  const repo = await r.json();
  if (!repo.permissions || !repo.permissions.push) throw new Error("this access key cannot write to the repository");
  return repo;
}

export async function unlock(password) {
  const cfg = await loadConfig();
  if (!cfg.tokenEnc) throw new Error("the site has not been set up yet (open setup.html first)");
  const key = await deriveKey(password, cfg.salt, cfg.iterations);
  let token;
  try { token = await openText(key, fromBase64(cfg.tokenEnc)); } catch { throw new Error("wrong password"); }
  await checkToken(token);
  const st = { keyHex: await exportKeyHex(key), token, at: Date.now() };
  session.set(st);
  return st;
}

export async function gallery(st) {
  const key = await importKeyHex(st.keyHex);
  const r = await api(st.token, "GET", `/repos/${REPO}/contents/site/gallery.json.enc?ref=main&t=${Date.now()}`, null, "application/vnd.github.raw+json");
  if (r.status === 404) return { photos: [] };
  if (!r.ok) throw new Error(`GitHub answered ${r.status} for the gallery`);
  try { return JSON.parse(await openText(key, new Uint8Array(await r.arrayBuffer()))); }
  catch { throw new Error("the gallery was written under another password; delete the pictures and upload again"); }
}

// The picture's type from its first bytes, never from its name.
export function sniff(u8) {
  if (u8.length >= 3 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) return "image/jpeg";
  if (u8.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((b, i) => u8[i] === b)) return "image/png";
  if (u8.length >= 12 && String.fromCharCode(...u8.subarray(0, 4)) === "RIFF" && String.fromCharCode(...u8.subarray(8, 12)) === "WEBP") return "image/webp";
  return null;
}

export async function upload(st, file, count) {
  if (count >= MAX_PHOTOS) throw new Error(`the gallery holds at most ${MAX_PHOTOS} pictures; delete one first`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const type = sniff(bytes);
  if (!type) throw new Error("only JPEG, PNG or WebP pictures are accepted");
  if (bytes.length > MAX_BYTES) throw new Error("a picture may be at most 25 MB");
  const key = await importKeyHex(st.keyHex);
  const sealed = await seal(key, bytes);
  const id = toHex(randomBytes(12));
  const blob = await api(st.token, "POST", `/repos/${REPO}/git/blobs`, { content: toBase64(sealed), encoding: "base64" });
  if (!blob.ok) throw new Error(`GitHub refused the upload (${blob.status})`);
  const { sha } = await blob.json();
  const name = String(file.name || "picture").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 120) || "picture";
  const d = await api(st.token, "POST", `/repos/${REPO}/dispatches`, { event_type: "photo", client_payload: { action: "add", id, name, type, bytes: bytes.length, blobSha: sha, key: st.keyHex } });
  if (d.status !== 204) throw new Error(`GitHub did not start the job (${d.status})`);
  const p = { id, name, bytes: bytes.length, startedAt: Date.now() };
  pending.add(p);
  return p;
}

export async function remove(st, id) {
  const d = await api(st.token, "POST", `/repos/${REPO}/dispatches`, { event_type: "photo", client_payload: { action: "delete", id, key: st.keyHex } });
  if (d.status !== 204) throw new Error(`GitHub did not start the job (${d.status})`);
  pending.add({ id, name: "", bytes: 0, startedAt: Date.now(), deleting: true });
}

// Whether the prepared files have reached the live site (Pages publishes about a minute after the Action).
export async function published(id) {
  const r = await fetch(`photos/${id}/widevine.mpd.enc?v=${Date.now()}`, { method: "HEAD", cache: "no-store" });
  return r.ok;
}
