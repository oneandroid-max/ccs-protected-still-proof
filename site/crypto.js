// One encryption module for the browser pages AND the GitHub Action (Node 22 has the same WebCrypto),
// so the two can never drift apart. Key: PBKDF2-SHA256 over the password (600,000 rounds, a salt from
// config.json) → AES-256-GCM. Sealed layout: "CCS1" + 12-byte IV + ciphertext with its 16-byte tag.
const subtle = globalThis.crypto.subtle;
export const MAGIC = [0x43, 0x43, 0x53, 0x31]; // "CCS1"
export const ITERATIONS = 600000;

export function toBase64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
export function fromBase64(b64) {
  const s = atob(b64); const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}
export const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
export const fromHex = (hex) => new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
export const randomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export async function deriveKey(password, saltBase64, iterations = ITERATIONS) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: fromBase64(saltBase64), iterations }, base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
export async function exportKeyHex(key) { return toHex(new Uint8Array(await subtle.exportKey("raw", key))); }
export async function importKeyHex(hex) {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("the key must be 64 hex characters");
  return subtle.importKey("raw", fromHex(hex), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}

export async function seal(key, bytes) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, bytes));
  const out = new Uint8Array(4 + 12 + ct.length);
  out.set(MAGIC, 0); out.set(iv, 4); out.set(ct, 16);
  return out;
}
export async function open(key, sealed) {
  if (sealed.length < 4 + 12 + 16 || MAGIC.some((b, i) => sealed[i] !== b)) throw new Error("not a sealed file");
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: sealed.subarray(4, 16) }, key, sealed.subarray(16)));
  } catch { throw new Error("wrong password (or a damaged file)"); }
}
export const sealText = (key, text) => seal(key, new TextEncoder().encode(text));
export const openText = async (key, sealed) => new TextDecoder().decode(await open(key, sealed));
