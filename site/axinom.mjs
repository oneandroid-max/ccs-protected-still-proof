// FairPlay licences for the test site, through Axinom's evaluation DRM service: the job (never the
// browser) mints one licence token per protected output, signed with the evaluation account's
// communication key, carrying that output's content key encrypted for Axinom. The token is then sealed
// under the picture key like every other output, so only someone with the site's password can ask for
// a licence. The method follows Axinom's own quick start (github.com/Axinom/drm-quick-start,
// EntitlementService.js): AES-256-CBC without padding under the communication key, the IV being the key
// id's bytes, and an HS256 JWT. Node only (the job), no outside packages.
import { createCipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";

// Axinom's FairPlay licence service and its evaluation FairPlay certificate (issued by Apple to
// "FairPlay Streaming: Axinom GmbH", valid to 2026-11-30, read on a runner by apple-probe.yml).
export const AXINOM_FAIRPLAY_LICENSE = "https://drm-fairplay-licensing.axprod.net/AcquireLicense";
export const AXINOM_FAIRPLAY_CERT = "https://tools.axinom.com/FPScert/fairplay.cer";
// An Axinom FairPlay licence address: the shared one above, or an environment's own, which carries the
// environment's tenant prefix (https://<prefix>.drm-fairplay-licensing.axprod.net/AcquireLicense, as its DRM
// Service page shows it; Axinom: "use the URLs exactly as shown"). A page sends a token to no other host: the
// route-1 page and the Apple check page carry this same pattern (the tests compare them).
export const FAIRPLAY_LICENSE_ADDRESS = /^https:\/\/(?:[a-z0-9][a-z0-9-]{0,62}\.)?drm-fairplay-licensing\.axprod\.net\/AcquireLicense$/;
// The account's own settings, committed in site/axinom.json (public by nature: Safari asks the licence address
// in the open): its FairPlay licence address. Without the file, the shared address; anything that is not an
// Axinom FairPlay licence address is refused with a plain message.
export async function readAxinomSettings(siteDir) {
  let raw;
  try { raw = await fs.readFile(join(siteDir, "axinom.json"), "utf8"); } catch { return { fairplayLicense: AXINOM_FAIRPLAY_LICENSE }; }
  let settings;
  try { settings = JSON.parse(raw); } catch { throw new Error("site/axinom.json is not readable JSON"); }
  if (!settings || typeof settings !== "object" || Array.isArray(settings)) throw new Error("site/axinom.json is not an object of settings");
  if (!("fairplayLicense" in settings)) return { fairplayLicense: AXINOM_FAIRPLAY_LICENSE }; // only a missing setting means the shared address
  const fairplayLicense = settings.fairplayLicense;
  if (typeof fairplayLicense !== "string" || !FAIRPLAY_LICENSE_ADDRESS.test(fairplayLicense)) throw new Error("site/axinom.json names a FairPlay licence address that is not one of Axinom's (https://<prefix>.drm-fairplay-licensing.axprod.net/AcquireLicense)");
  return { fairplayLicense };
}

// Whether Axinom's licence service accepts a token's key id and signature, asked from anywhere (a runner, no
// Apple device): a licence request carrying the token and a dummy body. Axinom reads the token before the body,
// so its answer (header X-AxDRM-ErrorMessage, HTTP 400 or 403) complains about the request when the key id and
// the signature are good, and about the token when not. Measured 2026-10-11 17:15Z and 18:03Z, at the account's
// address and the shared one alike, with Axinom's public token, the same token signed with another key, and one
// naming an unknown key id:
//   good:           "Invalid license request. …" (the body missing at 0 bytes, too short below 176, "Supported
//                   versions are 1, 2 or 3, but used version is 0." at 176 and above)
//   another key:    "Invalid DRM message. The signature is invalid." (at every size from 0 to 400 bytes)
//   unknown key id: "License denied. The DRM message references the ID of an unknown communication key."
// Only one of the measured answers about the request counts as accepted ("Invalid license request." also opens an
// answer about the token's header, which is not: the seventh review). It proves the key pair, and nothing else:
// not the address (a made-up prefix answers the same way), not the rest of the token's message, which Axinom reads
// after a device's request. A device has the last word. Something that is not a token is never sent. Each try
// has its own time limit; no answer, or a server error (HTTP 5xx, 429), is retried, then reported as Axinom out
// of reach, never as a refusal.
export const TOKEN_CHECK_BODY_BYTES = 176;
export const TOKEN_CHECK_TIMEOUT_MS = 20000;
export const TOKEN_ACCEPTED = /^Invalid license request\. (The request body is missing\.|License request total size is less than the expected header size\.|Supported versions are 1, 2 or 3, but used version is 0\.)$/;
const TOKEN_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
export async function checkTokenWithAxinom(token, license, fetchFn = fetch, { tries = 3, pause = (ms) => new Promise((r) => setTimeout(r, ms)), timeoutMs = TOKEN_CHECK_TIMEOUT_MS } = {}) {
  if (!FAIRPLAY_LICENSE_ADDRESS.test(String(license))) throw new Error("the FairPlay licence address is not one of Axinom's");
  if (!TOKEN_SHAPE.test(String(token))) return { accepted: false, reached: false, status: 0, message: "that is not a licence token: nothing was sent" };
  let last = null;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetchFn(license, { method: "POST", headers: { "X-AxDRM-Message": token, "Content-Type": "application/octet-stream" }, body: new Uint8Array(TOKEN_CHECK_BODY_BYTES), signal: AbortSignal.timeout(timeoutMs) });
      if (r.status >= 500 || r.status === 429) throw new Error(`Axinom answered HTTP ${r.status}`);
      const message = String(r.headers.get("x-axdrm-errormessage") || "").trim();
      return { accepted: TOKEN_ACCEPTED.test(message), reached: true, status: r.status, message: message || `no message (HTTP ${r.status})` };
    } catch (e) { last = e; if (i + 1 < tries) await pause(2000 * 2 ** i); }
  }
  const why = last && last.cause && last.cause.message ? last.cause.message : String((last && last.message) || last);
  return { accepted: false, reached: false, status: 0, message: `Axinom could not be reached (${tries} tries): ${why}` };
}
// Whether Axinom accepts this communication key: a token for a throwaway key, asked as above.
export const checkKeyWithAxinom = (com, fetchFn = fetch, opts) => { const ids = newFairPlayIds(); return checkTokenWithAxinom(mintToken(com, ids.kid, ids.key), com.license || AXINOM_FAIRPLAY_LICENSE, fetchFn, opts); };

// Whether a token was signed with this communication key (HS256 under the key's 32 bytes).
export function tokenSignedWith(token, key) {
  const [head, body, sig] = String(token).split(".");
  if (!head || !body || !sig) return false;
  const want = createHmac("sha256", key).update(`${head}.${body}`).digest(), got = Buffer.from(sig, "base64url");
  return got.length === want.length && timingSafeEqual(got, want);
}
// A short check value of a communication key (16 hex of HMAC-SHA256 under the key, of a fixed label): it tells
// whether a form's token was made with the key now set when the token itself is sealed. It reveals no more about
// the key than a token's own signature does.
export const comKeyCheck = (com) => createHmac("sha256", com.key).update("ccs-proof communication key check").digest("hex").slice(0, 16);

// Axinom's PUBLIC test key: the content key of its own public FairPlay test stream ("v10 HLS H264
// single key"), published with a licence token that never expires, in github.com/Axinom/public-test-vectors
// (ContentKeys/Axinom-Encoding-Dash-Hls-H264-protected-SingleKey.txt; the token is the AXINOM_PUBLIC_TOKEN
// of web/research/drm/index.html and the TOKEN of web/research/apple/index.html, checked equal by the
// tests). Anyone can decrypt with it, so it protects ONLY the public test card (tools/fairplay-card.mjs),
// never a picture of the owner's.
export const AXINOM_PUBLIC_TEST = {
  kid: "4060a865887842679cbf91ae5bae1e72",
  key: Buffer.from("/DU0CDcxDMD7U96X4ipp4A==", "base64").toString("hex"),
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

// A key id in the GUID text form Axinom uses, from 16 bytes in order (no byte swapping).
export const kidToUuid = (hex) => `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`.toLowerCase();

// The communication key, from the two values the evaluation account shows: an id (GUID) and a
// base64 key of 32 bytes. The id is kept exactly as given (Axinom compares it with its own record).
// With it, the account's FairPlay licence address (readAxinomSettings), which every Apple form made with
// this key records. Throws with a plain message when any is missing or malformed; the message never
// carries a key's value.
export function readCommunicationKey(id, keyB64, license = AXINOM_FAIRPLAY_LICENSE) {
  if (!id || !keyB64) throw new Error("the Axinom communication key is not set (AXINOM_COM_KEY_ID and AXINOM_COM_KEY)");
  const given = String(id).trim();
  if (!UUID.test(given.toLowerCase())) throw new Error("AXINOM_COM_KEY_ID is not a GUID");
  const key = Buffer.from(String(keyB64).trim(), "base64");
  if (key.length !== 32) throw new Error(`AXINOM_COM_KEY must be 32 bytes in base64 (got ${key.length})`);
  if (!FAIRPLAY_LICENSE_ADDRESS.test(String(license))) throw new Error("the FairPlay licence address is not one of Axinom's");
  return { id: given, key, license: String(license) };
}

// The content key encrypted for Axinom: AES-256-CBC, no padding, the IV being the key id's 16 bytes.
export function encryptContentKey(comKey, kidHex, keyHex) {
  if (!/^[0-9a-f]{32}$/.test(kidHex) || !/^[0-9a-f]{32}$/.test(keyHex)) throw new Error("key id and key must be 32 hex characters");
  const c = createCipheriv("aes-256-cbc", comKey, Buffer.from(kidHex, "hex"));
  c.setAutoPadding(false);
  return Buffer.concat([c.update(Buffer.from(keyHex, "hex")), c.final()]).toString("base64");
}

// One licence token for one content key, shaped exactly as Axinom's quick start shapes it (envelope:
// version, com_key_id, message, begin_date, expiration_date; the key naming "Policy A" and the policy
// defined), with its values hardened where the quick start relaxes them "as permissive as possible for
// the scope of this guide": licences are not kept on the device (allow_persistence false), PlayReady gets
// hardware clients only (min_device_security_level 3000, no play enabler for virtual machines) instead of
// any client (150), and Widevine hardware clients only (device_security_level HW_SECURE_ALL: the decoding
// in protected hardware), so a software client of either can never be handed the key. The SHAPE is the one
// every Axinom example in reach uses (the 13 tokens of its public test vectors and quick start all name and
// define "Policy A"); only the values differ. Axinom honours one token on all of its licence services, which
// is why the other two are restricted; the FairPlay section is left at Axinom's defaults (HDCP type 0 on
// cable outputs, AirPlay and cable adapters allowed) until a device measurement and the owner decide it
// (docs.axinom.com/services/drm/license-service/entitlement-message/content-key-usage-policies, read on a
// runner by apple-probe.yml).
// Valid from a day before `now` (clock drift) for `days` days; the job renews it before it runs out.
export function mintToken(com, kidHex, keyHex, { now = new Date(), days = 60 } = {}) {
  const from = new Date(now.getTime() - 24 * 3600 * 1000), to = new Date(now.getTime() + days * 24 * 3600 * 1000);
  const payload = {
    version: 1,
    com_key_id: com.id,
    begin_date: from.toISOString(),
    expiration_date: to.toISOString(),
    message: {
      type: "entitlement_message",
      version: 2,
      license: { start_datetime: from.toISOString(), expiration_datetime: to.toISOString(), allow_persistence: false },
      content_keys_source: { inline: [{ id: kidToUuid(kidHex), encrypted_key: encryptContentKey(com.key, kidHex, keyHex), usage_policy: "Policy A" }] },
      content_key_usage_policies: [{ name: "Policy A", playready: { min_device_security_level: 3000 }, widevine: { device_security_level: "HW_SECURE_ALL" } }],
    },
  };
  const head = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" })), body = b64url(JSON.stringify(payload));
  const sig = b64url(createHmac("sha256", com.key).update(`${head}.${body}`).digest());
  return `${head}.${body}.${sig}`;
}

// Fresh FairPlay protection for one output: a key id, a key and the constant IV that cbcs encryption
// uses, and the key address the playlist carries, in the form Axinom's own playlists use
// ("skd://<key id GUID>:<IV in upper-case hex>", read on a runner by apple-probe.yml); Axinom's licence
// returns the key with that IV.
export function newFairPlayIds() {
  const kid = randomBytes(16).toString("hex"), key = randomBytes(16).toString("hex"), iv = randomBytes(16).toString("hex");
  return { kid, key, iv, keyUri: `skd://${kidToUuid(kid)}:${iv.toUpperCase()}` };
}
