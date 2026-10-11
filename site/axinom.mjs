// FairPlay licences for the test site, through Axinom's evaluation DRM service: the job (never the
// browser) mints one licence token per protected output, signed with the evaluation account's
// communication key, carrying that output's content key encrypted for Axinom. The token is then sealed
// under the picture key like every other output, so only someone with the site's password can ask for
// a licence. The method follows Axinom's own quick start (github.com/Axinom/drm-quick-start,
// EntitlementService.js): AES-256-CBC without padding under the communication key, the IV being the key
// id's bytes, and an HS256 JWT. Node only (the job), no outside packages.
import { createCipheriv, createHmac, randomBytes } from "node:crypto";

// Axinom's FairPlay licence service and its evaluation FairPlay certificate (issued by Apple to
// "FairPlay Streaming: Axinom GmbH", valid to 2026-11-30, read on a runner by apple-probe.yml).
export const AXINOM_FAIRPLAY_LICENSE = "https://drm-fairplay-licensing.axprod.net/AcquireLicense";
export const AXINOM_FAIRPLAY_CERT = "https://tools.axinom.com/FPScert/fairplay.cer";

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
// Throws with a plain message when either is missing or malformed; the message never carries a value.
export function readCommunicationKey(id, keyB64) {
  if (!id || !keyB64) throw new Error("the Axinom communication key is not set (AXINOM_COM_KEY_ID and AXINOM_COM_KEY)");
  const given = String(id).trim();
  if (!UUID.test(given.toLowerCase())) throw new Error("AXINOM_COM_KEY_ID is not a GUID");
  const key = Buffer.from(String(keyB64).trim(), "base64");
  if (key.length !== 32) throw new Error(`AXINOM_COM_KEY must be 32 bytes in base64 (got ${key.length})`);
  return { id: given, key };
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
