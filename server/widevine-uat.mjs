// signAndForward(cfg, { challenge, contentId, policy }) → { status, licence, device, raw }
//
// The one call to the Widevine licence environment: sign the request with our signer, forward the
// phone's challenge, parse the answer. Node 22 and Cloudflare Workers: Fetch API + WebCrypto only,
// no dependencies.
//
// The protocol, as measured live against https://license.uat.widevine.com/cenc/getlicense/widevine_test
// on 2026-10-13 (scratchpad licsrv-research/live/*) and as implemented by Shaka Packager
// (packager/media/base/request_signer.cc, widevine_key_source.cc, widevine_common_encryption.proto)
// and by public proxies (exe12356/widevine-proxy, jt-seo/WidevineProxy, alfg/widevine,
// TranHanHieu/license-proxy-widevine):
//
//   POST <licenseUrl>            content-type: application/json
//   { "request":   base64( innerJson ),
//     "signature": base64( AES-256-CBC(key, iv, PKCS#5( SHA-1(innerJson) )) ),
//     "signer":    "<signer>" }
//
//   innerJson = { "payload":             base64(challenge bytes from the CDM),
//                 "content_id":          base64(content id bytes),
//                 "provider":            "<signer>",
//                 "allowed_track_types": "SD_HD",
//                 "policy_overrides":    { "can_play": true, "license_duration_seconds": N } }
//
//   answer (flat JSON, HTTP 200 even on refusal):
//     status           "OK" | "SIGNATURE_FAILED" | "INVALID_LICENSE_CHALLENGE" | "MALFORMED_REQUEST" | ...
//     status_message   text (may be absent)
//     license          base64 SignedMessage bytes — only when status is OK
//     message_type     "SERVICE_CERTIFICATE" (for the 08 04 challenge) | "LICENSE"
//     make, model, security_level, drm_cert_serial_number, platform_verification_status, ...
//                      present once the challenge carried a client identity (not for the certificate request)
//
// The 08 04 challenge (SignedMessage{type: SERVICE_CERTIFICATE_REQUEST}) goes through the same call;
// the environment answers it with status OK and the type-5 SERVICE_CERTIFICATE in "license".

const enc = new TextEncoder();
const dec = new TextDecoder();

export function toBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
export function fromBase64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function fromHex(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new Error("widevine-uat: key/iv must be hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// signature = AES-CBC(key, iv, PKCS#5(SHA-1(message))). WebCrypto's AES-CBC always applies
// PKCS#7 padding, which is PKCS#5 for the 16-byte AES block (request_signer.cc: AesCbcEncryptor
// with kPkcs5Padding and kUseConstantIv over the mbedtls SHA-1 of the message).
export async function signMessage(message, keyHex, ivHex) {
  const digest = await crypto.subtle.digest("SHA-1", enc.encode(message));
  const key = await crypto.subtle.importKey("raw", fromHex(keyHex), { name: "AES-CBC" }, false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv: fromHex(ivHex) }, key, digest));
}

export function buildMessage(cfg, { challenge, contentId, policy }) {
  const inner = {
    payload: toBase64(challenge),
    content_id: toBase64(contentId),
    provider: cfg.signer,
    allowed_track_types: "SD_HD",
  };
  const seconds = policy && Number(policy.licenceDurationSeconds);
  if (Number.isFinite(seconds) && seconds > 0) inner.policy_overrides = { can_play: true, license_duration_seconds: Math.floor(seconds) };
  return JSON.stringify(inner);
}

// The serial comes back as base64 of the hex text of the serial; give the hex text when that is
// what it is, otherwise the value as received.
function certSerial(v) {
  if (typeof v !== "string" || !v) return null;
  try {
    const text = dec.decode(fromBase64(v));
    return /^[0-9a-f]+$/i.test(text) ? text.toLowerCase() : v;
  } catch (e) { return v; }
}

export async function signAndForward(cfg, { challenge, contentId, policy }, deps = {}) {
  if (!cfg || !cfg.licenseUrl || !cfg.signer || !cfg.keyHex || !cfg.ivHex) throw new Error("widevine-uat: cfg needs licenseUrl, signer, keyHex, ivHex");
  if (!(challenge instanceof Uint8Array) || challenge.length === 0) throw new Error("widevine-uat: challenge must be a non-empty Uint8Array");
  if (!(contentId instanceof Uint8Array)) throw new Error("widevine-uat: contentId must be a Uint8Array");
  const doFetch = deps.fetch || fetch;

  const message = buildMessage(cfg, { challenge, contentId, policy });
  const signature = await signMessage(message, cfg.keyHex, cfg.ivHex);
  const body = JSON.stringify({ request: toBase64(enc.encode(message)), signature: toBase64(signature), signer: cfg.signer });

  const res = await doFetch(cfg.licenseUrl, { method: "POST", headers: { "content-type": "application/json" }, body });
  const text = await res.text();
  if (res.status !== 200) throw new Error("widevine-uat: licence environment answered HTTP " + res.status + ": " + text.slice(0, 200));
  let raw;
  try { raw = JSON.parse(text); } catch (e) { throw new Error("widevine-uat: licence environment answered non-JSON: " + text.slice(0, 200)); }

  const status = typeof raw.status === "string" ? raw.status : "NO_STATUS";
  const licence = status === "OK" && typeof raw.license === "string" && raw.license ? fromBase64(raw.license) : null;
  const hasDevice = typeof raw.make === "string" || typeof raw.model === "string" || typeof raw.security_level === "number" || typeof raw.drm_cert_serial_number === "string";
  // Everything else the environment reported (platform, platform_verification_status, system_id,
  // client_info, supported_tracks, ...) stays available in `raw`.
  const device = hasDevice
    ? {
        securityLevel: typeof raw.security_level === "number" ? raw.security_level : null,
        make: raw.make || null,
        model: raw.model || null,
        certSerial: certSerial(raw.drm_cert_serial_number),
      }
    : null;
  return { status, statusMessage: raw.status_message || "", messageType: raw.message_type || null, licence, device, raw };
}
