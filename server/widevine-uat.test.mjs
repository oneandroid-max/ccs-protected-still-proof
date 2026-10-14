// node --test server/widevine-uat.test.mjs
// The signing and parsing of the licence-environment call, against values measured live on
// 2026-10-13 (the signature below was produced by WebCrypto and by openssl independently and was
// accepted by https://license.uat.widevine.com/cenc/getlicense/widevine_test with status OK).
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildMessage, signAndForward, signMessage, toBase64 } from "./widevine-uat.mjs";

const CFG = { licenseUrl: "https://license.uat.widevine.com/cenc/getlicense/widevine_test", signer: "widevine_test", keyHex: "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9", ivHex: "d58ce954203b7c9a9a9d467f59839249" };
const CERT_REQUEST = new Uint8Array([0x08, 0x04]);

test("signature: AES-256-CBC over PKCS#5(SHA-1(message)) with the test key/iv matches the measured value", async () => {
  const sig = await signMessage('{"payload":"CAQ="}', CFG.keyHex, CFG.ivHex);
  assert.equal(toBase64(sig), "shlE/X0IKTDQ7BMSreF1T7NdMLAedpTR4N79I6Lz2/E=");
});

test("message: payload and content id base64, provider, SD_HD, policy only when a duration is set", () => {
  const m = JSON.parse(buildMessage(CFG, { challenge: CERT_REQUEST, contentId: new TextEncoder().encode("ccs-proof-pin48213"), policy: { licenceDurationSeconds: 600 } }));
  assert.deepEqual(m, { payload: "CAQ=", content_id: "Y2NzLXByb29mLXBpbjQ4MjEz", provider: "widevine_test", allowed_track_types: "SD_HD", policy_overrides: { can_play: true, license_duration_seconds: 600 } });
  const none = JSON.parse(buildMessage(CFG, { challenge: CERT_REQUEST, contentId: new Uint8Array(0), policy: {} }));
  assert.equal(none.policy_overrides, undefined);
});

function fakeFetch(status, body, seen) {
  return async (url, init) => { seen.push({ url, init }); return { status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) }; };
}

test("forward: posts the signed outer JSON and returns licence bytes plus device facts on OK", async () => {
  const seen = [];
  const res = await signAndForward(CFG, { challenge: CERT_REQUEST, contentId: new Uint8Array(0), policy: {} }, { fetch: fakeFetch(200, { status: "OK", message_type: "LICENSE", license: toBase64(new Uint8Array([8, 2, 9])), make: "samsung", model: "SM-X", security_level: 1, drm_cert_serial_number: btoa("abcd1234") }, seen) });
  assert.equal(seen[0].url, CFG.licenseUrl);
  assert.equal(seen[0].init.method, "POST");
  assert.equal(seen[0].init.headers["content-type"], "application/json");
  const outer = JSON.parse(seen[0].init.body);
  assert.deepEqual(Object.keys(outer).sort(), ["request", "signature", "signer"]);
  assert.equal(outer.signer, "widevine_test");
  assert.equal(atob(outer.request), '{"payload":"CAQ=","content_id":"","provider":"widevine_test","allowed_track_types":"SD_HD"}');
  assert.equal(res.status, "OK");
  assert.deepEqual(res.licence, new Uint8Array([8, 2, 9]));
  assert.deepEqual(res.device, { securityLevel: 1, make: "samsung", model: "SM-X", certSerial: "abcd1234" });
});

test("forward: a refusal is a status with no licence; the certificate answer has no device; non-200 and non-JSON throw", async () => {
  const refused = await signAndForward(CFG, { challenge: CERT_REQUEST, contentId: new Uint8Array(0) }, { fetch: fakeFetch(200, { status: "SIGNATURE_FAILED", status_message: "Signature verification failed" }, []) });
  assert.equal(refused.status, "SIGNATURE_FAILED");
  assert.equal(refused.licence, null);
  assert.equal(refused.statusMessage, "Signature verification failed");
  const cert = await signAndForward(CFG, { challenge: CERT_REQUEST, contentId: new Uint8Array(0) }, { fetch: fakeFetch(200, { status: "OK", message_type: "SERVICE_CERTIFICATE", license: toBase64(new Uint8Array([8, 5])) }, []) });
  assert.equal(cert.device, null);
  assert.equal(cert.messageType, "SERVICE_CERTIFICATE");
  await assert.rejects(signAndForward(CFG, { challenge: CERT_REQUEST, contentId: new Uint8Array(0) }, { fetch: fakeFetch(503, "down", []) }), /HTTP 503/);
  await assert.rejects(signAndForward(CFG, { challenge: CERT_REQUEST, contentId: new Uint8Array(0) }, { fetch: fakeFetch(200, "<html>", []) }), /non-JSON/);
});
