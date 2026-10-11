#!/usr/bin/env node
// tools/widevine-key.mjs — asks Google's Widevine UAT key server for a content key, signed with the
// PUBLIC test credentials (signer "widevine_test", the ones in the shaka-packager documentation).
// Test-only: the matching licence proxy (cwip-shaka-proxy.appspot.com/no_auth) hands this key to any
// player that presents the PSSH, so the key protects nothing; it exercises the phone's protected
// video path, which is what route 1 measures. A real deployment signs with CCS's own credentials
// and binds each licence to the viewer's session.
// Runs on a GitHub runner (the authoring sandbox cannot reach the key server). Writes
// web/research/drm/widevine-key.json: content id, the SD track's key id and key (hex), the PSSH.
//   node tools/widevine-key.mjs <content-id>
import { createHash, createCipheriv } from "node:crypto";
import { writeFile, mkdir } from "node:fs/promises";

const contentId = process.argv[2] || "ccs-proof-drm-1";
const KEY_SERVER = "https://license.uat.widevine.com/cenc/getcontentkey/widevine_test";
const SIGNER = "widevine_test";
const AES_KEY = Buffer.from("1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9", "hex");   // 32 bytes: AES-256-CBC
const AES_IV = Buffer.from("d58ce954203b7c9a9a9d467f59839249", "hex");

// CommonEncryptionRequest as JSON (bytes fields base64); signature = AES-CBC(PKCS#5) of SHA-1(request),
// exactly as shaka-packager's AesRequestSigner does it.
const request = JSON.stringify({
  content_id: Buffer.from(contentId).toString("base64"),
  policy: "",
  tracks: [{ type: "SD" }, { type: "HD" }],
  drm_types: ["WIDEVINE"],
  protection_scheme: "CENC",
});
const digest = createHash("sha1").update(request).digest();
const cipher = createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
const signature = Buffer.concat([cipher.update(digest), cipher.final()]);
const body = JSON.stringify({ request: Buffer.from(request).toString("base64"), signature: signature.toString("base64"), signer: SIGNER });

const res = await fetch(KEY_SERVER, { method: "POST", headers: { "Content-Type": "application/json" }, body });
const text = await res.text();
console.log(`key server: HTTP ${res.status}, ${text.length} bytes`);
if (!res.ok) { console.error(text); process.exit(1); }
const outer = JSON.parse(text);
const inner = JSON.parse(Buffer.from(outer.response, "base64").toString("utf8"));
console.log(`status: ${inner.status}; tracks: ${(inner.tracks || []).map((t) => t.type).join(", ") || "none"}`);
if (inner.status !== "OK" && inner.status !== 0) { console.error(JSON.stringify(inner, null, 2)); process.exit(1); }

const tracks = (inner.tracks || []).map((t) => {
  const keyId = Buffer.from(t.key_id || t.keyId, "base64"), key = Buffer.from(t.key, "base64");
  const pssh = (t.pssh || [])[0] || {};
  return { type: t.type, keyId: keyId.toString("hex"), key: key.toString("hex"), psshData: pssh.data || null, psshBoxes: pssh.boxes || null };
});
const out = { contentId, keyServer: KEY_SERVER, licenseProxy: "https://cwip-shaka-proxy.appspot.com/no_auth", signer: SIGNER, status: inner.status, tracks, fetchedAt: new Date().toISOString(),
  note: "Test-only key from Google's Widevine UAT server with the public test signer; the licence proxy issues it to anyone. It exercises the protected video path and protects nothing." };
await mkdir("web/research/drm", { recursive: true });
await writeFile("web/research/drm/widevine-key.json", JSON.stringify(out, null, 2) + "\n");
for (const t of tracks) console.log(`${t.type}: key id ${t.keyId}, pssh data ${t.psshData ? Buffer.from(t.psshData, "base64").length : 0} bytes, boxes ${t.psshBoxes ? Buffer.from(t.psshBoxes, "base64").length : 0} bytes`);
