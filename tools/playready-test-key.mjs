// Derives the content key that Microsoft's PUBLIC PlayReady test server
// (test.playready.microsoft.com) issues for a key id, from Microsoft's published test key seed.
// Same algorithm as Bento4's DerivePlayReadyKey (mp4utils.py). The seed is public, so every key
// derived here is public too: test content only, never anything private.
//
//   node tools/playready-test-key.mjs <kid-hex-32>        prints the key
//   node tools/playready-test-key.mjs --self-test          checks the known pair used by route 1
import { createHash } from "node:crypto";

const TEST_KEY_SEED_B64 = "XVBovsmzhP9gRIZxWfFta3VVRPzVEWmJsazEJ46I";

export function derivePlayReadyTestKey(kidHex) {
  if (!/^[0-9a-fA-F]{32}$/.test(kidHex)) throw new Error("the key id must be 32 hex characters");
  const k = Buffer.from(kidHex, "hex");
  // the server reads the key id as a GUID: the first three fields are little-endian
  const kid = Buffer.concat([Buffer.from([k[3], k[2], k[1], k[0], k[5], k[4], k[7], k[6]]), k.subarray(8)]);
  const seed = Buffer.from(TEST_KEY_SEED_B64, "base64").subarray(0, 30);
  const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
  const a = sha(seed, kid), b = sha(seed, kid, seed), c = sha(seed, kid, seed, kid);
  const key = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) key[i] = a[i] ^ a[i + 16] ^ b[i] ^ b[i + 16] ^ c[i] ^ c[i + 16];
  return key.toString("hex");
}

import { pathToFileURL } from "node:url";
// The command-line part runs only when this file is the program, never when it is imported.
const arg = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href ? process.argv[2] : undefined;
if (arg === "--self-test") {
  // the photo's key id and the key the test server issued for it (route 1, 2026-10-11)
  const got = derivePlayReadyTestKey("9e0ffaba46a81decdc6fce6f0cafa51a");
  const want = "40e5f649ceffefbda90b977272f3d2d3";
  console.log(got === want ? `self-test ok: ${got}` : `SELF-TEST FAILED: got ${got}, want ${want}`);
  process.exit(got === want ? 0 : 1);
} else if (arg) {
  console.log(derivePlayReadyTestKey(arg));
}
