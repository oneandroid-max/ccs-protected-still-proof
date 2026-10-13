// signAndForward(cfg, { challenge, contentId, policy }) → { status, licence, device, raw }
//
// NOT YET IMPLEMENTED. The request format of Google's Widevine licence environment is being
// established by live measurement from the sandbox before any line of it is written here, so that
// nothing in this file is guessed. Until then every call throws, the core returns 502, and the
// tests exercise the core with an injected stand-in (server/test.mjs).
export async function signAndForward() {
  throw new Error("widevine-uat: not implemented yet (protocol measurement pending)");
}
