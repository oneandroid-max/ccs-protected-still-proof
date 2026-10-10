/* proofcore.c — see proofcore.h. Written for this proof; no library behind it. */
#include "proofcore.h"
#include <string.h>
#include <stdio.h>

/* ---- SHA-256 ---- */
static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
  uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
  int i;
  for (i = 0; i < 16; i++) w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
  for (i = 16; i < 64; i++) {
    uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
    uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
  for (i = 0; i < 64; i++) {
    uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
    uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
    t1 = h + S1 + ch + K[i] + w[i];
    t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
  }
  c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}
void sha256_init(sha256_ctx *c) {
  static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
  memcpy(c->h, iv, sizeof iv); c->len = 0; c->buflen = 0;
}
void sha256_update(sha256_ctx *c, const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  c->len += len;
  if (c->buflen) {
    size_t take = 64 - c->buflen; if (take > len) take = len;
    memcpy(c->buf + c->buflen, p, take); c->buflen += take; p += take; len -= take;
    if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
  }
  while (len >= 64) { sha256_block(c, p); p += 64; len -= 64; }
  if (len) { memcpy(c->buf, p, len); c->buflen = len; }
}
void sha256_final(sha256_ctx *c, uint8_t out[32]) {
  uint64_t bits = c->len * 8; int i;
  uint8_t pad = 0x80;
  sha256_update(c, &pad, 1);
  { uint8_t z = 0; while (c->buflen != 56) sha256_update(c, &z, 1); }
  { uint8_t lenb[8]; for (i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i)); sha256_update(c, lenb, 8); }
  for (i = 0; i < 8; i++) { out[i*4] = (uint8_t)(c->h[i] >> 24); out[i*4+1] = (uint8_t)(c->h[i] >> 16); out[i*4+2] = (uint8_t)(c->h[i] >> 8); out[i*4+3] = (uint8_t)c->h[i]; }
}
void sha256(const void *data, size_t len, uint8_t out[32]) { sha256_ctx c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out); }

/* ---- HMAC ---- */
void hmac_sha256_init(hmac_ctx *h, const uint8_t *key, size_t keylen) {
  uint8_t k[64], pad[64]; int i;
  memset(k, 0, 64);
  if (keylen > 64) sha256(key, keylen, k); else memcpy(k, key, keylen);
  for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
  sha256_init(&h->inner); sha256_update(&h->inner, pad, 64);
  for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
  sha256_init(&h->outer); sha256_update(&h->outer, pad, 64);
  memset(k, 0, 64); memset(pad, 0, 64);
}
void hmac_sha256_compute(const hmac_ctx *h, const uint8_t *msg, size_t msglen, uint8_t out[32]) {
  sha256_ctx c = h->inner; uint8_t t[32];
  sha256_update(&c, msg, msglen); sha256_final(&c, t);
  c = h->outer; sha256_update(&c, t, 32); sha256_final(&c, out);
}

/* ---- PBKDF2 ---- */
void pbkdf2_hmac_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t iterations, uint8_t *out, size_t dklen) {
  hmac_ctx h; uint32_t block = 1; size_t done = 0;
  hmac_sha256_init(&h, pw, pwlen);
  while (done < dklen) {
    uint8_t u[32], t[32], msg[256]; uint32_t j; int k; size_t take;
    memcpy(msg, salt, saltlen);
    msg[saltlen] = (uint8_t)(block >> 24); msg[saltlen+1] = (uint8_t)(block >> 16); msg[saltlen+2] = (uint8_t)(block >> 8); msg[saltlen+3] = (uint8_t)block;
    hmac_sha256_compute(&h, msg, saltlen + 4, u); memcpy(t, u, 32);
    for (j = 1; j < iterations; j++) { hmac_sha256_compute(&h, u, 32, u); for (k = 0; k < 32; k++) t[k] ^= u[k]; }
    take = dklen - done; if (take > 32) take = 32;
    memcpy(out + done, t, take); done += take; block++;
  }
}

/* ---- CCSP1 ---- */
int ccsp1_parse(const uint8_t *file, size_t len, ccsp1_header *h) {
  if (len < 38 + 16) return 0;
  if (memcmp(file, "CCSP1", 5) != 0 || file[5] != 1) return 0;
  h->iterations = ((uint32_t)file[6] << 24) | ((uint32_t)file[7] << 16) | ((uint32_t)file[8] << 8) | file[9];
  if (h->iterations == 0) return 0;
  h->salt = file + 10; h->iv = file + 26; h->ciphertext = file + 38; h->ciphertext_len = len - 38;
  return 1;
}
void ccsp1_derive_key(const char *secret, const char *pin, const ccsp1_header *h, uint8_t key[32]) {
  char pw[512]; size_t n;
  n = (size_t)snprintf(pw, sizeof pw, "%s:%s", secret, pin);
  if (n >= sizeof pw) n = sizeof pw - 1;
  pbkdf2_hmac_sha256((const uint8_t *)pw, n, h->salt, 16, h->iterations, key, 32);
  memset(pw, 0, sizeof pw);
}

/* ---- The mark (identical to mark.js and ProofMark.java) ---- */
void mark_seed(const char *secret, const char *pin, const char *hour, uint8_t seed[32]) {
  char s[640]; int n = snprintf(s, sizeof s, "ccs-mark-v1:%s:%s:%s", secret, pin, hour);
  if (n < 0) n = 0;
  if ((size_t)n >= sizeof s) n = (int)sizeof s - 1;
  sha256(s, (size_t)n, seed);
}
static uint32_t rd32(const uint8_t *b) { return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3]; }
void mark_tile_pattern(const uint8_t seed[32], int8_t pattern[MARK_TILE * MARK_TILE]) {
  uint32_t x = rd32(seed), y = rd32(seed + 4), z = rd32(seed + 8), w = rd32(seed + 12); int i;
  if (!x) x = 0x9e3779b9u;
  if (!y) y = 0x243f6a88u;
  if (!z) z = 0xb7e15162u;
  if (!w) w = 0x6a09e667u;
  for (i = 0; i < MARK_TILE * MARK_TILE; i++) {
    uint32_t t = x ^ (x << 11);
    x = y; y = z; z = w;
    w = (w ^ (w >> 19)) ^ (t ^ (t >> 8));
    pattern[i] = ((w >> 16) & 1) ? 1 : -1;
  }
}
void mark_id(const uint8_t seed[32], char out[9]) { hex_encode(seed, 4, out); }
static uint8_t clamp8(int v) { return (uint8_t)(v < 0 ? 0 : (v > 255 ? 255 : v)); }
void mark_apply(uint8_t *px, int w, int h, int stride_bytes, int offR, int offG, int offB, const int8_t *pattern) {
  int x, y;
  for (y = 0; y < h; y++) {
    const int8_t *row = pattern + (y % MARK_TILE) * MARK_TILE;
    uint8_t *p = px + (size_t)y * (size_t)stride_bytes;
    for (x = 0; x < w; x++, p += 4) {
      int m = MARK_AMPLITUDE * row[x % MARK_TILE];
      p[offR] = clamp8(p[offR] + m); p[offG] = clamp8(p[offG] + m); p[offB] = clamp8(p[offB] + m);
    }
  }
}
void hex_encode(const uint8_t *in, size_t len, char *out) {
  static const char *hx = "0123456789abcdef"; size_t i;
  for (i = 0; i < len; i++) { out[2*i] = hx[in[i] >> 4]; out[2*i+1] = hx[in[i] & 15]; }
  out[2*len] = 0;
}
