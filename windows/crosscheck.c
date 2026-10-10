/* crosscheck.c — the Windows console cross-check: decrypts a CCSP1 file with proofcore (PBKDF2) and
 * CNG (AES-GCM) and prints the canonical line CI diffs against tests/vectors/expected.txt.
 *   crosscheck.exe <file.enc> <secret> <pin> <YYYY-MM-DDTHH> --canonical
 * Build: cl /W4 /O2 crosscheck.c proofcore.c /link bcrypt.lib */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proofcore.h"
#include "gcm.h"

static int read_file(const char *path, uint8_t **buf, size_t *len) {
  FILE *f = fopen(path, "rb"); long n; if (!f) return 0;
  fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
  *buf = (uint8_t *)malloc((size_t)n); *len = (size_t)n;
  if (fread(*buf, 1, *len, f) != *len) { fclose(f); return 0; }
  fclose(f); return 1;
}

int main(int argc, char **argv) {
  uint8_t *file; size_t len; ccsp1_header h; uint8_t key[32], *plain; size_t plainlen; int rc;
  uint8_t seed[32], d[32]; int8_t *pat; char hx[65], id[9], psha[65], rsha[65], magic[7]; int plus = 0, i, x, y;
  uint8_t *ramp, *rgb; const int W = 300, H = 200; const char *wrong; const char *wrongResult;
  if (argc < 5) { fprintf(stderr, "usage: <file.enc> <secret> <pin> <YYYY-MM-DDTHH> [--canonical]\n"); return 2; }
  if (!read_file(argv[1], &file, &len) || !ccsp1_parse(file, len, &h)) { fprintf(stderr, "not a CCSP1 file\n"); return 1; }
  ccsp1_derive_key(argv[2], argv[3], &h, key);
  plain = (uint8_t *)malloc(h.ciphertext_len);
  rc = gcm_decrypt(key, h.iv, h.ciphertext, h.ciphertext_len, plain, &plainlen);
  if (rc != GCM_OK) { fprintf(stderr, "decrypt failed: %d\n", rc); return 1; }
  sha256(plain, plainlen, d); hex_encode(d, 32, hx); hex_encode(plain, 3, magic);
  mark_seed(argv[2], argv[3], argv[4], seed); pat = (int8_t *)malloc(MARK_TILE * MARK_TILE); mark_tile_pattern(seed, pat); mark_id(seed, id);
  for (i = 0; i < MARK_TILE * MARK_TILE; i++) if (pat[i] == 1) plus++;
  sha256(pat, MARK_TILE * MARK_TILE, d); hex_encode(d, 32, psha);
  ramp = (uint8_t *)malloc((size_t)W * H * 4);
  for (y = 0; y < H; y++) for (x = 0; x < W; x++) { uint8_t *p = ramp + ((size_t)y * W + x) * 4; p[0] = (uint8_t)(x & 255); p[1] = (uint8_t)(y & 255); p[2] = (uint8_t)((x + y) & 255); p[3] = 255; }
  mark_apply(ramp, W, H, W * 4, 0, 1, 2, pat);
  rgb = (uint8_t *)malloc((size_t)W * H * 3);
  for (i = 0; i < W * H; i++) { rgb[i*3] = ramp[i*4]; rgb[i*3+1] = ramp[i*4+1]; rgb[i*3+2] = ramp[i*4+2]; }
  sha256(rgb, (size_t)W * H * 3, d); hex_encode(d, 32, rsha);
  wrong = strcmp(argv[3], "000000") == 0 ? "111111" : "000000";
  { uint8_t wkey[32]; uint8_t *wp = (uint8_t *)malloc(h.ciphertext_len); size_t wl;
    ccsp1_derive_key(argv[2], wrong, &h, wkey);
    wrongResult = gcm_decrypt(wkey, h.iv, h.ciphertext, h.ciphertext_len, wp, &wl) == GCM_OK ? "DECRYPTED" : "refused"; }
  if (argc > 5 && strcmp(argv[5], "--canonical") == 0) {
    printf("ccs-vector-v1 plainBytes=%u plainSha256=%s jpegMagic=%s markId=%s patternSha256=%s patternPlusOnes=%d markedRampSha256=%s wrongPin=%s\n",
           (unsigned)plainlen, hx, magic, id, psha, plus, rsha, wrongResult);
  } else {
    printf("{\"iterations\":%u,\"plainBytes\":%u,\"plainSha256\":\"%s\",\"jpegMagic\":\"%s\",\"bucket\":\"%s\",\"markId\":\"%s\",\"patternSha256\":\"%s\",\"patternPlusOnes\":%d,\"markedRampSha256\":\"%s\"}\n",
           h.iterations, (unsigned)plainlen, hx, magic, argv[4], id, psha, plus, rsha);
    printf("{\"wrongPin\":\"%s\",\"result\":\"%s\"}\n", wrong, wrongResult);
  }
  return strcmp(wrongResult, "refused") == 0 ? 0 : 1;
}
