/* coretest.c — tests proofcore on any machine (gcc coretest.c proofcore.c -o coretest):
 *   coretest sha            → SHA-256 of "abc" and of the empty string against the FIPS vectors
 *   coretest key <file.enc> <secret> <pin>            → the derived key in hex (compare with Node deriveBits)
 *   coretest mark <secret> <pin> <hour>               → markId, patternSha256, patternPlusOnes, markedRampSha256
 * The ramp is the same synthetic 300×200 image as tools/cross-check.mjs (R=x, G=y, B=x+y), marked and hashed in RGB order. */
#include "proofcore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **buf, size_t *len) {
  FILE *f = fopen(path, "rb"); long n; if (!f) return 0;
  fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
  *buf = (uint8_t *)malloc((size_t)n); *len = (size_t)n;
  if (fread(*buf, 1, *len, f) != *len) { fclose(f); return 0; }
  fclose(f); return 1;
}
int main(int argc, char **argv) {
  char hx[65]; uint8_t d[32];
  if (argc < 2) { fprintf(stderr, "usage: sha | key <file> <secret> <pin> | mark <secret> <pin> <hour>\n"); return 2; }
  if (!strcmp(argv[1], "sha")) {
    sha256("abc", 3, d); hex_encode(d, 32, hx); printf("sha256(abc)=%s\n", hx);
    sha256("", 0, d); hex_encode(d, 32, hx); printf("sha256()=%s\n", hx);
    { uint8_t big[1000]; int i; sha256_ctx c; memset(big, 'a', 1000); sha256_init(&c); for (i = 0; i < 1000; i++) sha256_update(&c, big, 1000); sha256_final(&c, d); hex_encode(d, 32, hx); printf("sha256(a*1e6)=%s\n", hx); }
    return 0;
  }
  if (!strcmp(argv[1], "key") && argc == 5) {
    uint8_t *file; size_t len; ccsp1_header h; uint8_t key[32];
    if (!read_file(argv[2], &file, &len) || !ccsp1_parse(file, len, &h)) { fprintf(stderr, "bad file\n"); return 1; }
    ccsp1_derive_key(argv[3], argv[4], &h, key); hex_encode(key, 32, hx);
    printf("iterations=%u key=%s\n", h.iterations, hx); return 0;
  }
  if (!strcmp(argv[1], "mark") && argc == 5) {
    uint8_t seed[32]; int8_t *pat = (int8_t *)malloc(MARK_TILE * MARK_TILE); char id[9]; int plus = 0, i, x, y;
    uint8_t *ramp; const int W = 300, H = 200; uint8_t *rgb;
    mark_seed(argv[2], argv[3], argv[4], seed); mark_tile_pattern(seed, pat); mark_id(seed, id);
    for (i = 0; i < MARK_TILE * MARK_TILE; i++) if (pat[i] == 1) plus++;
    sha256(pat, MARK_TILE * MARK_TILE, d); hex_encode(d, 32, hx);
    printf("markId=%s patternSha256=%s patternPlusOnes=%d ", id, hx, plus);
    ramp = (uint8_t *)malloc((size_t)W * H * 4);
    for (y = 0; y < H; y++) for (x = 0; x < W; x++) { uint8_t *p = ramp + ((size_t)y * W + x) * 4; p[0] = (uint8_t)(x & 255); p[1] = (uint8_t)(y & 255); p[2] = (uint8_t)((x + y) & 255); p[3] = 255; }
    mark_apply(ramp, W, H, W * 4, 0, 1, 2, pat);
    rgb = (uint8_t *)malloc((size_t)W * H * 3);
    for (i = 0; i < W * H; i++) { rgb[i*3] = ramp[i*4]; rgb[i*3+1] = ramp[i*4+1]; rgb[i*3+2] = ramp[i*4+2]; }
    sha256(rgb, (size_t)W * H * 3, d); hex_encode(d, 32, hx);
    printf("markedRampSha256=%s\n", hx); return 0;
  }
  fprintf(stderr, "bad arguments\n"); return 2;
}
