/* proofcore.h — the portable heart of the Windows viewer: SHA-256, HMAC, PBKDF2, the CCSP1 header, and
 * the viewer mark. Plain C, no Windows call in it, so it compiles and is tested on any machine with a C
 * compiler (coretest.c) before it ever meets a Windows runner. AES-GCM is the one piece left to the
 * operating system (CNG, in viewer.c and crosscheck.c), because a cipher is the system's job. */
#ifndef PROOFCORE_H
#define PROOFCORE_H
#include <stddef.h>
#include <stdint.h>

/* ---- SHA-256 (FIPS 180-4) ---- */
typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t buflen; } sha256_ctx;
void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);

/* ---- HMAC-SHA256 with precomputed pads (PBKDF2 calls it 400,000 times) ---- */
typedef struct { sha256_ctx inner, outer; } hmac_ctx;
void hmac_sha256_init(hmac_ctx *h, const uint8_t *key, size_t keylen);
void hmac_sha256_compute(const hmac_ctx *h, const uint8_t *msg, size_t msglen, uint8_t out[32]);

/* ---- PBKDF2-HMAC-SHA256 (RFC 8018), identical to WebCrypto's ---- */
void pbkdf2_hmac_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                        uint32_t iterations, uint8_t *out, size_t dklen);

/* ---- The CCSP1 file: "CCSP1", version 1, iterations (uint32 BE), salt[16], iv[12], ciphertext+tag ---- */
typedef struct { uint32_t iterations; const uint8_t *salt; const uint8_t *iv; const uint8_t *ciphertext; size_t ciphertext_len; } ccsp1_header;
int ccsp1_parse(const uint8_t *file, size_t len, ccsp1_header *h);   /* 1 ok, 0 not a CCSP1 v1 file */
/* key = PBKDF2(secret + ":" + pin, salt, iterations), 32 bytes */
void ccsp1_derive_key(const char *secret, const char *pin, const ccsp1_header *h, uint8_t key[32]);

/* ---- The viewer mark: SHA-256("ccs-mark-v1:secret:pin:hour") → xorshift128 → 128×128 tile of ±1, ±3/255 ---- */
#define MARK_TILE 128
#define MARK_AMPLITUDE 3
void mark_seed(const char *secret, const char *pin, const char *hour, uint8_t seed[32]);
void mark_tile_pattern(const uint8_t seed[32], int8_t pattern[MARK_TILE * MARK_TILE]);
void mark_id(const uint8_t seed[32], char out[9]);
/* Adds the mark in place to 4-byte pixels; offR/offG/offB name the channel bytes (RGBA: 0,1,2; BGRA: 2,1,0). */
void mark_apply(uint8_t *px, int w, int h, int stride_bytes, int offR, int offG, int offB, const int8_t *pattern);

void hex_encode(const uint8_t *in, size_t len, char *out);   /* out needs 2*len+1 */
#endif
