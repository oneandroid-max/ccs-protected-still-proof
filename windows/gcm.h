/* gcm.h — AES-256-GCM decryption through Windows CNG (bcrypt). The cipher is the system's job; the
 * key derivation and the mark are ours (proofcore). Shared by viewer.c and crosscheck.c. */
#ifndef GCM_H
#define GCM_H
#include <stddef.h>
#include <stdint.h>
#define GCM_OK 0
#define GCM_TAG_MISMATCH 1   /* a wrong key: the tag does not verify, nothing is returned */
#define GCM_ERROR 2
/* ct_len includes the 16-byte tag appended by WebCrypto; out needs ct_len - 16 bytes. */
int gcm_decrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *ct, size_t ct_len, uint8_t *out, size_t *out_len);
#endif
