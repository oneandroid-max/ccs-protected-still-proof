#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include "gcm.h"
#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif
int gcm_decrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *ct, size_t ct_len, uint8_t *out, size_t *out_len) {
  BCRYPT_ALG_HANDLE alg = NULL; BCRYPT_KEY_HANDLE hkey = NULL; NTSTATUS st; ULONG n = 0; int rc = GCM_ERROR;
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
  if (ct_len < 16) return GCM_ERROR;
  st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (st != 0) return GCM_ERROR;
  st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  if (st != 0) goto done;
  st = BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0, (PUCHAR)key, 32, 0);
  if (st != 0) goto done;
  BCRYPT_INIT_AUTH_MODE_INFO(info);
  info.pbNonce = (PUCHAR)iv; info.cbNonce = 12;
  info.pbTag = (PUCHAR)(ct + ct_len - 16); info.cbTag = 16;
  st = BCryptDecrypt(hkey, (PUCHAR)ct, (ULONG)(ct_len - 16), &info, NULL, 0, out, (ULONG)(ct_len - 16), &n, 0);
  if (st == 0) { *out_len = n; rc = GCM_OK; }
  else if (st == STATUS_AUTH_TAG_MISMATCH) rc = GCM_TAG_MISMATCH;
  else rc = GCM_ERROR;
done:
  if (hkey) BCryptDestroyKey(hkey);
  if (alg) BCryptCloseAlgorithmProvider(alg, 0);
  return rc;
}
