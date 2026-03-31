// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef CRYPT__H__
#define CRYPT__H__

#include <openssl/evp.h>

struct crypt_ctx;

/* Prepare application wide crypt context "cctx".
 * Should be performed before any crypt or openssl calls.
 *
 * "cctx" must be freed by caller, see crypt_free().
 *
 * Returns 0 for success or negative errno on error. */
enum crypt_ctx_init_flags {
	CRYPT_CTX_INIT_PKCS11 = 1 << 0,
};
int crypt_ctx_create(struct crypt_ctx** cctx, int flags);
int crypt_ctx_free(struct crypt_ctx* cctx);

/* Parse "pkey" from "data" of "size".
 *
 * Caller responsible of freeing pkey.
 *
 * Returns 0 for success or negative errno on error. */
int crypt_parse_public_key(const uint8_t* data, size_t size, EVP_PKEY** pkey);

/* Serialize "pkey" to "data" of "size".
 *
 * Caller responsible of freeing "data".
 *
 * Returns 0 for success or negative errno for error. */
int crypt_serialize_public_key(uint8_t** data, size_t* size, const EVP_PKEY* pkey);

struct crypt_read_pkey_ctx;

/* Create context for finding public or private keys, they are mutually exclusive.
 *
 * If not NULL, "path" points to file of DER or PEM keys.
 * If not NULL, "pkcs11" is the pkcs11 URI of a token or object.
 * "flags" defines what to search for.
 *
 * "ctx" must be freed by caller, see crypt_read_pkey_ctx_free();
 *
 * Returns 0 for success or negative errno for error. */
enum crypt_read_flags {
	CRYPT_READ_PRIV = 1 << 0,
	CRYPT_READ_PUB  = 1 << 1,
};
int crypt_read_pkey_ctx_create(struct crypt_read_pkey_ctx** ctx, const char* path, const char* pkcs11, int flags);

/* Free "ctx", if NULL, nothing is done.
 *
 * Returns 0 for success or negative errno for error. */
int crypt_read_pkey_ctx_free(struct crypt_read_pkey_ctx* ctx);

/* Read next available "pkey" from "ctx". The "name" contains
 * path for files or pkcs11 string.
 *
 * Caller responsible for freeing "pkey" and "name".
 *
 * Returns 0 if key available, 1 if no further processing possible
 * or negative errno for error. */
int crypt_read_pkey(struct crypt_read_pkey_ctx* ctx, EVP_PKEY** pkey, char** name);

/* Return hash method to use with pkey.
 * crypt_digest_* functions use this hash method.
 *
 * Returns NULL if type of pkey is not supported. */
const char* crypt_pkey_hash_function(const EVP_PKEY* pkey);

/* Calculate hash, as returned by crypt_pkey_hash_function(pkey), of
 * "data" with size "data_size". Verify towards "digest" of size "digest_size"
 * signed by "pkey".
 *
 * Return 1 for valid, 0 for invalid or negative errno for error. */
int crypt_digest_verity(const uint8_t* data, size_t data_size, const uint8_t* digest, size_t digest_size, EVP_PKEY* pkey);

/* Calculate hash, as returned by crypt_pkey_hash_function(pkey), of
 * "data" with size "data_size". Sign with "pkey" and output
 * to "digest" of size "digest_size".
 *
 * Caller responsible of freeing "digest".
 *
 * Returns 0 for success or negative errno for error. */
int crypt_digest_create(const uint8_t* data, size_t data_size, uint8_t** digest, size_t* digest_size, EVP_PKEY* pkey);

#endif // CRYPT__H__
