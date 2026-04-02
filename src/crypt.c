// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/decoder.h>
#include <openssl/rsa.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include "log.h"
#include "crypt.h"

/* check bit-flag */
static inline int is_set(int flag, int mask)
{
	return (flag & mask) == mask;
}

static int error_cb(const char* input, size_t len, void* priv)
{
	(void) priv;
	(void) len;
	printf("%s\n", input);
	return 0;
}

struct crypt_ctx {
	OSSL_PROVIDER *provider_default;
	OSSL_PROVIDER *provider_pkcs11;
};

int crypt_ctx_create(struct crypt_ctx** cctx, int flags)
{
	if (cctx == NULL || *cctx != NULL)
		return -EINVAL;
	struct crypt_ctx *newctx = calloc(1, sizeof(struct crypt_ctx));
	if (newctx == NULL)
		return -ENOMEM;

	/* If pkcs11 provider is required then default provider must be explicitly
	 * loaded as well.
	 * Always load default provider and load pkcs11 if required.
	 * The providers must be loaded before using the library. */

	/* Ensure openssl errors are our errors */
	ERR_clear_error();

	int r = 0;

	newctx->provider_default = OSSL_PROVIDER_load(NULL, "default");
	if (newctx->provider_default == NULL) {
		pr_err("Failed loading openssl default provider\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -EFAULT;
		goto error_exit;
	}
	if (is_set(flags, CRYPT_CTX_INIT_PKCS11)) {
		newctx->provider_pkcs11 = OSSL_PROVIDER_load(NULL, "pkcs11");
		if (newctx->provider_pkcs11 == NULL) {
			pr_err("Failed loading openssl default provider\n");
			ERR_print_errors_cb(error_cb, NULL);
			r = -EFAULT;
			goto error_exit;
		}
	}

	*cctx = newctx;
	return 0;

error_exit:
	OSSL_PROVIDER_unload(newctx->provider_default);
	OSSL_PROVIDER_unload(newctx->provider_pkcs11);
	return r;
}

int crypt_ctx_free(struct crypt_ctx* cctx)
{
	if (cctx == NULL)
		return -EINVAL;
	OSSL_PROVIDER_unload(cctx->provider_default);
	OSSL_PROVIDER_unload(cctx->provider_pkcs11);
	free(cctx);
	return 0;
}

int crypt_parse_public_key(const uint8_t* data, size_t size, EVP_PKEY** pkey)
{
	if (data == NULL || size > LONG_MAX || pkey == NULL || *pkey != NULL)
		return -EINVAL;
	const unsigned char *tmp = data;
	*pkey = d2i_PUBKEY(NULL, &tmp, (long) size);
	if (*pkey == NULL)
		return -EPROTONOSUPPORT;
	return 0;
}

int crypt_serialize_public_key(uint8_t** data, size_t* size, const EVP_PKEY* pkey)
{
	if (data == NULL || *data != NULL || size == NULL || pkey == NULL)
		return -EINVAL;
	const int bytes = i2d_PUBKEY(pkey, (unsigned char**) data);
	if (bytes < 0)
		return -ENOSYS;
	*size = (size_t) bytes;
	return 0;
}

enum crypt_read_pkey_ctx_operations {
	READ_PKEY_FORMAT_FILE    = 1 << 0,
	READ_PKEY_FORMAT_PKCS11  = 1 << 1,
	READ_PKEY_TYPE_PRIV      = 1 << 2,
	READ_PKEY_TYPE_PUB       = 1 << 3,
	READ_PKEY_TYPE_PAIR      = READ_PKEY_TYPE_PRIV | READ_PKEY_TYPE_PUB,
	READ_PKEY_TYPE_MASK      = READ_PKEY_TYPE_PAIR,
};

struct crypt_read_pkey_ctx {
	char *path;
	char *pkcs11;
	FILE *file;
	OSSL_STORE_CTX *store;
	int ops;
	int done;
	size_t pem_index;
};

int crypt_read_pkey_ctx_create(struct crypt_read_pkey_ctx** ctx, const char* path, const char* pkcs11, int flags)
{
	/* must search somewhere */
	if (path == NULL && pkcs11 == NULL)
		return -EINVAL;
	/* must search for something */
	if ((flags & (CRYPT_READ_PRIV | CRYPT_READ_PUB)) == 0)
			return -EINVAL;
	/* must search for one of */
	if (is_set(flags, CRYPT_READ_PRIV) && is_set(flags, CRYPT_READ_PUB))
		return -EINVAL;

	struct crypt_read_pkey_ctx *newctx = calloc(1, sizeof(struct crypt_read_pkey_ctx));
	if (newctx == NULL)
		return -ENOMEM;

	newctx->ops = 0;
	if (is_set(flags, CRYPT_READ_PRIV))
		newctx->ops = READ_PKEY_TYPE_PRIV;
	if (is_set(flags, CRYPT_READ_PUB))
		newctx->ops = READ_PKEY_TYPE_PUB;
	newctx->done = 0;
	newctx->pem_index = 0;

	/* Notify OSSL_STORE what we are looking for, required to avoid requiring pin for pubkeys.
	 * This operation must be called before first OSSL_STORE_load() call. */
	int pkcs11_expected = 0;
	if (is_set(newctx->ops, READ_PKEY_TYPE_PUB))
		pkcs11_expected = OSSL_STORE_INFO_PUBKEY;
	if (is_set(newctx->ops, READ_PKEY_TYPE_PRIV))
		pkcs11_expected = OSSL_STORE_INFO_PKEY;

	int r = 0;

	if (path != NULL) {
		newctx->ops |= READ_PKEY_FORMAT_FILE;
		newctx->path = strdup(path);
		if (newctx->path == NULL) {
			r = -ENOMEM;
			goto error_exit;
		}
		newctx->file = fopen(newctx->path, "r");
		if (newctx->file == NULL) {
			r = -errno;
			pr_err("%s: fdopen [%d] %s\n", newctx->path, -r, strerror(-r));
			goto error_exit;
		}
	}

	if (pkcs11 != NULL) {
		newctx->ops |= READ_PKEY_FORMAT_PKCS11;
		newctx->pkcs11 = strdup(pkcs11);
		if (newctx->pkcs11 == NULL) {
			r = -ENOMEM;
			goto error_exit;
		}

		/* Ensure openssl errors are our errors */
		ERR_clear_error();

		newctx->store = OSSL_STORE_open(newctx->pkcs11, NULL, NULL, NULL, NULL);
		if (newctx->store == NULL) {
			pr_err("pkcs11 OSSL_STORE_open failed\n");
			ERR_print_errors_cb(error_cb, NULL);
			r = -EFAULT;
			goto error_exit;
		}
		r = OSSL_STORE_expect(newctx->store, pkcs11_expected);
		if (r != 1) {
			pr_err("pkcs11 OSSL_STORE_expect failed\n");
			ERR_print_errors_cb(error_cb, NULL);
			r = -EFAULT;
			goto error_exit;
		}
	}

	*ctx = newctx;
	return 0;
error_exit:
	if(newctx->file != NULL)
		fclose(newctx->file);
	if (newctx->path != NULL)
		free(newctx->path);
	if (newctx->pkcs11 != NULL)
		free(newctx->pkcs11);
	/* OSSL_STORE_close(ctx->store);
	* will cause a segmentation fault on OSSL_PROVIDER_unload(pkcs11_provider).
	* Is this close method redundant? */
	return r;
}

int crypt_read_pkey_ctx_free(struct crypt_read_pkey_ctx* ctx)
{
	if (ctx == NULL)
		return 0;
	if (ctx->file != NULL)
		fclose(ctx->file);
	if (ctx->path != NULL)
		free(ctx->path);
	if (ctx->pkcs11 != NULL)
		free(ctx->pkcs11);
	free(ctx);

	/* OSSL_STORE_close(ctx->store);
	* will cause a segmentation fault on OSSL_PROVIDER_unload(pkcs11_provider).
	* Is this close method redundant? */

	return 0;
}

static const char* read_pkey_ctx_key_type(int ops)
{
	switch (ops & READ_PKEY_TYPE_MASK) {
	case READ_PKEY_TYPE_PUB:
		return "PUB";
	case READ_PKEY_TYPE_PRIV:
		return "PRIV";
	case READ_PKEY_TYPE_PAIR:
		return "PAIR";
	default:
		return "UNKNOWN";
	}
}

int crypt_read_pkey(struct crypt_read_pkey_ctx* ctx, EVP_PKEY** pkey, char** name)
{
	if (ctx == NULL || pkey == NULL || *pkey != NULL || name == NULL || *name != NULL)
		return -EINVAL;

	int r = 0;

	if (is_set(ctx->ops, READ_PKEY_FORMAT_FILE) && !is_set(ctx->done, READ_PKEY_FORMAT_FILE)) {
		/* Ensure openssl errors are our errors */
		ERR_clear_error();

		/* check what to read */
		int selection = 0;
		switch (ctx->ops & READ_PKEY_TYPE_MASK) {
		case READ_PKEY_TYPE_PUB:
			selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY; break;
		case READ_PKEY_TYPE_PRIV:
			selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY; break;
		case READ_PKEY_TYPE_PAIR:
			selection = OSSL_KEYMGMT_SELECT_KEYPAIR; break;
		}
		EVP_PKEY* key = NULL;
		OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&key, NULL, NULL, NULL,
				selection, NULL, NULL);
		if (dctx == NULL) {
			pr_err("OSSL_DECODER_CTX_new_for_pkey failed\n");
			ERR_print_errors_cb(error_cb, NULL);
			return -EFAULT;
		}
		if (OSSL_DECODER_CTX_get_num_decoders(dctx) >= 1) {
			r = OSSL_DECODER_from_fp(dctx, ctx->file);
			if (r == 0)
				ERR_print_errors_cb(error_cb, NULL);
			r = r == 1 ? 0 : -EBADF;
		}
		else {
			pr_err("OSSL_DECODER_CTX_new_for_pkey no decoders found\n");
			ERR_print_errors_cb(error_cb, NULL);
			r = -EFAULT;
		}
		OSSL_DECODER_CTX_free(dctx);
		if (r == 0) {
			*name = strdup(ctx->path);
			if (*name == NULL) {
				EVP_PKEY_free(key);
				return -ENOMEM;
			}
			*pkey = key;
			pr_dbg("%s[%zu][%s]: %s-%d\n", ctx->path, ctx->pem_index, read_pkey_ctx_key_type(ctx->ops),
					EVP_PKEY_get0_type_name(*pkey), EVP_PKEY_get_bits(*pkey));
			ctx->pem_index++;
			return 0;
		}
		/* no further keys available */
		pr_dbg("%s[%zu]: [%d]: %s\n", ctx->path, ctx->pem_index, -r, strerror(-r));
		ctx->done |= READ_PKEY_FORMAT_FILE;
	}

	/* READ pkcs11 if requested */
	if (is_set(ctx->ops, READ_PKEY_FORMAT_PKCS11) && !is_set(ctx->done, READ_PKEY_FORMAT_PKCS11)) {
		/* Search for key in store */
		OSSL_STORE_INFO *info = NULL;
		while ((info = OSSL_STORE_load(ctx->store)) != NULL) {
			EVP_PKEY* key = NULL;
			if (key == NULL && is_set(ctx->ops, READ_PKEY_TYPE_PUB))
				key = OSSL_STORE_INFO_get0_PUBKEY(info);
			if (key == NULL && is_set(ctx->ops, READ_PKEY_TYPE_PRIV))
				key = OSSL_STORE_INFO_get0_PKEY(info);
			if (key != NULL)
				r = EVP_PKEY_up_ref(key);
			OSSL_STORE_INFO_free(info);
			if (key == NULL)
				continue;
			if (r != 1) {
				pr_err("pkcs11 failed retrieving key\n");
				EVP_PKEY_free(key);
				return -EFAULT;
			}
			*name = strdup("pkcs11");
			if (*name == NULL) {
				EVP_PKEY_free(key);
				return -ENOMEM;
			}
			*pkey = key;
			pr_dbg("pkcs11[%s]: %s-%d\n", read_pkey_ctx_key_type(ctx->ops), EVP_PKEY_get0_type_name(*pkey), EVP_PKEY_get_bits(*pkey));
			return 0;
		}

		/* pkcs11 store empty */
		ctx->done |= READ_PKEY_FORMAT_PKCS11;
	}

	return 1;
}

int crypt_read_x509(X509** x509, const char* path)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
		return -errno;
	*x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	if (*x509 == NULL)
		return -EBADF;
	return 0;
}

const char* crypt_pkey_hash_function(const EVP_PKEY* pkey)
{
	const int bits = EVP_PKEY_get_bits(pkey);
	if (bits == 0) {
		pr_err("key can not have 0 bits\n");
		return NULL;
	}

	/* Select hash function based on key strength as recommended by NIST SP 800-57pt1r6:
	 * Table 4. Security strengths of classical (non-quantum-resistant) asymmetric-key algorithms
	 * Table 6. Maximum security strengths for hash functions, XOFs, and their applications
	 */
	int css = 0; /* css -> "classical security strength" as in non-quantum-resistant */

	if (css == 0 && EVP_PKEY_is_a(pkey, "RSA")) {
		if (bits >= 15360)
			css = 256;
		else if (bits >= 7680)
			css = 192;
		else if (bits >= 3072)
			css = 128;
		else if (bits >= 2024)
			css = 112;
		else
			css = 80;

	}
	if (css == 0 && EVP_PKEY_is_a(pkey, "EC")) {
		if (bits >= 512)
			css = 256;
		else if (bits >= 384)
			css = 192;
		else if (bits >= 256)
			css = 128;
		else if (bits >= 224)
			css = 112;
		else
			css = 80;
	}

	if (css == 0) {
		pr_err("could not determine hash function for key\n");
		return NULL;
	}

	if (css >= 256)
		return "SHA512";
	else if (css >= 192)
		return "SHA384";
	else /* never drop below SHA256 */
		return "SHA256";
}

int crypt_digest_verity(const uint8_t* data, size_t data_size, const uint8_t* digest, size_t digest_size, EVP_PKEY* pkey)
{
	EVP_MD_CTX *ctx = NULL;
	EVP_MD *algo = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	/* Ensure openssl errors are our errors */
	ERR_clear_error();

	int r = 0;

	/* prepare validation context */
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		pr_dbg("failed creating validation context\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	/* Determine hash method  */
	algo = EVP_MD_fetch(NULL, crypt_pkey_hash_function(pkey), NULL);
	if (algo == NULL) {
		pr_err("failed fetching digest algorithm\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	/* initialize */
	if (EVP_DigestVerifyInit(ctx, &pctx, algo, NULL, pkey) != 1) {
		pr_dbg("failed initializing digest verification\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	if (EVP_PKEY_is_a(pkey, "RSA")) {
		/* Ensure PKCS#1 v1.5 padding for RSA keys */
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) < 1) {
			pr_err("failed setting RSA padding to PKCS#1 v1.5\n");
			r = -EFAULT;
			goto exit;
		}
	}

	/* verify */
	r = EVP_DigestVerify(ctx, digest, digest_size, data, data_size);
	if (r != 0 && r != 1) {
		pr_dbg("failed verifying digest\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
	}

exit:
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(algo);
	return r;
}
int crypt_digest_create(const uint8_t* data, size_t data_size, uint8_t** digest, size_t* digest_size, EVP_PKEY* pkey)
{
	uint8_t *digest_buf = NULL;
	size_t digest_buf_size = 0;
	EVP_MD_CTX *ctx = NULL;
	EVP_MD *algo = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int r = 0;

	/* Ensure openssl errors are our errors */
	ERR_clear_error();

	/* prepare validation context */
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		pr_err("failed creating validation context\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	/* Determine hash method */
	algo = EVP_MD_fetch(NULL, crypt_pkey_hash_function(pkey), NULL);
	if (algo == NULL) {
		pr_err("failed fetching digest algorithm\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	/* initialize */
	if (EVP_DigestSignInit(ctx, &pctx, algo, NULL, pkey) != 1) {
		pr_err("failed initializing digest verification\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	if (EVP_PKEY_is_a(pkey, "RSA")) {
		/* Ensure PKCS#1 v1.5 padding for RSA keys */
		if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) < 1) {
			pr_err("failed setting RSA padding to PKCS#1 v1.5\n");
			r = -EFAULT;
			goto exit;
		}
	}

	/* check digest size */
	if (EVP_DigestSign(ctx, NULL, &digest_buf_size, data, data_size) != 1) {
		pr_err("failed calculating digest size\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	/* Allocate */
	digest_buf = malloc(digest_buf_size);
	if (digest_buf == NULL) {
		r = -ENOMEM;
		goto exit;
	}

	/* sign digest */
	if (EVP_DigestSign(ctx, digest_buf, &digest_buf_size, data, data_size) != 1) {
		pr_err("failed signing digest\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	*digest = digest_buf;
	digest_buf = NULL;
	*digest_size = digest_buf_size;

	r = 0;
exit:
	if (digest_buf != NULL)
		free(digest_buf);
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(algo);
	return r;
}
