// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libcryptsetup.h>
#include "log.h"
#include "verity.h"

/*
 * Following functions are copied from cryptsetup/lib/utils_crypt.c
 *   hex_to_bin()
 *   hex2asc()
 *   crypt_hex_to_bytes()
 *   crypt_bytes_to_hex() (modified to use calloc() instead of crypt_safe_alloc())
 */

/*
 * Thanks Mikulas Patocka for these two char converting functions.
 *
 * This function is used to load cryptographic keys, so it is coded in such a
 * way that there are no conditions or memory accesses that depend on data.
 *
 * Explanation of the logic:
 * (ch - '9' - 1) is negative if ch <= '9'
 * ('0' - 1 - ch) is negative if ch >= '0'
 * we "and" these two values, so the result is negative if ch is in the range
 * '0' ... '9'
 * we are only interested in the sign, so we do a shift ">> 8"; note that right
 * shift of a negative value is implementation-defined, so we cast the
 * value to (unsigned) before the shift --- we have 0xffffff if ch is in
 * the range '0' ... '9', 0 otherwise
 * we "and" this value with (ch - '0' + 1) --- we have a value 1 ... 10 if ch is
 * in the range '0' ... '9', 0 otherwise
 * we add this value to -1 --- we have a value 0 ... 9 if ch is in the range '0'
 * ... '9', -1 otherwise
 * the next line is similar to the previous one, but we need to decode both
 * uppercase and lowercase letters, so we use (ch & 0xdf), which converts
 * lowercase to uppercase
 */
static int hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) & ('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) & ('A' - 1 - cu)) >> 8);
}

static char hex2asc(unsigned char c)
{
	return c + '0' + ((unsigned)(9 - c) >> 4 & 0x27);
}

static ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc)
{
	char *bytes;
	size_t i, len;
	int bl, bh;

	if (!hex || !result)
		return -EINVAL;

	len = strlen(hex);
	if (len % 2)
		return -EINVAL;
	len /= 2;

	bytes = safe_alloc ? crypt_safe_alloc(len) : malloc(len);
	if (!bytes)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		bh = hex_to_bin(hex[i * 2]);
		bl = hex_to_bin(hex[i * 2 + 1]);
		if (bh == -1 || bl == -1) {
			safe_alloc ? crypt_safe_free(bytes) : free(bytes);
			return -EINVAL;
		}
		bytes[i] = (bh << 4) | bl;
	}
	*result = bytes;
	return i;
}

static char *crypt_bytes_to_hex(size_t size, const char *bytes)
{
	unsigned i;
	char *hex;

	if (size && !bytes)
		return NULL;

	/* Alloc adds trailing \0 */
	if (size == 0)
		hex = calloc(1, 2);
	else
		hex = calloc(1, size * 2 + 1);
	if (!hex)
		return NULL;

	if (size == 0)
		hex[0] = '-';
	else for (i = 0; i < size; i++) {
		hex[i * 2]     = hex2asc((const unsigned char)bytes[i] >> 4);
		hex[i * 2 + 1] = hex2asc((const unsigned char)bytes[i] & 0xf);
	}

	return hex;
}

int verity_open(const char* path, uint64_t tree_offset, const char* mapperpath, int flags, const char* roothash)
{
	if (path == NULL || tree_offset == 0 || roothash == NULL)
		return -EINVAL;
	if ((flags & VERITY_VERIFY) == 0 && mapperpath == NULL)
		return -EINVAL;

	char *roothash_bytes = NULL;

	/* init */
	struct crypt_device *cd = NULL;
	int r = crypt_init_data_device(&cd, path, path);
	if (r != 0) {
		pr_err("crypt_init_data_device: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}

	/* load */
	struct crypt_params_verity params;
	memset(&params, 0, sizeof(params));
	params.flags = (flags & VERITY_VERIFY) == VERITY_VERIFY ? CRYPT_VERITY_CHECK_HASH : 0;
	params.hash_area_offset = tree_offset;
	r = crypt_load(cd, CRYPT_VERITY, &params);
	if (r != 0) {
		pr_err("crypt_load: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}

	/* confirm roothash size */
	const int roothash_expected = crypt_get_volume_key_size(cd);
	if (roothash_expected < 0) {
		pr_err("crypt_get_volume_key_size: unexpected size\n");
		r = -EFAULT;
		goto exit;
	}
	const ssize_t roothash_size = crypt_hex_to_bytes(roothash, &roothash_bytes, 0);
	if (roothash_size < 0) {
		pr_err("crypt_hex_to_bytes: unexpected result: %zd\n", roothash_size);
		r = -EFAULT;
		goto exit;
	}
	if (roothash_size != roothash_expected) {
		pr_err("unexpected roothash size\n");
		r = -EBADF;
		goto exit;
	}

	/* verify */
	r = crypt_activate_by_signed_key(cd, mapperpath, roothash_bytes, roothash_size,
										NULL, 0, CRYPT_ACTIVATE_READONLY);
	if (r != 0) {
		pr_err("crypt_activate_by_signed_key: [%d] %s\n", -r, strerror(-r));
		r = -EBADF;
		goto exit;
	}

	r = 0;
exit:
	if (cd != NULL)
		crypt_free(cd);
	if (roothash_bytes != NULL)
		free(roothash_bytes);
	return r;
}

int verity_close(const char* mapperpath, int force)
{
	if (mapperpath == NULL)
		return -EINVAL;

	/* init */
	struct crypt_device *cd = NULL;
	int r = crypt_init_by_name(&cd, mapperpath);
	if (r != 0) {
		pr_err("crypt_init_by_name: [%d] %s\n", -r, strerror(-r));
		return r;
	}

	/* close */
	r = crypt_deactivate_by_name(cd, mapperpath, force ? CRYPT_DEACTIVATE_FORCE : 0);
	crypt_free(cd);
	if (r != 0) {
		pr_err("crypt_deactivate_by_name: [%d] %s\n", -r, strerror(-r));
		return r;
	}
	return 0;
}

int verity_create(const char* path, const char* tree, char** roothash)
{
	if (path == NULL || tree == NULL || *roothash != NULL)
		return -EINVAL;

	char *hash = NULL;

	/* init */
	struct crypt_device *cd = NULL;
	int r = crypt_init(&cd, tree);
	if (r != 0) {
		pr_err("crypt_init: [%d] %s\n", -r, strerror(-r));
		return r;
	}

	/* prepare */
	struct crypt_params_verity params;
	memset(&params, 0, sizeof(params));
	params.hash_name = "sha256";
	params.data_device = path;
	params.data_block_size = 4096;
	params.hash_block_size = 4096;
	params.hash_type = 1;
	params.salt_size = 32;
	params.salt = NULL;
	params.flags = CRYPT_VERITY_CREATE_HASH;

	/* format */
	r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params);
	if (r != 0) {
		pr_err("crypt_format: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}

	if (dbg) {
		r = crypt_dump(cd);
		if (r != 0)
			pr_dbg("crypt_dump: [%d] %s\n", -r, strerror(-r));
	}

	/* retrieve roothash */
	const int hash_size = crypt_get_volume_key_size(cd);
	hash = malloc(hash_size);
	if (hash == NULL) {
		r = -ENOMEM;
		goto exit;
	}
	size_t hash_bytes_returned = (size_t) hash_size;
	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, hash, &hash_bytes_returned, NULL, 0);
	if (r < 0) {
		pr_err("crypt_volume_key_get: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}
	if (hash_bytes_returned !=  (size_t) hash_size) {
		r = -EFAULT;
		pr_err("crypt_volume_key_get: unexpected roothash size: %zu\n", hash_bytes_returned);
		goto exit;
	}
	*roothash = crypt_bytes_to_hex(hash_bytes_returned, hash);
	if (*roothash == NULL) {
		pr_err("crypt_bytes_to_hex: unexpected result\n");
		r = -EFAULT;
		goto exit;
	}

	r = 0;
exit:
	crypt_free(cd);
	if (hash != NULL)
		free(hash);
	return r;
}
