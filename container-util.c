#define _LARGEFILE64_SOURCE /* For lseek64() */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <libcryptsetup.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// FIXME:  Add test if FILE is symbolic link
// FIXME:  GPL-2.0-or-later
// FIXME:  cryptsetup license
// FIXME:  Test --pubkey with PEM
// FIXME:  Test --pubkey with DER
// FIXME:  Test --pubkey with mixed PEM object types (!= PUBLIC KEY)
// FIXME:  Test --pubkey-dir
// FIXME:  runtime dependency packages: pkcs11-provider
// FIXME:  Test RSA and ECDSA priv/pub keys
// FIXME:  Select hashing (i.e. sha256) based on key type
/*
 * Following functions are copied from cryptsetup/lib/utils_crypt.c
 *   hex_to_bin()
 *   hex2asc()
 *   crypt_hex_to_bytes()
 *   crypt_bytes_to_hex()
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

ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc)
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

char *crypt_bytes_to_hex(size_t size, const char *bytes)
{
	unsigned i;
	char *hex;

	if (size && !bytes)
		return NULL;

	/* Alloc adds trailing \0 */
	if (size == 0)
		hex = crypt_safe_alloc(2);
	else
		hex = crypt_safe_alloc(size * 2 + 1);
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

/* Get sizeof() struct member */
#define member_size(type, member) (sizeof(((type *)0)->member))

/* check bit-flag */
static inline int is_set(int flag, int mask)
{
	return (flag & mask) == mask;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int dbg = 0;
static void enable_debug(void)
{
	dbg = 1;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int info = 1;
static void disable_info(void)
{
	info = 0;
}

#define pr_dbg(fmt, ...) \
		if (dbg) {mprint(stdout, "dbg: " fmt, ##__VA_ARGS__);}
#define pr_info(fmt, ...) \
		if (info) {mprint(stdout, fmt, ##__VA_ARGS__);}
#define pr_err(fmt, ...) \
		if (1) {mprint(stderr, fmt, ##__VA_ARGS__);}

static void mprint(FILE* stream, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stream, fmt, args);
	va_end(args);
}

struct header {
	uint32_t magic;
	uint8_t rsvd[28];
	uint64_t tree_offset;
	uint64_t root_offset;
	uint64_t digest_offset;
	uint64_t key_offset;
};
#define HEADER_MAGIC 0x494d4721
#define HEADER_SIZE  64
_Static_assert(sizeof(struct header) == HEADER_SIZE, "struct header size unexpected\n");

struct section {
	off64_t offset;
	size_t size;
};

enum container_options {
	CONTAINER_NONE     = 0,
	CONTAINER_VALID    = 1 << 0, /* container header validated */
};

struct container {
	struct section data;
	struct section tree;
	struct section root;
	struct section digest;
	struct section key;
	struct section header;
	uint8_t *roothash;
	size_t roothash_size;
	EVP_PKEY *pkey;
	int opt;
};

static void destroy_container(struct container* container)
{
	EVP_PKEY_free(container->pkey);
	if (container->roothash != NULL)
		free(container->roothash);
	memset(container, 0, sizeof(*container));
}

static void dump_container(const struct container* container)
{
	const char* key_type = EVP_PKEY_get0_type_name(container->pkey);
	char *hex = crypt_bytes_to_hex(container->roothash_size, (char*) container->roothash);


	printf("container:\n"
			"  section   offset     size\n"
			"  data:     %-10" PRIu64 " [%zu b]\n"
			"  tree:     %-10" PRIu64 " [%zu b]\n"
			"  root:     %-10" PRIu64 " [%zu b]\n"
			"  pubkey:   %-10" PRIu64 " [%zu b]\n"
			"  digest:   %-10" PRIu64 " [%zu b]\n"
			"  header:   %-10" PRIu64 " [%zu b]\n"
			"  key type: %s-%d\n"
			"  roothash: %s\n",
				container->data.offset, container->data.size,
				container->tree.offset, container->tree.size,
				container->root.offset, container->root.size,
				container->key.offset, container->key.size,
				container->digest.offset, container->digest.size,
				container->header.offset, container->header.size,
				key_type ? key_type : "unknown", EVP_PKEY_get_bits(container->pkey),
				hex);

	if (hex != NULL)
		crypt_safe_free(hex);
}

static void u32tole(uint32_t in, uint8_t* buf)
{
	buf[0] = in & 0xff;
	buf[1] = (in >> 8) & 0xff;
	buf[2] = (in >> 16) & 0xff;
	buf[3] = (in >> 24) & 0xff;
}

static uint32_t u32fromle(const uint8_t* buf)
{
	const uint32_t out =
		buf[0]
		| (buf[1] << 8)
		| (buf[2] << 16)
		| ((uint32_t) buf[3] << 24);
	return out;
}

static void u64tole(uint64_t in, uint8_t* buf)
{
	buf[0] = in & 0xff;
	buf[1] = (in >> 8) & 0xff;
	buf[2] = (in >> 16) & 0xff;
	buf[3] = (in >> 24) & 0xff;
	buf[4] = (in >> 32) & 0xff;
	buf[5] = (in >> 40) & 0xff;
	buf[6] = (in >> 48) & 0xff;
	buf[7] = (in >> 56) & 0xff;
}

static uint64_t u64fromle(const uint8_t* buf)
{
	const uint64_t out =
		(uint64_t) buf[0]
		| ((uint64_t) buf[1] << 8)
		| ((uint64_t) buf[2] << 16)
		| ((uint64_t) buf[3] << 24)
		| ((uint64_t) buf[4] << 32)
		| ((uint64_t) buf[5] << 40)
		| ((uint64_t) buf[6] << 48)
		| ((uint64_t) buf[7] << 56);
	return out;
}

static int write_bytes(int fd, const uint8_t* buf, ssize_t size)
{
	ssize_t bytes_remaining = size;
	uint8_t *tmp = (uint8_t*) buf;
	while(bytes_remaining > 0) {
		ssize_t bytes = write(fd, tmp, bytes_remaining);
		if (bytes < 0)
			return -errno;
		if (bytes < 1 || bytes > bytes_remaining)
			return -EIO;
		bytes_remaining -= bytes;
		tmp += bytes;
	}
	return 0;
}

static int pwrite_bytes(int fd, off64_t offset, const uint8_t* buf, ssize_t bytes)
{
	const off64_t pos = lseek64(fd, offset, SEEK_SET);
	if (pos < 0)
		return -errno;
	return write_bytes(fd, buf, bytes);
}

static int padto_multiple_of(int fd, off64_t multiple)
{
	if (multiple < 1)
		return -EINVAL;
	const off64_t size = lseek64(fd, 0, SEEK_END);
	if (size < 0)
		return -errno;
	const off64_t modulus = -size % multiple;
	if (modulus == 0)
		return 0;
	const ssize_t remaining = (ssize_t) multiple + modulus;
	pr_dbg("padding from %lld by %lld to %lld\n", size, remaining, size + remaining);
	uint8_t *buf = malloc(remaining);
	if (buf == NULL)
		return -ENOMEM;
	memset(buf, 0, remaining);
	int r = write_bytes(fd, buf, remaining);
	free(buf);
	return r;
}

static int read_bytes(int fd, uint8_t* buf, ssize_t size)
{
	ssize_t bytes_remaining = size;
	while(bytes_remaining > 0) {
		ssize_t bytes = read(fd, buf, bytes_remaining);
		if (bytes < 0)
			return -errno;
		if (bytes < 1 || bytes > bytes_remaining)
			return -EIO;
		bytes_remaining -= bytes;
		buf += bytes;
	}
	return 0;
}

static int pread_bytes(int fd, off64_t offset, uint8_t* buf, ssize_t bytes)
{
	const off64_t pos = lseek64(fd, offset, SEEK_SET);
	if (pos < 0)
		return -errno;
	return read_bytes(fd, buf, bytes);
}

static int error_cb(const char* input, size_t len, void* priv)
{
	(void) priv;
	(void) len;
	printf("%s\n", input);
	return 0;
}

static int parse_private_key(const uint8_t* data, long size, EVP_PKEY** pkey)
{
	const unsigned char *tmp = data;
	*pkey = d2i_AutoPrivateKey(NULL, &tmp, size);
	if (*pkey == NULL)
		return -EPROTONOSUPPORT;
	return 0;
}

static int parse_public_key(const uint8_t* data, long size, EVP_PKEY** pkey)
{
	const unsigned char *tmp = data;
	*pkey = d2i_PUBKEY(NULL, &tmp, size);
	if (*pkey == NULL)
		return -EPROTONOSUPPORT;
	return 0;
}

/*
 * return 1 if equal
 *        0 if not equal
 *        negative errno for error
 */
static int compare_pkey(const EVP_PKEY* lhs, const EVP_PKEY* rhs)
{
	int r = 0;

	/* compare keys */
	switch (EVP_PKEY_eq(lhs, rhs)) {
	case 0:
		r = 0;
		break;
	case 1:
		r = 1;
		break;
	case -1:
		r = -EBADF;
		break;
	case -2:
		r = -EOPNOTSUPP;
		break;
	default:
		r = -EFAULT;
		break;
	}
	return r;
}

enum read_pkey_ctx_operations {
	READ_PKEY_FORMAT_DER     = 1 << 0,
	READ_PKEY_FORMAT_PEM     = 1 << 1,
	READ_PKEY_FORMAT_STACK   = 1 << 2,
	READ_PKEY_FORMAT_PKCS11  = 1 << 3,
	READ_PKEY_TYPE_PRIV      = 1 << 4,
	READ_PKEY_TYPE_PUB       = 1 << 5,
};

struct read_pkey_ctx {
	char *path;
	char *pkcs11;
	FILE *file;
	OSSL_STORE_CTX *store;
	int ops;
	int done;
	size_t pem_index;
};

static int read_pkey_ctx_create(struct read_pkey_ctx* ctx, const char* path, const char* pkcs11, int ops)
{
	memset(ctx, 0, sizeof(*ctx));

	if (path == NULL && (is_set(ops, READ_PKEY_FORMAT_DER) || is_set(ops, READ_PKEY_FORMAT_PEM)))
		return -EINVAL;
	if (pkcs11 == NULL && is_set(ops, READ_PKEY_FORMAT_PKCS11))
		return -EINVAL;
	/* Must search for something */
	if ((ops & (READ_PKEY_TYPE_PRIV | READ_PKEY_TYPE_PUB)) == 0)
			return -EINVAL;
	/* Can't search for both priv and pubkeys simultaneously from pkcs11 */
	if (is_set(ops, READ_PKEY_FORMAT_PKCS11)
			&& is_set(ops, READ_PKEY_TYPE_PRIV)
			&& is_set(ops, READ_PKEY_TYPE_PUB))
		return -EINVAL;

	if (path != NULL) {
		ctx->path = (char*) path;
		ctx->file = fopen(path, "r");
		if (ctx->file == NULL) {
			int r = -errno;
			pr_err("%s: fdopen [%d] %s\n", path, -r, strerror(-r));
			return r;
		}
	}
	if (pkcs11 != NULL) {
		ctx->pkcs11 = (char*) pkcs11;
		/* Ensure openssl errors are our errors */
		ERR_clear_error();

		ctx->store = OSSL_STORE_open(pkcs11, UI_null(), NULL, NULL, NULL);
		if (ctx->store == NULL) {
			if (path != NULL) {
				fclose(ctx->file);
				ctx->file = NULL;
			}
			pr_err("pkcs11 OSSL_STORE_open failed\n");
			ERR_print_errors_cb(error_cb, NULL);
			return -EFAULT;
		}

		/* Notify store what we are looking for, required to avoid
		 * requiring pin for pubkeys.
		 * This operation must be called before first
		 * OSSL_STORE_load() call. */
		int expected = 0;
		if (is_set(ops, READ_PKEY_TYPE_PUB))
			expected = OSSL_STORE_INFO_PUBKEY;
		if (is_set(ops, READ_PKEY_TYPE_PRIV))
			expected = OSSL_STORE_INFO_PKEY;
		int r = OSSL_STORE_expect(ctx->store, expected);
		if (r != 1) {
			if (path != NULL) {
				fclose(ctx->file);
				ctx->file = NULL;
			}
			pr_err("pkcs11 OSSL_STORE_expect failed\n");
			ERR_print_errors_cb(error_cb, NULL);
			return -EFAULT;
		}
	}

	ctx->ops = ops;
	ctx->done = 0;
	ctx->pem_index = 0;
	return 0;
}

static int read_pkey_ctx_free(struct read_pkey_ctx* ctx)
{
	if (ctx == NULL)
		return 0;
	if (ctx->file != NULL)
		fclose(ctx->file);
	ctx->file = NULL;

	/* OSSL_STORE_close(ctx->store);
	* will cause a segmentation fault on OSSL_PROVIDER_unload(pkcs11_provider).
	* Is this close method redundant? */

	return 0;
}

/* Return PKEY from ctx, caller responsible of freeing pkey.
 * path should NOT be freed.
 *
 * Return 0 if key available, 1 if no further processing possible
 * or negative errno for error. */
static int read_pkey(struct read_pkey_ctx* ctx, EVP_PKEY** pkey, char** path)
{
	if ((ctx == NULL) || (pkey == NULL) || (*pkey != NULL))
		return -EINVAL;

	int r = 0;

	/* Read PEM if requested */
	if (is_set(ctx->ops, READ_PKEY_FORMAT_PEM) && !is_set(ctx->done, READ_PKEY_FORMAT_PEM)) {
		for (; ctx->pem_index < SIZE_MAX; ++ctx->pem_index) {

			/* Next PEM call not allowed unless READ_PKEY_FORMAT_STACK is set */
			if (!is_set(ctx->ops, READ_PKEY_FORMAT_STACK))
				ctx->done |= READ_PKEY_FORMAT_PEM;

			/* read PEM */
			uint8_t *data = NULL;
			char *name = NULL;
			char *header = NULL;
			long len = 0;
			if (PEM_read(ctx->file, &name, &header, &data, &len) != 1) {
				/* no further PEM available */
				ctx->done |= READ_PKEY_FORMAT_PEM;
				break;
			}

			/* parse by PEM name*/
			r = -EPROTOTYPE;
			if (r != 0 && is_set(ctx->ops, READ_PKEY_TYPE_PUB) && (strcmp(name, "PUBLIC KEY") == 0))
				r = parse_public_key(data, len, pkey);
			if (r != 0 && is_set(ctx->ops, READ_PKEY_TYPE_PRIV) && (strcmp(name, "PRIVATE KEY") == 0))
				r = parse_private_key(data, len, pkey);
			if (r == 0) {
				pr_dbg("%s[PEM%zu][%s]: %s-%d\n", ctx->path, ctx->pem_index, name, EVP_PKEY_get0_type_name(*pkey), EVP_PKEY_get_bits(*pkey));
			}
			else {
				pr_dbg("%s[PEM%zu][%s]: [%d] %s\n", ctx->path, ctx->pem_index, name, -r, strerror(-r));
			}
			OPENSSL_free(name);
			OPENSSL_free(header);
			OPENSSL_free(data);
			if (r == 0) {
				*path = ctx->path;
				return 0;
			}
		}
	}

	/* Read DER if requested */
	if (is_set(ctx->ops, READ_PKEY_FORMAT_DER) && !is_set(ctx->done, READ_PKEY_FORMAT_DER)) {

		/* No further DER processing  after this */
		ctx->done |= READ_PKEY_FORMAT_DER;

		/* rewind file in case it has been used for PEM parsing */
		rewind(ctx->file);

		/* read in up to 1mb from file */
		const size_t der_buf_size = 1 * 1024 * 1024;
		uint8_t *der_buf = malloc(der_buf_size);
		if (der_buf == NULL)
			return -ENOMEM;
		const long len = fread(der_buf, 1, der_buf_size, ctx->file);

		/* check for type by trying parsing */
		r = -EPROTOTYPE;
		if (r != 0 && is_set(ctx->ops, READ_PKEY_TYPE_PUB))
			r = parse_public_key(der_buf, len, pkey);
		if (r != 0 && is_set(ctx->ops, READ_PKEY_TYPE_PRIV))
			r = parse_private_key(der_buf, len, pkey);
		free(der_buf);
		if (r == 0) {
			*path = ctx->path;
			pr_dbg("%s[DER0]: %s-%d\n", ctx->path, EVP_PKEY_get0_type_name(*pkey), EVP_PKEY_get_bits(*pkey));
			return 0;
		}
		pr_dbg("%s[DER0]: [%d] %s\n", ctx->path, -r, strerror(-r));
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
			*pkey = key;
			*path = "pkcs11";
			pr_dbg("pkcs11: %s-%d\n", EVP_PKEY_get0_type_name(*pkey), EVP_PKEY_get_bits(*pkey));
			return 0;
		}

		/* pkcs11 store empty */
		ctx->done |= READ_PKEY_FORMAT_PKCS11;
	}

	return 1;
}

static int read_private_key(const char* key_path, const char* key_pkcs11, EVP_PKEY** pkey)
{
	int flags = READ_PKEY_TYPE_PRIV;
	if (key_path != NULL)
		flags |= READ_PKEY_FORMAT_DER | READ_PKEY_FORMAT_PEM;
	if (key_pkcs11 != NULL)
		flags |= READ_PKEY_FORMAT_PKCS11;

	struct read_pkey_ctx ctx;
	int r = read_pkey_ctx_create(&ctx, key_path, key_pkcs11, flags);
	if (r != 0)
		return r;

	char *name = NULL;
	r = read_pkey(&ctx, pkey, &name);
	read_pkey_ctx_free(&ctx);
	if (r > 0)
		r = -EBADF;
	return r;
}

static int read_and_match_public_key(const char* key_path, const char* key_pkcs11, const EVP_PKEY* pkey)
{
	int flags = READ_PKEY_TYPE_PUB;
	if (key_path != NULL)
		flags |= READ_PKEY_FORMAT_DER | READ_PKEY_FORMAT_PEM | READ_PKEY_FORMAT_STACK;
	if (key_pkcs11 != NULL)
		flags |= READ_PKEY_FORMAT_PKCS11;

	struct read_pkey_ctx ctx;
	int r = read_pkey_ctx_create(&ctx, key_path, key_pkcs11, flags);
	if (r != 0)
		return r;

	EVP_PKEY *compare = NULL;
	char *name = NULL;
	while ((r = read_pkey(&ctx, &compare, &name)) == 0) {
		const int result = compare_pkey(compare, pkey);
		EVP_PKEY_free(compare);
		if (result == 1) {
			r = 1;
			pr_info("%s: pubkey used for validation\n", name);
			goto exit;
		}
	}
	if (r > 0)
		r = 0;
exit:
	read_pkey_ctx_free(&ctx);
	return r;
}

static int match_pubkey(const char* pubkey, const char* pubkey_dir, const char* pubkey_pkcs11, const EVP_PKEY* pkey)
{
	if ((pubkey != NULL) || pubkey_pkcs11 != NULL) {
		if (read_and_match_public_key(pubkey, pubkey_pkcs11, pkey) == 1)
			return 0;
	}

	if (pubkey_dir != NULL) {
		int r = 0;
		DIR *dir = opendir(pubkey_dir);
		if (dir == NULL) {
			r = -errno;
			pr_dbg("%s: failed opendir: [%d] %s\n", pubkey_dir, -r, strerror(-r));
			return r;
		}

		struct dirent *entry = NULL;
		r = -EBADF;
		while ((entry = readdir(dir)) != NULL) {
			char *path = NULL;
			int r = asprintf(&path, "%s/%s", pubkey_dir, entry->d_name);
			if (r < 0) {
				r = -errno;
				pr_err("%s: failed asprintf: [%d]: %s\n", pubkey_dir, -r, strerror(-r));
				break;
			}

			/* Attempt comparison if path is regular file */
			struct stat st;
			memset(&st, 0, sizeof(st));
			r = -EBADF;
			if ((stat(path, &st) == 0) && S_ISREG(st.st_mode))
				r = read_and_match_public_key(path, NULL, pkey);
			free(path);
			if (r == 1)
				break;
		}
		closedir(dir);
		if (r == 1)
			return 0;
	}

	return -EBADF;
}

/* buf must be of size HEADER_SIZE */
static int create_container_header(struct container* container, uint8_t* buf, size_t size)
{
	if ((size != HEADER_SIZE) || (buf == NULL) || (container == NULL)
			|| (container->data.size == 0)   || (container->data.size > INT64_MAX)
			|| (container->tree.size == 0)   || (container->tree.size > INT64_MAX)
			|| (container->root.size == 0)   || (container->root.size > INT64_MAX)
			|| (container->digest.size == 0) || (container->digest.size > INT64_MAX)
			|| (container->key.size == 0)    || (container->key.size > INT64_MAX)
			|| (container->header.size == 0) || (container->header.size > INT64_MAX))
		return -EINVAL;

	/* fill in offsets */
	container->data.offset = 0;
	if (container->data.size > INT64_MAX)
		return -EINVAL;
	container->tree.offset = container->data.offset + container->data.size;
	if (container->tree.offset > INT64_MAX - (int64_t) container->tree.size)
		return -EINVAL;
	container->root.offset = container->tree.offset + container->tree.size;
	if (container->root.offset > INT64_MAX - (int64_t) container->root.size)
		return -EINVAL;
	container->digest.offset = container->root.offset + container->root.size;
	if (container->digest.offset > INT64_MAX - (int64_t) container->digest.size)
		return -EINVAL;
	container->key.offset = container->digest.offset + container->digest.size;
	if (container->key.offset > INT64_MAX - (int64_t) container->key.size)
		return -EINVAL;
	container->header.offset = container->key.offset + container->key.size;


	/* prepare header */
	struct header hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = HEADER_MAGIC;
	hdr.tree_offset = container->tree.offset;
	hdr.root_offset = container->root.offset;
	hdr.key_offset = container->key.offset;
	hdr.digest_offset = container->digest.offset;

	/* write to buffer */
	u32tole(hdr.magic, buf + offsetof(struct header, magic));
	memcpy(buf + offsetof(struct header, rsvd), &hdr.rsvd, member_size(struct header, rsvd));
	u64tole(hdr.tree_offset, buf + offsetof(struct header, tree_offset));
	u64tole(hdr.root_offset, buf + offsetof(struct header, root_offset));
	u64tole(hdr.digest_offset, buf + offsetof(struct header, digest_offset));
	u64tole(hdr.key_offset, buf + offsetof(struct header, key_offset));
	return 0;
}

static int read_container_header(int fd, struct container* container)
{
	/* Reposition to start of header */
	const off64_t header_pos = lseek64(fd, -HEADER_SIZE, SEEK_END);
	if (header_pos < 0) {
		if (errno == EINVAL) {
			return -ENOMSG; /* not of type container */
		}
		else {
			return -errno;
		}
	}

	/* read in header */
	uint8_t buf[HEADER_SIZE];
	int r = read_bytes(fd, buf, HEADER_SIZE);
	if (r != 0)
		return r;

	/* populate hdr */
	struct header hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = u32fromle(buf + offsetof(struct header, magic));
	if (hdr.magic != HEADER_MAGIC) {
		pr_dbg("hdr.magic 0x%" PRIx32 " not the expected 0x%" PRIx32 "\n", hdr.magic, HEADER_MAGIC)
		return -ENOMSG; /* not of type container */
	}
	memcpy(&hdr.rsvd, buf + offsetof(struct header, rsvd), member_size(struct header, rsvd));
	hdr.tree_offset = u64fromle(buf + offsetof(struct header, tree_offset));
	hdr.root_offset = u64fromle(buf + offsetof(struct header, root_offset));
	hdr.digest_offset = u64fromle(buf + offsetof(struct header, digest_offset));
	hdr.key_offset = u64fromle(buf + offsetof(struct header, key_offset));

	pr_dbg("hdr.tree_offset: 0x%" PRIx32 "\n", hdr.tree_offset);
	pr_dbg("hdr.root_offset: 0x%" PRIx32 "\n", hdr.root_offset);
	pr_dbg("hdr.digest_offset: 0x%" PRIx32 "\n", hdr.digest_offset);
	pr_dbg("hdr.key_offset: 0x%" PRIx32 "\n", hdr.key_offset);

	/* validate offsets, set size to 0 if invalid */
	container->header.offset = header_pos;
	container->header.size = HEADER_SIZE;
	container->key.offset = hdr.key_offset;
	container->key.size = header_pos > container->key.offset ? container->header.offset - container->key.offset : 0;
	container->digest.offset = hdr.digest_offset;
	container->digest.size = container->key.offset > container->digest.offset ? container->key.offset - container->digest.offset : 0;
	container->root.offset = hdr.root_offset;
	container->root.size = container->digest.offset > container->root.offset ? container->digest.offset - container->root.offset : 0;
	container->tree.offset = hdr.tree_offset;
	container->tree.size = container->root.offset > container->tree.offset ? container->root.offset - container->tree.offset : 0;
	container->data.offset = 0;
	container->data.size = container->tree.offset > container->data.offset ? container->tree.offset - container->data.offset : 0;

	/* check if any offset is invalid */
	if ((container->key.size == 0) || (container->digest.size == 0) || (container->root.size == 0)
		|| (container->tree.size == 0) || (container->data.size == 0) || (container->header.size == 0)) {
		pr_dbg("container - insane header offsets\n")
		return -ENOMSG; /* not of type container */
	}

	return 0;
}

static int create_digest(const uint8_t* data, size_t data_size, uint8_t** digest, size_t* digest_size, EVP_PKEY* pkey)
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

	/* Use SHA256 */
	algo = EVP_MD_fetch(NULL, "sha256", NULL);
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
/*
#include <openssl/store.h>
	int padding = 0;
	if (EVP_PKEY_CTX_get_rsa_padding(pctx, &padding) < 1) {
		pr_err("Cant check padding!");
		r = -EFAULT;
		goto exit;
	}
	printf("PADDING: %d\n", padding);
*/
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
	//EVP_PKEY_CTX_free(pctx);
	return r;
}

/* Return 1 for valid, 0 for invalid, else negative errno for error */
static int verify_digest(const uint8_t* data_buf, size_t data_size, uint8_t* digest_buf, size_t digest_size, EVP_PKEY* pkey)
{
	EVP_MD_CTX *ctx = NULL;
	EVP_MD *algo = NULL;

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

	/* Only sha256 supported */
	algo = EVP_MD_fetch(NULL, "sha256", NULL);
	if (algo == NULL) {
		pr_dbg("failed fetching digest algorithm\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	/* initialize */
	if (EVP_DigestVerifyInit(ctx, NULL, algo, NULL, pkey) != 1) {
		pr_dbg("failed initializing digest verification\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}

	/* verify */
	r = EVP_DigestVerify(ctx, digest_buf, digest_size, data_buf, data_size);
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

struct region {
	off64_t offset;
	size_t size;
	size_t extra;
	uint8_t **data;
};

static int read_container(struct container* container, int fd)
{
	/* read header */
	int r = read_container_header(fd, container);
	switch (r) {
	case 0:
		break;
	case -ENOMSG:
		container->opt = CONTAINER_NONE;
		return 0;
		break;
	default:
		pr_dbg("container - invalid header: [%d]: %s\n", -r, strerror(-r));
		return r;
	}

	if (container->key.size > LONG_MAX) /* d2i_PUBKEY() length argument is type long */
		return -ENOMSG; /* not a container */

	char *roothash = NULL;
	uint8_t *digest = NULL;
	uint8_t *pubkey = NULL;

	/* allocate and read metadata */
	const struct region regions[] = {
			{container->key.offset, container->key.size, 0, &pubkey},
			{container->digest.offset, container->digest.size, 0, &digest},
			/** allocate an extra byte for null-terminator, calloc ensure '\0' at end */
			{container->root.offset, container->root.size, 1, (uint8_t**) &roothash},
	};
	for (size_t i = 0; i < ARRAY_SIZE(regions); ++i) {
		*(regions[i].data) = calloc(1, regions[i].size + regions[i].extra);
		if (*(regions[i].data) == NULL) {
			r = -ENOMEM;
			goto exit;
		}
		r = pread_bytes(fd, regions[i].offset, *(regions[i].data), regions[i].size);
		if (r != 0) {
			pr_err("failed reading from FILE: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
	}

	/* parse pubkey */
	r = parse_public_key(pubkey, container->key.size, &container->pkey);
	if (r != 0) {
		pr_dbg("container - pubkey: [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* validate roothash signature */
	r = verify_digest((uint8_t*) roothash, container->root.size, (uint8_t*) digest, container->digest.size, container->pkey);
	switch (r) {
	case 1:
		container->opt |= CONTAINER_VALID;
		pr_dbg("container - valid\n");
		break;
	case 0:
		container->opt &= ~CONTAINER_VALID;
		pr_dbg("container - invalid signature\n");
		break;
	default:
		goto exit;
	}

	/* roothash from hex-encoding to bytes */
	ssize_t roothash_bytes = crypt_hex_to_bytes(roothash, (char**) &container->roothash, 0);
	if (roothash_bytes < 0) {
		r = -EBADF;
		goto exit;
	}
	container->roothash_size = (size_t) roothash_bytes;

	r = 0;
exit:
	if (roothash != NULL)
		free(roothash);
	if (digest != NULL)
		free(digest);
	if (pubkey != NULL)
		free(pubkey);
	return r;
}

static int verity_open(const char* path, const char* mapperpath, int flags, const struct container* container)
{
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
	params.flags = flags;
	params.hash_area_offset = container->tree.offset;
	r = crypt_load(cd, CRYPT_VERITY, &params);
	if (r != 0) {
		pr_err("crypt_load: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}

	/* confirm roothash size */
	const int hash_size = crypt_get_volume_key_size(cd);
	if (hash_size < 0) {
		pr_err("crypt_get_volume_key_size: unexpected size\n");
		r = -EFAULT;
		goto exit;
	}
	if (container->roothash_size != (size_t) hash_size) {
		pr_err("unexpected roothash size\n");
		r = -EBADF;
		goto exit;
	}

	/* verify */
	r = crypt_activate_by_signed_key(cd, mapperpath, (char*) container->roothash, container->roothash_size,
										NULL, 0, CRYPT_ACTIVATE_READONLY);
	if (r != 0) {
		pr_err("crypt_activate_by_signed_key: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}

	r = 0;
exit:
	if (cd != NULL)
		crypt_free(cd);
	return r;
}

static int verity_close(const char* mapperpath, int force)
{
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

static int verity_create(const char* path, const char* tree, uint8_t** roothash, size_t* roothash_size)
{
	uint8_t *hash = NULL;

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
	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, (char*) hash, &hash_bytes_returned, NULL, 0);
	if (r < 0) {
		pr_err("crypt_volume_key_get: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}
	if (hash_bytes_returned != (size_t) hash_size) {
		r = -EFAULT;
		pr_err("crypt_volume_key_get: unexpected roothash size: %zu\n", hash_bytes_returned);
		goto exit;
	}
	*roothash = hash;
	hash = NULL;
	*roothash_size = hash_bytes_returned;

	r = 0;
exit:
	crypt_free(cd);
	if (hash != NULL)
		free(hash);
	return r;
}

static int cat_container(const struct container* container, int fd, int treefd, uint8_t* roothash, uint8_t* digest, uint8_t* pubkey, uint8_t* header)
{
	int r = 0;
	uint8_t *buf = NULL;

	/* position output at end of file */
	if (lseek64(fd, 0, SEEK_END) < 0) {
		r = -errno;
		pr_err("failed seeking file [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* position tree at start of file */
	if (lseek64(treefd, 0, SEEK_SET) < 0) {
		r = -errno;
		pr_err("failed seeking tree [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* write tree to output */
	ssize_t bytes = 0;
	const size_t buf_size = 4096;
	buf = malloc(buf_size);
	if (buf == NULL) {
		r = -ENOMEM;
		goto exit;
	}
	while ((bytes = read(treefd, buf, buf_size)) > 0 ) {
		r = write_bytes(fd, buf, bytes);
		if (r != 0) {
			pr_err("failed writing to file: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
	}
	if (bytes < 0) {
		r = -errno;
		pr_err("failed reading tree [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* write metadata */
	const struct region regions[] = {
			{container->root.offset, container->root.size, 0, &roothash},
			{container->digest.offset, container->digest.size, 0, &digest},
			{container->key.offset, container->key.size, 0, &pubkey},
			{container->header.offset, container->header.size, 0, &header},
	};

	for (size_t i = 0; i < ARRAY_SIZE(regions); ++i) {
		r = pwrite_bytes(fd, regions[i].offset, *(regions[i].data), regions[i].size);
		if (r != 0) {
			pr_err("failed writing to FILE: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
	}

	r = 0;
exit:
	if (buf != NULL)
		free(buf);
	return r;
}

static int write_container(int fd, const char* path, EVP_PKEY* pkey, struct container* container)
{
	char tmppath[] = "/tmp/ctutil-XXXXXX";
	uint8_t *pubkey_buf = NULL;
	uint8_t *digest = NULL;
	char *hex = NULL;
	int r = 0;
	int tmpfd = -1;

	/* fd size must be padded to multiples of 4096 */
	r = padto_multiple_of(fd, 4096);
	if (r != 0) {
		pr_err("%s: failed padding: [%d]: %s\n", path, -r, strerror(-r));
		goto exit;
	}

	/* create temp-file for hash tree output */
	tmpfd = mkostemp(tmppath, O_CLOEXEC);
	if (tmpfd < 0) {
		r = -errno;
		pr_err("mktmp: [%d] %s\n", -r, strerror(-r));
		return r;
	}

	/* verity create */
	r = verity_create(path, tmppath, &container->roothash, &container->roothash_size);
	if (r != 0)
		goto exit;
	const off64_t data_size = lseek64(fd, 0, SEEK_END);
	if (data_size < 0) {
		r = -errno;
		pr_err("%s: failed getting data size [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}
	container->data.size = (size_t) data_size;
	const off64_t tree_size = lseek64(tmpfd, 0, SEEK_END);
	if (tree_size < 0) {
		r = -errno;
		pr_err("%s: failed getting tree size [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}
	container->tree.size = (size_t) tree_size;

	/* Sign hex-encoded roothash */
	size_t digest_size = 0;
	hex = crypt_bytes_to_hex(container->roothash_size, (char*) container->roothash);
	if (hex == NULL) {
		r = -EFAULT;
		goto exit;
	}
	container->root.size = strlen(hex);
	r = create_digest((uint8_t*) hex, container->root.size, &digest, &digest_size, pkey);
	if (r != 0)
		goto exit;
	container->digest.size = digest_size;

	/* retrieve pubkey */
	/* Ensure openssl errors are our errors */
	ERR_clear_error();
	const int pubkey_bytes = i2d_PUBKEY(pkey, (unsigned char**) &pubkey_buf);
	if (pubkey_bytes < 0) {
		pr_err("failed extracting pubkey\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
		goto exit;
	}
	container->key.size = (size_t) pubkey_bytes;

	/* create header */
	container->header.size = HEADER_SIZE;
	uint8_t header_buf[HEADER_SIZE];
	r = create_container_header(container, header_buf, container->header.size);
	if (r != 0) {
		pr_err("failed creating header: %[%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* concatenate parts */
	r = cat_container(container, fd, tmpfd, (uint8_t*) hex, digest, pubkey_buf, header_buf);
	if (r != 0) {
		pr_err("failed assembling container: %[%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* add signing key to container if needed */
	r = EVP_PKEY_up_ref(pkey);
	if (r != 1) {
		r = -EFAULT;
		pr_err("failed increment private key ref count\n");
		goto exit;
	}
	container->pkey = pkey;

	r = 0;
exit:
	if (unlink(tmppath) != 0)
		pr_info("failed removing tmpfile: %s\n", tmppath);
	close(tmpfd);
	if (digest != NULL)
		free(digest);
	if (pubkey_buf != NULL)
		free(pubkey_buf);
	if (hex != NULL)
		crypt_safe_free(hex);
	return r;
}

static void print_usage(void)
{
	printf("container-util, operate on image containers\n");
	printf("Usage:   container-util [OPTIONS] FILE\n");
	printf("\n");
	printf("Options:\n");
	printf("  -f/--force       Replace existing header\n");
	printf("  -d/--debug       Enable debug output\n");
	printf("  -q/--quiet       Silence output\n");
	printf("  -h/--help        This message\n");
	printf("  --verify         Verify signature\n");
	printf("  --create         Create signature\n");
	printf("  --open           Create a mapping with provided name\n");
	printf("  --close          Close a mapping with provided name\n");
	printf("                     Using --force will immediately deactivate and\n");
	printf("                     replace with error device for active users.\n");
	printf("  --keyfile        Path to signing key\n");
	printf("  --key-pkcs11     PKCS11 url for signing key\n");
	printf("  --pubkey         Path to validation key\n");
	printf("  --pubkey-pkcs11  PKCS11 URL for validation key\n");
	printf("  --pubkey-dir     Path to directory of validation keys\n");
	printf("  --pubkey-any     Use pubkey from container\n");
	printf("  --roothash       Dump roothash\n");
	printf("\n");
	printf("Input FILE size when creating a container should be a multiple of 4096,"
			"if not it will be zero-padded\n");
	printf("\n");
	printf("Examples:\n");
	printf("Create container and sign with keyfile:\n");
	printf(" container-util --keyfile private.pem rootfs.container\n");
	printf("Create container and sigh with pkcs11:\n");
	printf(" container-util --key-pkcs11 \"pkcs11:token=ms;object=test;pin-value=123456\" rootfs.container\n");
	printf("Verify container with keyfile:\n");
	printf(" container-util --pubkey private.pem rootfs.container\n");
	printf("Verify container with pkcs11:\n");
	printf(" container-util --pubkey-pkcs11 \"pkcs11:token=ms;object=test\" rootfs.container\n");
	printf("Open dm-verify mapping at /dev/mapper/rootfs\n");
	printf(" container-util --pubkey-any --open rootfs rootfs.container\n");
	printf("Close opened dm-verity mapping at /dev/mapper/rootfs\n");
	printf(" veritysetup close rootfs\n");
	printf("\n");
	printf("Return values:\n");
	printf("  0 if OK or error code\n");
	printf("Error codes:\n");
	printf(" 2  (ENOENT): No such file (or no permission)\n");
	printf(" 9  (EBADF):  Corrupt input FILE\n");
	printf(" 14 (EFAULT): Operation failed\n");
	printf(" 22 (EINVAL): Invalid argument\n");
	printf("\n");
}

enum options {
	OPT_VERIFY_ONLY  = 1 << 0,
	OPT_CREATE       = 1 << 1,
	OPT_OPEN         = 1 << 2,
	OPT_FORCE        = 1 << 3,
	OPT_ROOTHASH     = 1 << 4,
	OPT_PUBKEY_ANY   = 1 << 5,
	OPT_CLOSE        = 1 << 6,
};

struct config {
	int opt;
	char *filepath;
	char *mapperpath;
	char *key_path;
	char *key_pkcs11;
	char *pubkey_path;
	char *pubkey_pkcs11;
	char *pubkey_dir;
};

//NOLINTNEXTLINE(readability-function-cognitive-complexity)
int main(int argc, char *argv[])
{
	struct config cfg;
	memset(&cfg, 0, sizeof(cfg));

	for (int i = 1; i < argc; i++) {
		if (strcmp("--verify", argv[i]) == 0) {
			cfg.opt |= OPT_VERIFY_ONLY;
		}
		else if (strcmp("--create", argv[i]) == 0) {
			cfg.opt |= OPT_CREATE | OPT_PUBKEY_ANY;
		}
		else if (strcmp("--open", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --open\n");
				return EINVAL;
			}
			cfg.opt |= OPT_OPEN;
			cfg.mapperpath = argv[i];
		}
		else if (strcmp("--close", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --close\n");
				return EINVAL;
			}
			cfg.opt |= OPT_CLOSE;
			cfg.mapperpath = argv[i];
		}
		else if (strcmp("--keyfile", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --keyfile\n");
				return EINVAL;
			}
			cfg.key_path = argv[i];
		}
		else if (strcmp("--key-pkcs11", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --key-pkcs11\n");
				return EINVAL;
			}
			cfg.key_pkcs11 = argv[i];
		}
		else if (strcmp("--pubkey", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --pubkey\n");
				return EINVAL;
			}
			cfg.pubkey_path = argv[i];
		}
		else if (strcmp("--pubkey-pkcs11", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --pubkey-pkcs11\n");
				return EINVAL;
			}
			cfg.pubkey_pkcs11 = argv[i];
		}
		else if (strcmp("--pubkey-dir", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --pubkey-dir\n");
				return EINVAL;
			}
			cfg.pubkey_dir = argv[i];
		}
		else if (strcmp("--pubkey-any", argv[i]) == 0) {
			cfg.opt |= OPT_PUBKEY_ANY;
		}
		else if (strcmp("--debug", argv[i]) == 0 || strcmp("-d", argv[i]) == 0) {
			enable_debug();
		}
		else if (strcmp("--quiet", argv[i]) == 0 || strcmp("-q", argv[i]) == 0) {
			disable_info();
		}
		else if (strcmp("--help", argv[i]) == 0 || strcmp("-h", argv[i]) == 0) {
			print_usage();
			return EINVAL;
		}
		else if (strcmp("--force", argv[i]) == 0 || strcmp("-f", argv[i]) == 0) {
			cfg.opt |= OPT_FORCE;
		}
		else if (strcmp("--roothash", argv[i]) == 0) {
			cfg.opt |= OPT_ROOTHASH;
		}
		else if (cfg.filepath == NULL) {
			cfg.filepath = argv[i];
		}
		else {
			pr_err("invalid argument: %s\n", argv[i]);
			return EINVAL;
		}
	}

	if ((cfg.opt & (OPT_VERIFY_ONLY | OPT_CREATE | OPT_OPEN | OPT_ROOTHASH | OPT_CLOSE)) == 0) {
		pr_err("Missing operation --verify, --create, --open, --close or --roothash\n");
		return EINVAL;
	}

	/* close verity device */
	if ((cfg.opt & OPT_CLOSE) == OPT_CLOSE) {
		if (verity_close(cfg.mapperpath, cfg.opt & OPT_FORCE) != 0)
			return EFAULT;
		return 0;
	}

	if (cfg.filepath == NULL) {
		pr_err("Missing mandatory argument FILE\n");
		return EINVAL;
	}

	if ((cfg.opt & OPT_PUBKEY_ANY) == 0
			&& cfg.pubkey_path == NULL
			&& cfg.pubkey_pkcs11 == NULL
			&& cfg.pubkey_dir == NULL) {
		pr_err("Missing --pubkey, --pubkey-pkcs11, --pubkey-dir or --pubkey-any\n");
		return EINVAL;
	}

	/* If pkcs11 provider is required then default provider must be explicitly
	 * loaded as well.
	 * Always load default provider and load pkcs11 if required. */

	/* Ensure openssl errors are our errors */
	ERR_clear_error();

	OSSL_PROVIDER *provider_default = OSSL_PROVIDER_load(NULL, "default");
	if (provider_default == NULL) {
		pr_err("Failed loading openssl default provider\n");
		ERR_print_errors_cb(error_cb, NULL);
		return EFAULT;
	}
	OSSL_PROVIDER *provider_pkcs11 = NULL;
	if ((cfg.pubkey_pkcs11 != NULL) | (cfg.key_pkcs11 != NULL)) {
		provider_pkcs11 = OSSL_PROVIDER_load(NULL, "pkcs11");
		if (provider_pkcs11 == NULL) {
			pr_err("Failed loading openssl pkcs11 provider\n");
			ERR_print_errors_cb(error_cb, NULL);
			return EFAULT;
		}
	}

	struct container container;
	memset(&container, 0, sizeof(container));
	EVP_PKEY *signing_key = NULL;
	int r = 0;
	int filefd = -1;

	/* open FILE and validate as container */
	filefd = open(cfg.filepath, O_RDONLY | O_CLOEXEC);
	if (filefd < 0) {
		r = -errno;
		pr_err("%s: [%d] %s\n", cfg.filepath, cfg.filepath, -r, strerror(-r));
		goto exit;
	}

	r = read_container(&container, filefd);
	if (r != 0) {
		pr_err("%s: failed reading: [%d] %s\n", cfg.filepath, -r, strerror(-r));
		goto exit;
	}

	/* Match pubkey if container is valid.
	 *
	 * If OPT_PUBKEY_ANY is set then we are
	 * satisfied with digest verification towards
	 * pubkey provided by container as part of container
	 * validation. */
	if (((container.opt & CONTAINER_VALID) == CONTAINER_VALID)
			&& ((cfg.opt & OPT_PUBKEY_ANY) != OPT_PUBKEY_ANY)
			&& (match_pubkey(cfg.pubkey_path, cfg.pubkey_dir, cfg.pubkey_pkcs11, container.pkey) != 0)) {
		r = -EBADF;
		pr_err("pubkey validation failed\n");
		goto exit;
	}

	/* verify data and tree to roothash */
	if ((cfg.opt & OPT_VERIFY_ONLY) == OPT_VERIFY_ONLY) {
		if ((container.opt & CONTAINER_VALID) != CONTAINER_VALID) {
			pr_err("container - not a container\n");
			r = -EBADF;
			goto exit;
		}

		r = verity_open(cfg.filepath, NULL, CRYPT_VERITY_CHECK_HASH, &container);
		if (r < 0)
			goto exit;
		if (info)
			dump_container(&container);
		pr_info("container - verified\n");
		goto exit;
	}

	/* open as devicemapper block device */
	if ((cfg.opt & OPT_OPEN) == OPT_OPEN) {
		if ((container.opt & CONTAINER_VALID) != CONTAINER_VALID) {
			pr_err("container - not a container\n");
			r = -EBADF;
			goto exit;
		}
		r = verity_open(cfg.filepath, cfg.mapperpath, 0, &container);
		if (r != 0)
			goto exit;

		/* on success the roothash should be printed */
		cfg.opt = OPT_ROOTHASH;
	}

	/* dump roothash */
	if ((cfg.opt & OPT_ROOTHASH) == OPT_ROOTHASH) {
		if ((container.opt & CONTAINER_VALID) != CONTAINER_VALID) {
			pr_err("container - not a container\n");
			r = -EBADF;
			goto exit;
		}
		char *hex = crypt_bytes_to_hex(container.roothash_size, (char*) container.roothash);
		if (hex == NULL) {
			r = -EFAULT;
			goto exit;
		}
		printf("%s\n", hex);
		crypt_safe_free(hex);
		r = 0;
		goto exit;
	}

	/* create new header */
	if ((cfg.opt & OPT_CREATE) == OPT_CREATE) {
		if (((container.opt & CONTAINER_VALID) == CONTAINER_VALID)
			&& ((cfg.opt & OPT_FORCE) != OPT_FORCE)) {
			pr_err("FILE is valid container, use --force to overwrite\n");
			r = -EBADF;
			goto exit;
		}

		/* load private key */
		if ((cfg.opt & OPT_CREATE) == OPT_CREATE) {
			if ((cfg.key_path == NULL) && (cfg.key_pkcs11 == NULL)) {
				r = -EINVAL;
				pr_err("Missing key --keyfile or --key-pkcs11 for --create\n");
				goto exit;
			}
			if ((cfg.key_path != NULL) && (cfg.key_pkcs11 != NULL)) {
				r = -EINVAL;
				pr_err("--keyfile and --key-pkcs11 are mutually exclusive\n");
				goto exit;
			}
			r = read_private_key(cfg.key_path, cfg.key_pkcs11, &signing_key);
			if (r != 0) {
				pr_err("Could not read private key: [%d]: %s\n", -r, strerror(-r));
				goto exit;
			}
		}

		/* reopen for writing */
		close(filefd);
		filefd = open(cfg.filepath, O_RDWR | O_CLOEXEC);
		if (filefd < 0) {
			r = -errno;
			pr_err("%s: [%d] %s\n", cfg.filepath, -r, strerror(-r));
			goto exit;
		}

		/* remove header if available */
		if ((container.opt & CONTAINER_VALID) == CONTAINER_VALID) {
			if (container.data.offset != 0) {
				pr_err("expected data offset at 0 but got %" PRId64 "\n", container.data.offset);
				r = -EFAULT;
				goto exit;
			}
			r = ftruncate64(filefd, container.data.size);
			if (r != 0) {
				r = -errno;
				pr_err("%s: failed truncate: [%d]: %s\n", cfg.filepath, -r, strerror(-r));
				goto exit;
			}
		}
		/* add header */
		destroy_container(&container);
		r = write_container(filefd, cfg.filepath, signing_key, &container);
		if (info)
			dump_container(&container);
		pr_info("container - created\n");
		goto exit;
	}

	r = -EINVAL;
exit:
	if (filefd >= 0)
		close(filefd);
	destroy_container(&container);
	OSSL_PROVIDER_unload(provider_default);
	OSSL_PROVIDER_unload(provider_pkcs11);
	EVP_PKEY_free(signing_key);
	return -r;
}
