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
#include <libcryptsetup.h>

// FIXME:  Add test if FILE is symbolic link
// FIXME:  GPL-2.0-or-later
// FIXME:  cryptsetup license
// FIXME:  Test --pubkey with PEM
// FIXME:  Test --pubkey with DER
// FIXME:  Test --pubkey with mixed PEM object types (!= PUBLIC KEY)
// FIXME:  Test --pubkey-dir
// FIXME:  Add --dump to print header details incl. signing key type (and hash..?)
// FIXME:  Select hash based on key type
// FIXME:  runtime dependency packages: pkcs11-provider
// FIXME:  Do file-based public keys need to be validated? EVP_PKEY_public_check() ?
// FIXME:  data 4096 aligned

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

/*
 *
 */

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

/*
static void u32tole(uint32_t in, uint8_t* buf)
{
	buf[0] = in & 0xff;
	buf[1] = (in >> 8) & 0xff;
	buf[2] = (in >> 16) & 0xff;
	buf[3] = (in >> 24) & 0xff;
}
*/
static uint32_t u32fromle(const uint8_t* buf)
{
	const uint32_t out =
		buf[0]
		| (buf[1] << 8)
		| (buf[2] << 16)
		| (buf[3] << 24);
	return out;
}
/*
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
*/
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
static int compare_public_key(const EVP_PKEY* to_compare, const EVP_PKEY* pkey)
{
	pr_dbg("key type: %s\n", EVP_PKEY_get0_type_name(to_compare));
	int r = 0;

	/* compare keys */
	switch (EVP_PKEY_eq(pkey, to_compare)) {
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

/*
 * return 1 if equal
 *        0 if not equal
 *        negative errno for error
 */
static int compare_public_key_der(const uint8_t* der, long size, const EVP_PKEY* pkey)
{
	/* parse key */
	EVP_PKEY *to_compare = NULL;
	int r = parse_public_key(der, size, &to_compare);
	if (r != 0)
		return r;

	/* compare keys */
	r = compare_public_key(to_compare, pkey);
	EVP_PKEY_free(to_compare);
	return r;
}

static int read_and_compare_public_key(const char* path, const EVP_PKEY* pkey)
{
	int r = 0;
	/* Open as stream for PEM_read() compatibility */
	FILE *file = fopen(path, "r");
	if (file == NULL) {
		r = -errno;
		pr_err("%s: fdopen [%d] %s\n", path, -r, strerror(-r));
		return r;
	}

	uint8_t *data = NULL;
	char *name = NULL;
	char *header = NULL;
	long len = 0;

	/* Check first if pubkey is DER formatted
	 * by reading in 1MB to pre-allocated
	 * buffers mimicking PEM_read() usage. */
	const size_t der_buf_size = 1 * 1024 * 1024;
	r = -ENOMEM;
	data = OPENSSL_malloc(der_buf_size);
	if (data == NULL)
		goto exit;
	name = OPENSSL_strdup("PUBLIC KEY");
	if (name == NULL)
		goto exit;
	len = fread(data, 1, der_buf_size, file);

	/* rewind file for PEM parsing if DER fails */
	rewind(file);

	/* Keep track of DER/PEM and PEM count for improved
	 * debug messages */
	int is_PEM = 0;
	int PEM_count = -1;

	do {
		r = 0;

		pr_dbg("%s: %s%d checking\n", path, is_PEM ? "PEM" : "DER", is_PEM ? PEM_count : 0);

		if (strcmp(name, "PUBLIC KEY") == 0)
			r = compare_public_key_der(data, len, pkey);

		OPENSSL_free(name);
		name = NULL;
		OPENSSL_free(header);
		header = NULL;
		OPENSSL_free(data);
		data = NULL;


		if (r == 1) {
			pr_info("%s: pubkey used for validation\n", path);
			goto exit;
		}

		is_PEM = 1;
		PEM_count++;

	/* Check for PEM, single or stack */
	} while (PEM_read(file, &name, &header, &data, &len) == 1);

	r = 0;
exit:
	OPENSSL_free(data);
	OPENSSL_free(name);
	OPENSSL_free(header);
	fclose(file);
	return r;
}

static int read_and_compare_public_dir(const char* pubkey_dir, const EVP_PKEY* pkey)
{
	int r = 0;
	DIR *dir = opendir(pubkey_dir);
	if (dir == NULL) {
		r = -errno;
		pr_dbg("%s: failed opendir: [%d] %s\n", pubkey_dir, -r, strerror(-r));
		return r;
	}

	struct dirent *entry = NULL;
	while ((entry = readdir(dir)) != NULL) {
		char *path = NULL;
		r = asprintf(&path, "%s/%s", pubkey_dir, entry->d_name);
		if (r < 0) {
			r = -errno;
			pr_err("%s: failed asprintf: [%d]: %s\n", pubkey_dir, -r, strerror(-r));
			goto exit;
		}
		/* Attemt comparison if path is regular file */
		struct stat st;
		memset(&st, 0, sizeof(st));
		r = 0;
		if (stat(path, &st) == 0) {
			if (S_ISREG(st.st_mode))
				r = read_and_compare_public_key(path, pkey);
		}
		else {
			pr_dbg("%s: failed stat: [%d]: %s\n", path, errno, strerror(errno));
		}
		free(path);

		if (r == 1)
			goto exit;
	}
	r = -errno; /* errno will be 0 on end of stream, else error */
	if (r != 0)
		pr_dbg("%s: failed readdir: [%d]: %s\n", pubkey_dir, -r, strerror(-r));

exit:
	closedir(dir);
	return r;
}

static int read_and_compare_public_pkcs11(const char* pubkey_pkcs11, const EVP_PKEY* pkey)
{
	(void) pkey;

	/* Ensure openssl errors are our errors */
	ERR_clear_error();

	OSSL_STORE_CTX *store = OSSL_STORE_open(pubkey_pkcs11, NULL, NULL, NULL, NULL);
	if (store == NULL) {
		pr_err("pkcs11 OSSL_STORE_open failed\n");
		ERR_print_errors_cb(error_cb, NULL);
		return -EFAULT;
	}

	/* Notify store we are looking for public key */
	int r = OSSL_STORE_expect(store, OSSL_STORE_INFO_PUBKEY);
	if (r != 1) {
		pr_err("pkcs11 OSSL_STORE_expect failed\n");
		ERR_print_errors_cb(error_cb, NULL);
		return -EFAULT;
	}

	/* Search for pubkey in store */
	OSSL_STORE_INFO *info = NULL;
	while((info = OSSL_STORE_load(store)) != NULL) {
		EVP_PKEY* to_compare = OSSL_STORE_INFO_get0_PUBKEY(info);
		r = to_compare != NULL ? compare_public_key(to_compare, pkey) : 0;
		OSSL_STORE_INFO_free(info);
		info = NULL;
		if (r == 1)
			return r;
	}

	/* OSSL_STORE_close(store);
	* will cause a segmentation fault on OSSL_PROVIDER_unload(pkcs11_provider).
	* Is this close method redundant? */

	return 0;
}

static int match_pubkey(const char* pubkey, const char* pubkey_dir, const char* pubkey_pkcs11, const EVP_PKEY* pkey)
{
	if (pubkey) {
		pr_dbg("match container pubkey to --pubkey\n");
		if (read_and_compare_public_key(pubkey, pkey) == 1)
			return 0;
	}
	if (pubkey_dir) {
		pr_dbg("match container pubkey to --pubkey-dir\n");
		if (read_and_compare_public_dir(pubkey_dir, pkey) == 1)
			return 0;
	}
	if (pubkey_pkcs11) {
		pr_dbg("match container pubkey to --pubkey-pkcs11\n");
		if (read_and_compare_public_pkcs11(pubkey_pkcs11, pkey) == 1)
			return 0;
	}

	return -EBADF;
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
	if (hdr.magic != HEADER_MAGIC)
		return -ENOMSG; /* not of type container */
	memcpy(&hdr.rsvd, buf + offsetof(struct header, rsvd), member_size(struct header, rsvd));
	hdr.tree_offset = u64fromle(buf + offsetof(struct header, tree_offset));
	hdr.root_offset = u64fromle(buf + offsetof(struct header, root_offset));
	hdr.digest_offset = u64fromle(buf + offsetof(struct header, digest_offset));
	hdr.key_offset = u64fromle(buf + offsetof(struct header, key_offset));

	/* validate offsets, set size to 0 if invalid */
	container->key.offset = hdr.key_offset;
	container->key.size = header_pos > container->key.offset ? header_pos - container->key.offset : 0;
	container->digest.offset = hdr.digest_offset;
	container->digest.size = container->key.offset > container->digest.offset ? container->key.offset - container->digest.offset : 0;
	container->root.offset = hdr.root_offset;
	container->root.size = container->digest.offset > container->root.offset ? container->digest.offset - container->root.offset : 0;
	container->tree.offset = hdr.tree_offset;
	container->tree.size = container->root.offset > container->tree.offset ? container->root.offset - container->tree.offset : 0;
	container->data.offset = 0;
	container->data.size = container->tree.offset > container->data.offset ? container->tree.offset - container->data.offset : 0;

	pr_dbg("header:\n"
			"  data:   %-10" PRIu64 " [%zu b]\n"
			"  tree:   %-10" PRIu64 " [%zu b]\n"
			"  root:   %-10" PRIu64 " [%zu b]\n"
			"  key:    %-10" PRIu64 " [%zu b]\n"
			"  digest: %-10" PRIu64 " [%zu b]\n",
				container->data.offset, container->data.size, container->tree.offset, container->tree.size,
				container->root.offset, container->root.size, container->key.offset, container->key.size,
				container->digest.offset, container->digest.size);

	/* check if any offset is invalid */
	if ((container->key.size == 0) | (container->digest.size == 0) | (container->root.size == 0)
		| (container->tree.size == 0) | (container->data.size == 0)) {
		pr_dbg("container - insane header offsets\n")
		return -ENOMSG; /* not of type container */
	}

	return 0;
}

static int read_container_public_key(int fd, const struct section* section, EVP_PKEY** pkey)
{
	if (section->size > LONG_MAX) /* d2i_PUBKEY() length argument is type long */
		return -EINVAL;

	/* Read to buffer */
	uint8_t *buf = malloc(section->size);
	if (buf == NULL)
		return -ENOMEM;
	int r = pread_bytes(fd, section->offset, buf, section->size);
	if (r != 0)
		goto exit;

	/* parse key */
	r = parse_public_key(buf, section->size, pkey);
	if (r != 0)
		goto exit;

	r = 0;
exit:
	free(buf);
	return r;
}

/* Return 1 for valid, 0 for invalid, else negative errno for error */
static int verify_container_digest(int fd, uint8_t* data_buf, size_t data_size, const struct section* digest, EVP_PKEY* pkey)
{
	uint8_t *digest_buf = NULL;
	EVP_MD_CTX *ctx = NULL;
	EVP_MD *algo = NULL;

	/* allocate */
	int r = -ENOMEM;
	digest_buf = malloc(digest->size);
	if (digest_buf == NULL)
		goto exit;

	/* read */
	r = pread_bytes(fd, digest->offset, digest_buf, digest->size);
	if (r != 0)
		goto exit;

	/* Ensure openssl errors are our errors */
	ERR_clear_error();

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
	r = EVP_DigestVerify(ctx, digest_buf, digest->size, data_buf, data_size);
	if (r != 0 && r != 1) {
		pr_dbg("failed verifying digest\n");
		ERR_print_errors_cb(error_cb, NULL);
		r = -ENOSYS;
	}

exit:
	if (digest_buf != NULL)
		free(digest_buf);
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(algo);
	return r;
}

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

	char *roothash = NULL;

	/* read public key */
	r = read_container_public_key(fd, &container->key, &container->pkey);
	if (r != 0) {
		pr_dbg("container - pubkey: [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* read roothash, allocate an extra byte for null-terminator
	 * for crypt_hex_to_bytes() */
	roothash = calloc(1, container->root.size + 1);
	if (roothash == NULL) {
		r = -ENOMEM;
		goto exit;
	}
	r = pread_bytes(fd, container->root.offset, (uint8_t*) roothash, container->root.size);
	if (r != 0)
		goto exit;

	/* validate roothash */
	r = verify_container_digest(fd, (uint8_t*) roothash, container->root.size, &container->digest, container->pkey);
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

static int write_container(int fd, const char* path, const char* key, const char* key_pkcs11, struct container* container)
{
	(void) fd; (void) key; (void) key_pkcs11;
	int r = 0;
	/* create temp-file for hash tree output */
	char tmppath[] = "/tmp/ctutil-XXXXXX";
	int tmpfd = mkostemp(tmppath, O_CLOEXEC);
	if (tmpfd < 0) {
		r = -errno;
		pr_err("mktmp: [%d] %s\n", -r, strerror(-r));
		return r;
	}

	/* verity format */
	r = verity_create(path, tmppath, &container->roothash, &container->roothash_size);
	if (r != 0)
		goto exit;

	r = 0;
exit:
	if (unlink(tmppath) != 0)
		pr_info("failed removing tmpfile: %s\n", tmppath);
	close(tmpfd);
	return r;
}

static void print_usage(void)
{
	printf("container-util, operate on image containers\n");
	printf("Usage:   container-util [OPTIONS] FILE\n");
	printf("Example: serial-echo --mode raw -b 9600 /dev/ttymxc2\n");
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

	EVP_PKEY *signing_key = NULL;
	if ((cfg.opt & OPT_CREATE) == OPT_CREATE) {
		if ((cfg.key_path == NULL) && (cfg.key_pkcs11 == NULL)) {
			pr_err("Missing key --keyfile or --key-pkcs11 for --create\n");
			return EINVAL;
		}
		if ((cfg.key_path != NULL) && (cfg.key_pkcs11 != NULL)) {
			pr_err("--keyfile and --key-pkcs11 are mutually exclusive\n");
			return EINVAL;
		}
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

	int r = 0;
	struct container container;
	memset(&container, 0, sizeof(container));

	/* open FILE and validate as container */
	int filefd = open(cfg.filepath, O_RDONLY | O_CLOEXEC);
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
		pr_info("container - verified\n");
		goto exit;
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

	/* open as devicemapper block device */
	if ((cfg.opt & OPT_OPEN) == OPT_OPEN) {
		if ((container.opt & CONTAINER_VALID) != CONTAINER_VALID) {
			pr_err("container - not a container\n");
			r = -EBADF;
			goto exit;
		}
		r = verity_open(cfg.filepath, cfg.mapperpath, 0, &container);
		if (r == 0)
			pr_info("container - opened\n");
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
		r = write_container(filefd, cfg.filepath, cfg.key_path, cfg.key_pkcs11, &container);
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
