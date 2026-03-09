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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* Get sizeof() struct member */
#define member_size(type, member) (sizeof(((type *)0)->member))

/*
 * Add test if FILE is symbolic link
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
	CONTAINER_NONE = 0,
	CONTAINER_VERIFIED = 1 << 0,
};

struct container {
	struct section data;
	struct section tree;
	struct section root;
	struct section digest;
	struct section key;
	uint8_t *roothash;
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

static int read_header(int fd, struct container* container)
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

static int error_cb(const char* input, size_t len, void* priv)
{
	(void) priv;
	(void) len;
	printf("%s\n", input);
	return 0;
}

static int read_public_key(int fd, const struct section* section, EVP_PKEY** pkey)
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
	const unsigned char *tmp = buf;
	/* Ensure openssl errors are our errors */
	ERR_clear_error();
	*pkey = d2i_PUBKEY(NULL, &tmp, (long) section->size);
	if (*pkey == NULL) {
		if (dbg) {
			pr_dbg("Failed pubkey parsing\n");
			ERR_print_errors_cb(error_cb, NULL);
		}
		r = -EPROTONOSUPPORT;
		goto exit;
	}

	r = 0;
exit:
	free(buf);
	return r;
}

/* Return 1 for valid, 0 for invalid, else negative errno for error */
static int validate_digest(int fd, uint8_t* data_buf, size_t data_size, const struct section* digest, EVP_PKEY* pkey)
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
	int r = read_header(fd, container);
	switch (r) {
	case 0:
		break;
	case ENOMSG:
		container->opt = CONTAINER_NONE;
		return 0;
		break;
	default:
		pr_dbg("container - invalid header: [%d]: %s\n", -r, strerror(-r));
		return r;
	}

	/* read public key */
	r = read_public_key(fd, &container->key, &container->pkey);
	if (r != 0) {
		pr_dbg("container - pubkey: [%d]: %s\n", -r, strerror(-r));
		return r;
	}

	/* read roothash */
	container->roothash = malloc(container->root.size);
	if (container->roothash == NULL) {
		r = -ENOMEM;
		pr_dbg("container - roothash: [%d]: %s\n", -r, strerror(-r));
		return r;
	}
	r = pread_bytes(fd, container->root.offset, container->roothash, container->root.size);
	if (r != 0)
		return r;

	/* validate roothash */
	r = validate_digest(fd, container->roothash, container->root.size, &container->digest, container->pkey);
	switch (r) {
	case 1:
		container->opt |= CONTAINER_VERIFIED;
		pr_dbg("container - valid\n");
		break;
	default:
		container->opt &= ~CONTAINER_VERIFIED;
		pr_dbg("container - invalid signature\n");
		break;
	}
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
	printf("  --keyfile        Path to signing key\n");
	printf("  --key-pkcs11     PKCS11 url for signing key\n");
	printf("  --pubkey         Path to validation key\n");
	printf("  --pubkey-pkcs11  PKCS11 URL for validation key\n");
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
	OPT_VERIFY_ONLY = 1 << 0,
	OPT_CREATE      = 1 << 1,
	OPT_OPEN        = 1 << 2,
	OPT_FORCE       = 1 << 3,
	OPT_ROOTHASH    = 1 << 4,
	OPT_PUBKEY_ANY  = 1 << 5,
};

struct config {
	int opt;
	char *filepath;
	char *mapperpath;
	char *key_path;
	char *key_pkcs11;
	char *pubkey_path;
	char *pubkey_pkcs11;

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
				fprintf(stderr, "invalid argument --open\n");
				return EINVAL;
			}
			cfg.opt |= OPT_OPEN;
			cfg.mapperpath = argv[i];
		}
		else if (strcmp("--keyfile", argv[i]) == 0) {
			if (++i >= argc) {
				fprintf(stderr, "invalid argument --keyfile\n");
				return EINVAL;
			}
			cfg.key_path = argv[i];
		}
		else if (strcmp("--key-pkcs11", argv[i]) == 0) {
			if (++i >= argc) {
				fprintf(stderr, "invalid argument --key-pkcs11\n");
				return EINVAL;
			}
			cfg.key_pkcs11 = argv[i];
		}
		else if (strcmp("--pubkey", argv[i]) == 0) {
			if (++i >= argc) {
				fprintf(stderr, "invalid argument --pubkey\n");
				return EINVAL;
			}
			cfg.pubkey_path = argv[i];
		}
		else if (strcmp("--pubkey-pkcs11", argv[i]) == 0) {
			if (++i >= argc) {
				fprintf(stderr, "invalid argument --pubkey-pkcs11\n");
				return EINVAL;
			}
			cfg.pubkey_pkcs11 = argv[i];
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
			fprintf(stderr, "invalid argument: %s\n", argv[i]);
			return EINVAL;
		}
	}

	if ((cfg.opt & (OPT_VERIFY_ONLY | OPT_CREATE | OPT_OPEN | OPT_ROOTHASH)) == 0) {
		fprintf(stderr, "Missing operation --verify, --create, --open or --roothash\n");
		return EINVAL;
	}

	if (cfg.filepath == NULL) {
		fprintf(stderr, "Missing mandatory argument FILE\n");
		return EINVAL;
	}

	if ((cfg.opt & OPT_PUBKEY_ANY) == 0
			&& cfg.pubkey_path == NULL
			&& cfg.pubkey_pkcs11 == NULL) {
		fprintf(stderr, "Missing pubkey --pubkey, --pubkey-pkcs11 or --pubkey-any\n");
		return EINVAL;
	}

	if ((cfg.opt & OPT_CREATE) == OPT_CREATE
			&& cfg.key_path == NULL
			&& cfg.key_pkcs11 == NULL) {
		fprintf(stderr, "Missing key --keyfile or --key-pkcs11 for --create\n");
		return EINVAL;
	}

	int r = 0;
	struct container container;
	memset(&container, 0, sizeof(container));

	/* open file and validate if found */
	int filefd = open(cfg.filepath, O_RDONLY);
	if (filefd >= 0) {
		pr_dbg("%s: found file\n", cfg.filepath);
		r = read_container(&container, filefd);
		if (r != 0)
			goto exit;
	}
	else if (errno == ENOENT) {
		/* Depending on operation a non existing file might be OK. */
		pr_dbg("%s: not found\n", cfg.filepath);
	}
	else {
		r = -errno;
		pr_err("%s: [%d] %s\n", cfg.filepath, -r, strerror(-r));
		goto exit;
	}

	if (cfg.opt & OPT_ROOTHASH)


exit:
	if (filefd >= 0)
		close(filefd);
	destroy_container(&container);
	pr_dbg("exit: %d\n", r);
	return r;
}
