// SPDX-License-Identifier: GPL-2.0-or-later

//NOLINTNEXTLINE(bugprone-reserved-identifier)
#define _LARGEFILE64_SOURCE /* For lseek64() */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "log.h"
#include "header.h"
#include "verity.h"
#include "crypt.h"

/* return number of elements in array */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* xstr() will return string literal from symbol content */
#define xstr(a) str(a)
#define str(a) #a

/* check bit-flag */
static inline int is_set(int flag, int mask)
{
	return (flag & mask) == mask;
}

struct section {
	off64_t offset;
	size_t size;
};

enum container_flags {
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
	char *roothash;
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

static const char* hash_function(const EVP_PKEY* pkey)
{
	const char *hash = crypt_pkey_hash_function(pkey);
	if (hash == NULL)
		return "UNSUPPORTED";
	return hash;
}

static void dump_container(const struct container* container)
{
	const char* key_type = EVP_PKEY_get0_type_name(container->pkey);

	printf("container:\n"
			"  section   offset     size\n"
			"  data:     %-10" PRIu64 " [%zu b]\n"
			"  tree:     %-10" PRIu64 " [%zu b]\n"
			"  root:     %-10" PRIu64 " [%zu b]\n"
			"  pubkey:   %-10" PRIu64 " [%zu b]\n"
			"  digest:   %-10" PRIu64 " [%zu b]\n"
			"  header:   %-10" PRIu64 " [%zu b]\n"
			"  key type: %s-%d + %s\n"
			"  roothash: %s\n",
				container->data.offset, container->data.size,
				container->tree.offset, container->tree.size,
				container->root.offset, container->root.size,
				container->key.offset, container->key.size,
				container->digest.offset, container->digest.size,
				container->header.offset, container->header.size,
				key_type ? key_type : "unknown", EVP_PKEY_get_bits(container->pkey),
				hash_function(container->pkey), container->roothash);
}

static int write_bytes(int fd, const uint8_t* buf, size_t size)
{
	if (size > SSIZE_MAX)
		return -EINVAL;
	ssize_t bytes_remaining = (ssize_t) size;
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

static int pwrite_bytes(int fd, off64_t offset, const uint8_t* buf, size_t bytes)
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
	pr_info("WARNING: padding FILE from %lld by %lld to %lld\n", size, remaining, size + remaining);
	uint8_t *buf = malloc(remaining);
	if (buf == NULL)
		return -ENOMEM;
	memset(buf, 0, remaining);
	int r = write_bytes(fd, buf, remaining);
	free(buf);
	return r;
}

static int read_bytes(int fd, uint8_t* buf, size_t size)
{
	if (size > SSIZE_MAX)
		return -EINVAL;
	ssize_t bytes_remaining = (ssize_t) size;
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

static int pread_bytes(int fd, off64_t offset, uint8_t* buf, size_t bytes)
{
	const off64_t pos = lseek64(fd, offset, SEEK_SET);
	if (pos < 0)
		return -errno;
	return read_bytes(fd, buf, bytes);
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

static int read_private_key(const char* key_path, const char* key_pkcs11, EVP_PKEY** pkey)
{
	struct crypt_read_pkey_ctx *ctx = NULL;
	int r = crypt_read_pkey_ctx_create(&ctx, key_path, key_pkcs11, CRYPT_READ_PRIV);
	if (r != 0)
		return r;

	char *name = NULL;
	r = crypt_read_pkey(ctx, pkey, &name);
	crypt_read_pkey_ctx_free(ctx);
	if (r > 0)
		r = -EBADF;
	free(name);
	return r;
}

static int read_and_match_public_key(const char* key_path, const char* key_pkcs11, const EVP_PKEY* pkey)
{
	struct crypt_read_pkey_ctx *ctx = NULL;
	int r = crypt_read_pkey_ctx_create(&ctx, key_path, key_pkcs11, CRYPT_READ_PUB);
	if (r != 0)
		return r;

	EVP_PKEY *compare = NULL;
	char *name = NULL;
	while ((r = crypt_read_pkey(ctx, &compare, &name)) == 0) {
		const int result = compare_pkey(compare, pkey);
		EVP_PKEY_free(compare);
		compare = NULL;
		if (result == 1) {
			r = 1;
			pr_info("%s: pubkey used for validation\n", name);
			free(name);
			goto exit;
		}
		free(name);
	}
	if (r > 0)
		r = 0;
exit:
crypt_read_pkey_ctx_free(ctx);
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
			if (asprintf(&path, "%s/%s", pubkey_dir, entry->d_name) < 0) {
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
	if ((size != HEADER_SIZE) || (buf == NULL) || (container == NULL))
		return -EINVAL;

	/* validate size and fill in offsets with no overlap */
	struct section *sections[] = {
		&container->data, &container->tree, &container->root,
		&container->digest, &container->key, &container->header
	};
	off64_t previous_end = 0;
	for (size_t i = 0; i < ARRAY_SIZE(sections); ++i) {
		if ((sections[i]->size == 0)
			|| (sections[i]->size > INT64_MAX)
			|| ((INT64_MAX - sections[i]->size) < (size_t) previous_end))
			return -EINVAL;
		sections[i]->offset = previous_end;
		previous_end = sections[i]->offset + (off64_t) sections[i]->size;
	}

	/* prepare header */
	struct header hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = HEADER_MAGIC;
	hdr.tree_offset = container->tree.offset;
	hdr.root_offset = container->root.offset;
	hdr.key_offset = container->key.offset;
	hdr.digest_offset = container->digest.offset;

	return container_header_serialize(&hdr, buf, size);
}

/* return -1 if too large */
static off64_t size_to_off64(size_t input)
{
	return input > INT64_MAX ? -1 : (off64_t) input;
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

	struct header hdr;
	r = container_header_parse(&hdr, buf, HEADER_SIZE);
	if (r != 0)
		return r;

	pr_dbg("hdr.tree_offset: 0x%" PRIx64 "\n", hdr.tree_offset);
	pr_dbg("hdr.root_offset: 0x%" PRIx64 "\n", hdr.root_offset);
	pr_dbg("hdr.digest_offset: 0x%" PRIx64 "\n", hdr.digest_offset);
	pr_dbg("hdr.key_offset: 0x%" PRIx64 "\n", hdr.key_offset);

	container->data.offset = 0;
	container->tree.offset = size_to_off64(hdr.tree_offset);
	container->root.offset = size_to_off64(hdr.root_offset);
	container->digest.offset = size_to_off64(hdr.digest_offset);
	container->key.offset = size_to_off64(hdr.key_offset);
	container->header.offset = header_pos;

	/* Calculate and validate sections sizes with no overlap */
	struct section *sections[] = {
		&container->header, &container->key, &container->digest,
		&container->root, &container->tree, &container->data
	};

	off64_t previous_offset = (INT64_MAX - header_pos) > HEADER_SIZE ? header_pos + HEADER_SIZE : 0;
	for (size_t i = 0; i < ARRAY_SIZE(sections); ++i) {
		if ((sections[i]->offset < 0)
			|| (sections[i]->offset >= previous_offset))
			return -ENOMSG;
		sections[i]->size = previous_offset - sections[i]->offset;
		previous_offset = sections[i]->offset;
	}

	return 0;
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

	uint8_t *digest = NULL;
	uint8_t *pubkey = NULL;

	/* allocate and read metadata */
	const struct region regions[] = {
			{container->key.offset, container->key.size, 0, &pubkey},
			{container->digest.offset, container->digest.size, 0, &digest},
			/** allocate an extra byte for null-terminator, calloc ensure '\0' at end */
			{container->root.offset, container->root.size, 1, (uint8_t**) &container->roothash},
	};
	for (size_t i = 0; i < ARRAY_SIZE(regions); ++i) {
		/* check for overflow */
		if ((SIZE_MAX - regions[i].size) < regions[i].extra) {
			r = -EINVAL;
			goto exit;
		}
		// Following error looks like false positive and thus ignored.
		//NOLINTNEXTLINE(clang-analyzer-optin.portability.UnixAPI)
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
	r = crypt_parse_public_key(pubkey, container->key.size, &container->pkey);
	if (r != 0) {
		pr_dbg("container - pubkey: [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* validate roothash signature */
	r = crypt_digest_verity((uint8_t*) container->roothash, container->root.size, digest, container->digest.size, container->pkey);
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

	r = 0;
exit:
	if (digest != NULL)
		free(digest);
	if (pubkey != NULL)
		free(pubkey);
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
	r = verity_create(path, tmppath, &container->roothash);
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

	/* Sign roothash */
	container->root.size = strlen(container->roothash);
	size_t digest_size = 0;
	r = crypt_digest_create((uint8_t*) container->roothash, container->root.size, &digest, &digest_size, pkey);
	if (r != 0)
		goto exit;
	container->digest.size = digest_size;

	/* retrieve pubkey */
	r = crypt_serialize_public_key(&pubkey_buf, &container->key.size, pkey);
	if (r != 0) {
		pr_err("failed extracting pubkey [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* create header */
	container->header.size = HEADER_SIZE;
	uint8_t header_buf[HEADER_SIZE];
	r = create_container_header(container, header_buf, container->header.size);
	if (r != 0) {
		pr_err("failed creating header: %[%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* concatenate parts */
	r = cat_container(container, fd, tmpfd, (uint8_t*) container->roothash, digest, pubkey_buf, header_buf);
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
	printf("  --version        Dump version\n");
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
	printf(" container-util --close rootfs\n");
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
		else if (strcmp("--version", argv[i]) == 0) {
			printf("%s\n", xstr(SRC_VERSION));
			return EINVAL;
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

	struct crypt_ctx *cctx = NULL;
	struct container container;
	memset(&container, 0, sizeof(container));
	EVP_PKEY *signing_key = NULL;
	int filefd = -1;
	int r = 0;

	/* crypt context must be loaded before any crypt or openssl calls */
	int crypt_flags = 0;
	if (cfg.pubkey_pkcs11 != NULL || cfg.key_pkcs11 != NULL)
		crypt_flags |= CRYPT_CTX_INIT_PKCS11;
	r = crypt_ctx_create(&cctx, crypt_flags);
	if (r != 0) {
		pr_err("Failed loading cryptographic context: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}

	/* open FILE and validate as container */
	filefd = open(cfg.filepath, O_RDONLY | O_CLOEXEC);
	if (filefd < 0) {
		r = -errno;
		pr_err("%s: [%d] %s\n", cfg.filepath -r, strerror(-r));
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

		r = verity_open(cfg.filepath, container.tree.offset, NULL, VERITY_VERIFY, container.roothash);
		if (r < 0)
			goto exit;
		if (info)
			dump_container(&container);
		pr_info("File verified OK\n");
		goto exit;
	}

	/* open as devicemapper block device */
	if ((cfg.opt & OPT_OPEN) == OPT_OPEN) {
		if ((container.opt & CONTAINER_VALID) != CONTAINER_VALID) {
			pr_err("container - not a container\n");
			r = -EBADF;
			goto exit;
		}
		r = verity_open(cfg.filepath, container.tree.offset, cfg.mapperpath, 0, container.roothash);
		if (r != 0)
			goto exit;

		/* on success the roothash should be printed */
		printf("%s\n", container.roothash);
		r = 0;
		goto exit;
	}

	/* dump roothash */
	if ((cfg.opt & OPT_ROOTHASH) == OPT_ROOTHASH) {
		if ((container.opt & CONTAINER_VALID) != CONTAINER_VALID) {
			pr_err("container - not a container\n");
			r = -EBADF;
			goto exit;
		}
		printf("%s\n", container.roothash);
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
			if (container.data.size > INT64_MAX) {
				pr_err("FILE data larger than maximum supported");
				r = -EFAULT;
				goto exit;
			}
			r = ftruncate64(filefd, (ssize_t) container.data.size);
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
	crypt_ctx_free(cctx);
	EVP_PKEY_free(signing_key);
	pr_dbg("exit code: [%d]: %s\n", -r, strerror(-r));
	return -r;
}
