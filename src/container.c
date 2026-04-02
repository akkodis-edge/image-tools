// SPDX-License-Identifier: GPL-2.0-or-later
//NOLINTNEXTLINE(bugprone-reserved-identifier)
#define _LARGEFILE64_SOURCE /* For lseek64() */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include "log.h"
#include "crypt.h"
#include "verity.h"
#include "header.h"
#include "container.h"

enum container_flags {
	CONTAINER_NONE     = 0,
	CONTAINER_VALID    = 1 << 0, /* container header validated */
};

struct container {
	char *path;
	size_t size;
	struct header hdr;
	char *roothash;
	CMS_ContentInfo *cms;
	EVP_PKEY *pubkey;
	EVP_PKEY *signing_key;
	X509 *signing_cert;
	int opt;
};

static const char* hash_function(const EVP_PKEY* pkey)
{
	const char *hash = crypt_pkey_hash_function(pkey);
	if (hash == NULL)
		return "UNSUPPORTED";
	return hash;
}

static void dump_pkey(const EVP_PKEY* pkey, const char* hash)
{
	const char* key_type = EVP_PKEY_get0_type_name(pkey);
	printf("  key type: %s-%d + %s\n",
			key_type ? key_type : "unknown",
			EVP_PKEY_get_bits(pkey),
			hash != NULL ? hash : hash_function(pkey));
}

static void dump_x509(int index, const X509* cert)
{
	BIO *name_bio = BIO_new(BIO_s_mem());
	if (name_bio == NULL)
		goto exit;

	X509_NAME *name = X509_get_subject_name(cert);
	int r = X509_NAME_print_ex(name_bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
	if (r != -1) {
		/* Add null-terminator */
		if (BIO_write(name_bio, "", 1) == 1) {
			char *str = NULL;
			BIO_get_mem_data(name_bio, &str);
			printf("  %d:   %s\n", index, str);
		}
		else {
			r = -1;
		}
	}
	BIO_free(name_bio);
	if (r == -1)
		goto exit;

	EVP_PKEY* pkey = X509_get0_pubkey(cert);
	if (pkey != NULL) {
		printf("  %d: ", index);
		dump_pkey(pkey, "");
	}
	return;
exit:
	printf("%d: ERROR\n", index);
	return;
}

void container_dump(const struct container* container)
{
	printf("container:\n"
			"  section   offset     size\n"
			"  data:     %-10" PRIu64 " [%zu b]\n"
			"  tree:     %-10" PRIu64 " [%zu b]\n"
			"  root:     %-10" PRIu64 " [%zu b]\n"
			"  digest:   %-10" PRIu64 " [%zu b]\n"
			"  pubkey:   %-10" PRIu64 " [%zu b]\n"
			"  header:   %-10" PRIu64 " [%zu b]\n"
			"  roothash: %s\n",

				(uint64_t) 0, container->hdr.tree_offset,
				container->hdr.tree_offset, container->hdr.root_offset == 0
						? container->hdr.key_offset - container->hdr.tree_offset
						: container->hdr.root_offset - container->hdr.tree_offset,
				container->hdr.root_offset, container->hdr.root_offset == 0 ? 0 : container->hdr.digest_offset - container->hdr.root_offset,
				container->hdr.digest_offset, container->hdr.digest_offset == 0 ? 0 : container->hdr.key_offset - container->hdr.digest_offset,
				container->hdr.key_offset, container->size - HEADER_SIZE - container->hdr.key_offset,
				container->size - HEADER_SIZE, (uint64_t) HEADER_SIZE,
				container->roothash);

	const EVP_PKEY* pkey = container_get_verification_key(container);
	if (pkey != NULL)
		dump_pkey(pkey, NULL);

	CMS_ContentInfo *cms = container_get_cms((struct container*) container);
	if (cms != NULL) {
		STACK_OF(X509) *sk_x509 = CMS_get0_signers(cms);
		printf("  CMS signatures: %d\n", sk_X509_num(sk_x509));
		X509 *signer = NULL;
		int index = 0;
		while ((signer = sk_X509_pop(sk_x509)) != NULL) {
			dump_x509(index, signer);
			index++;
		}
		sk_X509_free(sk_x509);
	}
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

static int cat_rhs_on_lhs(int fdto, int fdfrom)
{
	int r = 0;
	uint8_t *buf = NULL;

	/* position output at end of file */
	if (lseek64(fdto, 0, SEEK_END) < 0) {
		r = -errno;
		pr_err("failed seeking file [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* position tree at start of file */
	if (lseek64(fdfrom, 0, SEEK_SET) < 0) {
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
	while ((bytes = read(fdfrom, buf, buf_size)) > 0 ) {
		r = write_bytes(fdto, buf, bytes);
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

	r = 0;
exit:
	if (buf != NULL)
		free(buf);
	return r;
}

static int read_container_header(int fd, off64_t* header_pos, struct header* hdr)
{
	/* Reposition to start of header */
	*header_pos = lseek64(fd, -HEADER_SIZE, SEEK_END);
	if (*header_pos < 0) {
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

	r = container_header_parse(hdr, buf, HEADER_SIZE);
	if (r != 0)
		return r;

	pr_dbg("hdr->tree_offset: %" PRIu64 "\n", hdr->tree_offset);
	pr_dbg("hdr->root_offset: %" PRIu64 "\n", hdr->root_offset);
	pr_dbg("hdr->digest_offset: %" PRIu64 "\n", hdr->digest_offset);
	pr_dbg("hdr->key_offset: %" PRIu64 "\n", hdr->key_offset);

	return 0;
}

/* enum used for array indexing, do not re-arrange */
enum container_region_index {
	REGION_HEADER,
	REGION_PUBKEY,
	REGION_DIGEST,
	REGION_ROOTHASH,
	REGION_TREE,
	REGION_DATA,
	REGION_MAX,
};

struct region {
	off64_t offset;
	size_t size;
	size_t extra;
	uint8_t *buf;
};

static int calculate_offset_size(struct region* region, off64_t previous_end, uint64_t ustart)
{
	if (previous_end < 0 || ustart > INT64_MAX)
		return -EINVAL;
	off64_t start = (off64_t) ustart;
	if (start >= previous_end)
		return -EINVAL;
	region->offset = start;
	region->size = previous_end - start;
	return 0;
}

static int header_has_cms(const struct header* hdr)
{
	return hdr->digest_offset == 0 && hdr->root_offset == 0;
}

static int container_read(struct container* container, int fd)
{
	if (container == NULL || fd < 0)
		return -EINVAL;

	container->opt = CONTAINER_NONE;

	/* read header */
	struct header hdr;
	off64_t header_pos = 0;
	int r = read_container_header(fd, &header_pos, &hdr);
	switch (r) {
	case 0:
		break;
	case -ENOMSG:
		return 0;
		break;
	default:
		pr_dbg("container - invalid header: [%d]: %s\n", -r, strerror(-r));
		return r;
	}

	struct region regions[REGION_MAX];
	memset(regions, 0, sizeof(regions));
	EVP_PKEY *pubkey = NULL;
	CMS_ContentInfo *cms = NULL;

	/* data section starts at 0 and ends at tree offset which must be > 0 and divisible by 4096 */
	if (hdr.tree_offset == 0 || hdr.tree_offset % 4096 != 0)
		return -ENOMSG;

	/* find key */
	if (calculate_offset_size(&regions[REGION_PUBKEY], header_pos, hdr.key_offset) != 0)
		return -ENOMSG;
	/* Determine whether plain key or cms structure was used.
	 * cms structures contains key, digest and roothash in REGION_PUBKEY
	 * while plain key needs to read all sections. */
	if (!header_has_cms(&hdr)) { /* plain keys */
		pr_dbg("hdr: plain key signature\n");
		/* find digest */
		if (calculate_offset_size(&regions[REGION_DIGEST], regions[REGION_PUBKEY].offset, hdr.digest_offset) != 0)
			return -ENOMSG;
		/* find roothash */
		if (calculate_offset_size(&regions[REGION_ROOTHASH], regions[REGION_DIGEST].offset, hdr.root_offset) != 0)
			return -ENOMSG;
		/* allocate an extra byte for roothash null-terminator */
		regions[REGION_ROOTHASH].extra = 1;
		/* find tree */
		if (calculate_offset_size(&regions[REGION_TREE], regions[REGION_ROOTHASH].offset, hdr.tree_offset) != 0)
			return -ENOMSG;
	}
	else { /* CMS */
		/* find tree */
		pr_dbg("hdr: cms structure\n");
		if (calculate_offset_size(&regions[REGION_TREE], regions[REGION_PUBKEY].offset, hdr.tree_offset) != 0)
			return -ENOMSG;
	}

	/* Allocate buffers and read pubkey, digest and roothash */
	const int read_stop_region = header_has_cms(&hdr) ? REGION_DIGEST : REGION_TREE;
	for (int i = REGION_PUBKEY; i < read_stop_region; ++i) {
		/* check for overflow */
		if ((SIZE_MAX - regions[i].size) < regions[i].extra) {
			r = -EINVAL;
			goto exit;
		}
		/* allocate */
		regions[i].buf = calloc(1, regions[i].size + regions[i].extra);
		if (regions[i].buf == NULL) {
			r = -ENOMEM;
			goto exit;
		}
		/* read buffer */
		r = pread_bytes(fd, regions[i].offset, regions[i].buf, regions[i].size);
		if (r != 0) {
			pr_err("failed reading from FILE: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
	}

	if (!header_has_cms(&hdr)) { /* parse pubkey */
		r = crypt_parse_public_key(regions[REGION_PUBKEY].buf, regions[REGION_PUBKEY].size, &pubkey);
		if (r != 0) {
			pr_dbg("container - pubkey: [%d]: %s\n", -r, strerror(-r));
			goto exit;
		}

		/* validate roothash signature */
		r = crypt_digest_verity(regions[REGION_ROOTHASH].buf, regions[REGION_ROOTHASH].size,
								regions[REGION_DIGEST].buf, regions[REGION_DIGEST].size, pubkey);
		if (r < 0) {
			pr_dbg("container - digest verify: [%d]: %s\n", -r, strerror(-r));
			goto exit;
		}
		if (r == 0) {
			pr_dbg("container - invalid signature\n");
			r = -EBADF;
			goto exit;
		}
	}
	else { /* parse cms */
		r = crypt_parse_cms(regions[REGION_PUBKEY].buf, regions[REGION_PUBKEY].size, &cms);
		if (r != 0) {
			pr_dbg("container - cms parse: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}

		/* validate data and retrieve roothash */
		r = crypt_cms_data(cms, &regions[REGION_ROOTHASH].buf, &regions[REGION_ROOTHASH].size);
		if (r != 0) {
			pr_dbg("container - cms data: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
		/* add null terminator */
		if (SIZE_MAX - regions[REGION_ROOTHASH].size < 1) {
			r = -EFAULT;
			goto exit;
		}
		regions[REGION_ROOTHASH].size++;
		uint8_t *newmem = realloc(regions[REGION_ROOTHASH].buf, regions[REGION_ROOTHASH].size);
		if (newmem == NULL) {
			r = -ENOMEM;
			goto exit;
		}
		regions[REGION_ROOTHASH].buf = newmem;
		regions[REGION_ROOTHASH].buf[regions[REGION_ROOTHASH].size - 1] = '\0';
	}

	pr_dbg("container - valid\n");

	/* Set container data */
	container->opt |= CONTAINER_VALID;
	container->size = header_pos + HEADER_SIZE;
	memcpy(&container->hdr, &hdr, sizeof(container->hdr));
	container->pubkey = pubkey;
	pubkey = NULL;
	container->cms = cms;
	cms = NULL;
	container->roothash = (char*) regions[REGION_ROOTHASH].buf;
	regions[REGION_ROOTHASH].buf = NULL;

	r = 0;
exit:
	EVP_PKEY_free(pubkey);
	CMS_ContentInfo_free(cms);
	for (int i = 0; i < REGION_MAX; ++i) {
		if (regions[i].buf != NULL)
			free(regions[i].buf);
	}
	return r;
}

int container_create_from_file(struct container** container, const char* path)
{
	if (container == NULL || *container != NULL || path == NULL)
		return -EINVAL;
	struct container *newc = calloc(1, sizeof(struct container));
	if (newc == NULL)
		return -ENOMEM;

	int r = 0;
	int fd = -1;

	newc->path = strdup(path);
	if (newc->path == NULL) {
		r = -ENOMEM;
		goto error_exit;
	}

	fd = open(newc->path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		r = -errno;
		pr_err("%s: open: [%d] %s\n", newc->path -r, strerror(-r));
		goto error_exit;
	}

	r = container_read(newc, fd);
	if (r != 0)
		goto error_exit;

	r = close(fd);
	fd = -1;
	if (r != 0) {
		r = -errno;
		pr_err("%s: close: [%d] %s\n", newc->path, -r, strerror(-r));
		goto error_exit;
	}

	*container = newc;
	return 0;

error_exit:
	if (newc->path != NULL)
		free(newc->path);
	if (fd >= 0)
		close(fd);
	free(newc);
	return r;
}

int container_free(struct container* container)
{
	if (container == NULL)
		return -EINVAL;
	if (container->path != NULL)
		free(container->path);
	EVP_PKEY_free(container->pubkey);
	EVP_PKEY_free(container->signing_key);
	X509_free(container->signing_cert);
	CMS_ContentInfo_free(container->cms);
	if (container->roothash != NULL)
		free(container->roothash);
	free(container);
	return 0;
}

int container_is_valid(const struct container* container)
{
	if (container != NULL && (container->opt & CONTAINER_VALID) == CONTAINER_VALID)
		return 1;
	return 0;
}

int container_set_signing_key(struct container* container, EVP_PKEY* pkey)
{
	if (container == NULL || pkey == NULL)
		return -EINVAL;
	if (EVP_PKEY_up_ref(pkey) != 1)
		return -EFAULT;
	EVP_PKEY_free(container->signing_key);
	container->signing_key = pkey;
	return 0;
}

int container_set_signing_cert(struct container* container, X509* cert)
{
	if (container == NULL || cert == NULL)
		return -EINVAL;
	if (X509_up_ref(cert) != 1)
		return -EFAULT;
	X509_free(container->signing_cert);
	container->signing_cert = cert;
	return 0;
}

const EVP_PKEY* container_get_verification_key(const struct container* container)
{
	if (container == NULL)
		return NULL;
	return container->pubkey;
}

CMS_ContentInfo* container_get_cms(struct container* container)
{
	if (container == NULL)
		return NULL;
	return container->cms;
}

const char* container_get_path(const struct container* container)
{
	if (container == NULL)
		return NULL;
	return container->path;
}

const char* container_get_roothash(const struct container* container)
{
	if (container == NULL)
		return NULL;
	return container->roothash;
}

uint64_t container_get_tree_offset(const struct container* container)
{
	if (container == NULL)
		return 0;
	return container->hdr.tree_offset;
}

static int calculate_offset(const struct region* previous, off64_t* offset)
{
	if (previous->size > INT64_MAX ||
		(INT64_MAX - previous->offset) < (off64_t) previous->size)
		return -EINVAL;
	*offset = previous->offset + (off64_t) previous->size;
	return 0;
}

int container_write(int fd, const char* path, struct container* container)
{
	CMS_ContentInfo *cms = NULL;
	char tmppath[] = "/tmp/ctutil-XXXXXX";
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

	struct region regions[REGION_MAX];
	memset(regions, 0, sizeof(regions));

	/* verity create */
	r = verity_create(path, tmppath, (char**) &regions[REGION_ROOTHASH].buf);
	if (r != 0)
		goto exit;
	/* Do not include null-terminator in output */
	regions[REGION_ROOTHASH].size = strlen((const char*) regions[REGION_ROOTHASH].buf);

	/* Find data size */
	const off64_t data_size = lseek64(fd, 0, SEEK_END);
	if (data_size < 0) {
		r = -errno;
		pr_err("%s: failed getting data size [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}
	regions[REGION_DATA].size = (size_t) data_size;
	regions[REGION_DATA].offset = 0;

	/* Find tree size */
	const off64_t tree_size = lseek64(tmpfd, 0, SEEK_END);
	if (tree_size < 0) {
		r = -errno;
		pr_err("%s: failed getting tree size [%d]: %s\n", -r, strerror(-r));
		goto exit;
	}
	regions[REGION_TREE].size = (size_t) tree_size;
	if (calculate_offset(&regions[REGION_DATA], &regions[REGION_TREE].offset) != 0) {
		r = -EFAULT;
		goto exit;
	}

	/* Determine signing method to use based on availability of signing certificate.
	 * Either plain digest with external roothash or CMS SignedData structure
	 * with wrapped roothash. */
	if (container->signing_cert == NULL) {
		/* calculate roothash offset */
		if (calculate_offset(&regions[REGION_TREE], &regions[REGION_ROOTHASH].offset) != 0) {
			r = -EFAULT;
			goto exit;
		}

		/* Calculate digest of roothash */
		r = crypt_digest_create(regions[REGION_ROOTHASH].buf, regions[REGION_ROOTHASH].size,
								&regions[REGION_DIGEST].buf, &regions[REGION_DIGEST].size,
								container->signing_key);
		if (r != 0)
			goto exit;
		if (calculate_offset(&regions[REGION_ROOTHASH], &regions[REGION_DIGEST].offset) != 0) {
			r = -EFAULT;
			goto exit;
		}

		/* Retrieve pubkey */
		r = crypt_serialize_public_key(&regions[REGION_PUBKEY].buf, &regions[REGION_PUBKEY].size,
										container->signing_key);
		if (r != 0) {
			pr_err("failed extracting pubkey [%d]: %s\n", -r, strerror(-r));
			goto exit;
		}
		if (calculate_offset(&regions[REGION_DIGEST], &regions[REGION_PUBKEY].offset) != 0) {
			r = -EFAULT;
			goto exit;
		}
	}
	else {
		/* Create cms with roothash */
		r = crypt_cms_create(regions[REGION_ROOTHASH].buf, regions[REGION_ROOTHASH].size,
								&cms, container->signing_key, container->signing_cert);
		if (r != 0)
			goto exit;
		r = crypt_serialize_cms(&regions[REGION_PUBKEY].buf, &regions[REGION_PUBKEY].size,
										cms);
		if (r != 0) {
			pr_err("failed serializing cms: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}

		/* roothash part of cms, do not write to container */
		regions[REGION_ROOTHASH].offset = 0;
		/* CMS placed in pubkey region, located after tree*/
		if (calculate_offset(&regions[REGION_TREE], &regions[REGION_PUBKEY].offset) != 0) {
			r = -EFAULT;
			goto exit;
		}
	}

	/* Create header */
	regions[REGION_HEADER].size = HEADER_SIZE;
	if (calculate_offset(&regions[REGION_PUBKEY], &regions[REGION_HEADER].offset) != 0) {
		r = -EFAULT;
		goto exit;
	}
	regions[REGION_HEADER].buf = malloc(regions[REGION_HEADER].size);
	if (regions[REGION_HEADER].buf == NULL) {
		r = -ENOMEM;
		goto exit;
	}
	struct header hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = HEADER_MAGIC;
	hdr.tree_offset = regions[REGION_TREE].offset;
	hdr.root_offset = regions[REGION_ROOTHASH].offset;
	hdr.digest_offset = regions[REGION_DIGEST].offset;
	hdr.key_offset = regions[REGION_PUBKEY].offset;
	r = container_header_serialize(&hdr, regions[REGION_HEADER].buf, regions[REGION_HEADER].size);
	if (r != 0) {
		pr_err("failed creating header: %[%d]: %s\n", -r, strerror(-r));
		goto exit;
	}

	/* append hash tree */
	r = cat_rhs_on_lhs(fd, tmpfd);
	if (r != 0)
		goto exit;

	/* write metadata */
	for (int i = 0; i < REGION_MAX; ++i) {
		if (regions[i].offset == 0 || regions[i].buf == NULL)
			continue;
		r = pwrite_bytes(fd, regions[i].offset, regions[i].buf, regions[i].size);
		if (r != 0) {
			pr_err("failed writing to FILE: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
	}

	/* set container parameters */
	/* pubkey key only set on plain key signing */

	if (cms == NULL && EVP_PKEY_up_ref(container->signing_key) != 1) {
		r = -EFAULT;
		goto exit;
	}
	memcpy(&container->hdr, &hdr, sizeof(container->hdr));
	if (cms == NULL)
		container->pubkey = container->signing_key;
	container->roothash = (char*) regions[REGION_ROOTHASH].buf;
	regions[REGION_ROOTHASH].buf = NULL;
	container->size = (size_t) regions[REGION_HEADER].offset + regions[REGION_HEADER].size;
	container->cms = cms;
	cms = NULL;

	r = 0;
exit:
	for (int i = 0; i < REGION_MAX; ++i) {
		if (regions[i].buf != NULL)
			free(regions[i].buf);
	}
	if (unlink(tmppath) != 0)
		pr_info("failed removing tmpfile: %s\n", tmppath);
	close(tmpfd);
	CMS_ContentInfo_free(cms);
	return r;
}

int container_format(struct container* container)
{
	if (container == NULL || container->signing_key == NULL)
		return -EINVAL;

	int r = 0;
	const int fd = open(container->path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		r = -errno;
		pr_err("%s: [%d] %s\n", container->path, -r, strerror(-r));
		goto exit;
	}

	/* remove header if available */
	if (container_is_valid(container)) {
		r = ftruncate64(fd, (off64_t) container->hdr.tree_offset);
		if (r != 0) {
			r = -errno;
			pr_err("%s: failed truncate: [%d]: %s\n", container->path, -r, strerror(-r));
			goto exit;
		}
		memset(&container->hdr, 0, sizeof(container->hdr));
		container->size = 0;
		container->opt = CONTAINER_NONE;
		EVP_PKEY_free(container->pubkey);
		container->pubkey = NULL;
		free(container->roothash);
		container->roothash = NULL;
		CMS_ContentInfo_free(container->cms);
		container->cms = NULL;
	}

	r = container_write(fd, container->path, container);
	if (r == 0)
		container->opt |= CONTAINER_VALID;
exit:
	if (fd >= 0)
		close(fd);
	return r;
}
