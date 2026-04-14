// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "log.h"
#include "header.h"
#include "verity.h"
#include "crypt.h"
#include "container.h"

/* xstr() will return string literal from symbol content */
#define xstr(a) str(a)
#define str(a) #a

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
	printf("Experimental (unstable):\n");
	printf("  --keyfile-ca     x509 for --keyfile. Will wrap roothash, digest\n");
	printf("                   and certificate in CMS as \"signed-data content type\"\n");
	printf("  --signer         Dump either pubkey or cms as PEM form to provided path\n");
	printf("  --pubkey-ca      Path to trusted root CA\n");
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
	OPT_SIGNER       = 1 << 7,
	OPT_PUBKEY_CMS   = 1 << 8,
	OPT_PUBKEY_PLAIN = 1 << 9,
};

struct config {
	int opt;
	char *filepath;
	char *mapperpath;
	char *key_path;
	char *key_ca_path;
	char *key_pkcs11;
	char *pubkey_path;
	char *pubkey_pkcs11;
	char *pubkey_dir;
	char *pubkey_ca;
	char *signer_path;
};

static int write_signer(struct container* container, const char* path)
{
	if (!container_is_valid(container))
		return -EINVAL;

	FILE *fp = fopen(path, "w");
	if (fp == NULL)
		return -errno;

	int r = -EINVAL;

	const CMS_ContentInfo *cms = container_get_cms(container);
	if (cms != NULL) {
		r = 0;
		if (PEM_write_CMS(fp, cms) != 1)
			r = -EIO;
		goto exit;

	}

	const EVP_PKEY *pkey = container_get_verification_key(container);
	if (pkey != NULL) {
		r = 0;
		if (PEM_write_PUBKEY(fp, pkey) != 1)
			r = -EIO;
		goto exit;
	}

exit:
	fclose(fp);
	return r;
}

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
		else if (strcmp("--signer", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --signer\n");
				return EINVAL;
			}
			cfg.opt |= OPT_SIGNER | OPT_PUBKEY_ANY;
			cfg.signer_path = argv[i];
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
		else if (strcmp("--keyfile-ca", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --keyfile-ca\n");
				return EINVAL;
			}
			cfg.key_ca_path = argv[i];
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
			cfg.opt |= OPT_PUBKEY_PLAIN;
			cfg.pubkey_path = argv[i];
		}
		else if (strcmp("--pubkey-pkcs11", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --pubkey-pkcs11\n");
				return EINVAL;
			}
			cfg.opt |= OPT_PUBKEY_PLAIN;
			cfg.pubkey_pkcs11 = argv[i];
		}
		else if (strcmp("--pubkey-dir", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --pubkey-dir\n");
				return EINVAL;
			}
			cfg.opt |= OPT_PUBKEY_PLAIN;
			cfg.pubkey_dir = argv[i];
		}
		else if (strcmp("--pubkey-ca", argv[i]) == 0) {
			if (++i >= argc) {
				pr_err("invalid argument --pubkey-ca\n");
				return EINVAL;
			}
			cfg.opt |= OPT_PUBKEY_CMS;
			cfg.pubkey_ca = argv[i];
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

	if ((cfg.opt & (OPT_VERIFY_ONLY | OPT_CREATE | OPT_OPEN | OPT_ROOTHASH | OPT_CLOSE | OPT_SIGNER)) == 0) {
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
			&& cfg.pubkey_dir == NULL
			&& cfg.pubkey_ca == NULL) {
		pr_err("Missing --pubkey, --pubkey-pkcs11, --pubkey-dir, --pubkey-ca or --pubkey-any\n");
		return EINVAL;
	}

	if ((cfg.opt & OPT_CREATE) == OPT_CREATE) {
		if ((cfg.key_path == NULL) && (cfg.key_pkcs11 == NULL) && (cfg.key_ca_path == NULL)) {
			pr_err("Missing key --keyfile, --keyfile-ca or --key-pkcs11 for --create\n");
			return EINVAL;
		}
		if ((cfg.key_path != NULL) && (cfg.key_pkcs11 != NULL) && (cfg.key_ca_path != NULL)) {
			pr_err("--keyfile, --keyfile-ca and --key-pkcs11 are mutually exclusive\n");
			return EINVAL;
		}
	}

	struct crypt_ctx *cctx = NULL;
	struct container *container = NULL;
	EVP_PKEY *signing_key = NULL;
	X509 *signing_cert = NULL;
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

	/* Attempt reading */
	r = container_create_from_file(&container, cfg.filepath);
	if (r != 0) {
		pr_err("%s: failed reading: [%d] %s\n", cfg.filepath, -r, strerror(-r));
		goto exit;
	}

	/* create new header */
	if ((cfg.opt & OPT_CREATE) == OPT_CREATE) {
		if (container_is_valid(container)
			&& (cfg.opt & OPT_FORCE) != OPT_FORCE) {
			pr_err("FILE is valid container, use --force to overwrite\n");
			r = -EBADF;
			goto exit;
		}

		/* load private key */
		r = read_private_key(cfg.key_path, cfg.key_pkcs11, &signing_key);
		if (r != 0) {
			pr_err("Could not read private key: [%d]: %s\n", -r, strerror(-r));
			goto exit;
		}
		r = container_set_signing_key(container, signing_key);
		if (r != 0) {
			pr_err("Failed setting signing key: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
		/* Load certificate */
		if (cfg.key_ca_path != NULL) {
			r = crypt_read_x509(&signing_cert, cfg.key_ca_path);
			if (r != 0) {
				pr_err("%s: Failed reading signing cert: [%d] %s\n", cfg.key_ca_path, -r, strerror(-r));
				goto exit;
			}
			r = container_set_signing_cert(container, signing_cert);
			if (r != 0) {
				pr_err("Failed setting signing cert: [%d] %s\n", -r, strerror(-r));
				goto exit;
			}
		}

		/* format */
		r = container_format(container);
		if (r != 0) {
			pr_err("Failed formatting container: [%d] %s\n", -r, strerror(-r));
			goto exit;
		}
		if (info)
			container_dump(container);
		pr_info("container - created\n");
		goto exit;
	}

	/* All following operations require container to be valid */
	if (!container_is_valid(container)) {
		pr_err("container - not a container\n");
		r = -EBADF;
		goto exit;
	}

	/* Verify signer.
	 *
	 * If OPT_PUBKEY_ANY is set then we are
	 * satisfied with digest verification towards
	 * pubkey provided by container as part of container
	 * validation. */
	if ((cfg.opt & OPT_PUBKEY_ANY) != OPT_PUBKEY_ANY) {
		/* Attempt verifying signer by any allowed method */
		int signer_verified = 0;
		/* plain private-public key pair */
		if (signer_verified == 0 && (cfg.opt & OPT_PUBKEY_PLAIN) == OPT_PUBKEY_PLAIN) {
			const EVP_PKEY *pkey = container_get_verification_key(container);
			if (pkey != NULL) {
				r = match_pubkey(cfg.pubkey_path, cfg.pubkey_dir, cfg.pubkey_pkcs11, pkey);
				if (r != 0) {
					r = -EBADF;
					pr_err("container - pubkey validation failed\n");
					goto exit;
				}
				signer_verified = 1;
			}
		}
		/* x509 certificate chain of CMS */
		if (signer_verified == 0 && (cfg.opt & OPT_PUBKEY_CMS) == OPT_PUBKEY_CMS) {
			CMS_ContentInfo *cms = container_get_cms(container);
			if (cms != NULL) {
				r = crypt_cms_verify_signer(cms, cfg.pubkey_ca);
				if (r != 0) {
					r = -EBADF;
					pr_err("container - cms validation failed\n");
					goto exit;
				}
				signer_verified = 1;
			}
		}

		if (signer_verified == 0) {
			r = -EBADF;
			pr_err("container - unexpected signature type\n");
			goto exit;
		}
	}

	/* verify data and tree to roothash */
	if ((cfg.opt & OPT_VERIFY_ONLY) == OPT_VERIFY_ONLY) {
		r = verity_open(container_get_path(container), container_get_tree_offset(container),
						NULL, VERITY_VERIFY, container_get_roothash(container));
		if (r < 0)
			goto exit;
		if (info)
			container_dump(container);
		pr_info("File verified OK\n");
		goto exit;
	}

	/* dump roothash */
	if ((cfg.opt & OPT_ROOTHASH) == OPT_ROOTHASH) {
		printf("%s\n", container_get_roothash(container));
		r = 0;
		goto exit;
	}

	/* open as devicemapper block device */
	if ((cfg.opt & OPT_OPEN) == OPT_OPEN) {
		r = verity_open(container_get_path(container), container_get_tree_offset(container),
						cfg.mapperpath, 0, container_get_roothash(container));
		if (r != 0)
			goto exit;

		/* on success the roothash should be printed */
		printf("%s\n", container_get_roothash(container));
		r = 0;
		goto exit;
	}

	/* dump signer */
	if ((cfg.opt & OPT_SIGNER) == OPT_SIGNER) {
		r = write_signer(container, cfg.signer_path);
		if (r != 0)
			pr_err("Failed writing signer: [%d] %s\n", -r, strerror(-r));
		goto exit;
	}

	r = -EINVAL;
exit:
	container_free(container);
	crypt_ctx_free(cctx);
	EVP_PKEY_free(signing_key);
	X509_free(signing_cert);
	pr_dbg("exit code: [%d]: %s\n", -r, strerror(-r));
	return -r;
}
