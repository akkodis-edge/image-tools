// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef CONTAINER__H__
#define CONTAINER__H__

#include <openssl/evp.h>

struct container;

/* create new "container" from file at "path".
 *
 * Use container_is_valid() to check if container header was
 * present and validated.
 * This will verify header offsets and signatures and not full
 * data validation of verity_verify(..., VERITY_VERIFY, ...).
 *
 * "container" must be freed by caller, see container_free()
 *
 * Returns 0 on success or negative errno for i/o errors.
 * Logical errors such as no header present can be detected
 * by container_is_valid()*/
int container_create_from_file(struct container** container, const char* path);
int container_free(struct container* container);

/* Retrieve key used for verifying container.
 *
 * Returns pointer to container internal key. Do not free.
 * Will be NULL if not valid. */
const EVP_PKEY* container_get_verification_key(const struct container* container);

/* Retrieve file path.
 *
 * Returns pointer to container internal path. Do not free. */
const char* container_get_path(const struct container* container);

/* Retrieve roothash.
 *
 * Returns pointer to container internal path. Do not free.
 * Will be NULL if not valid. */
const char* container_get_roothash(const struct container* container);

/* Retrieve tree offset within "path".
 *
 * Returns tree offset.
 * Will be 0 if not valid. */
uint64_t container_get_tree_offset(const struct container* container);

/* Returns 1 if container is valid, else 0. */
int container_is_valid(const struct container* container);

/* Assign key for usage by container_format().
 *
 * Returns 0 for success or negative errno for error. */
int container_set_signing_key(struct container* container, EVP_PKEY* pkey);

/* Calculate new hash, sign and write header to file.
 * Expects signing key provided by container_set_signing_key().
 *
 * Returns 0 on success or negative errno for error. */
int container_format(struct container* container);

/* Print container info */
void container_dump(const struct container* container);

#endif // CONTAINER__H__
