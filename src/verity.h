// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef VERITY__H__
#define VERITY__H__

#include <stdint.h>

/* Map file at "path" to devicemapper "mapperpath".
 * "tree_offset" points to start of hash tree within "path"
 * protected by hex-encoded "roothash".
 *
 * Returns 0 for success or negative errno for error. */
enum verity_open_flag {
	VERITY_VERIFY = 1 << 0, /* perform full verification of hash tree, device not opened, mapperpath may be NULL */
};
int verity_open(const char* path, uint64_t tree_offset, const char* mapperpath, int flags, const char* roothash);

/* Close verity mapping at devicemapper "mapperpath".
 * Operation will fail if mapping is in use, unless "force" is set.
 * If "force" is set and the mapping is in use, the mapping will be
 * replaced with an "always error mapping" and the mapping closed.
 *
 * Returns 0 for success or negative errno for error. */
int verity_close(const char* mapperpath, int force);

/* Calculate hash for file at "path". Output hashtree in file "tree" and
 * return hex-encoded "roothash".
 *
 * Caller is responsible for freeing "roothash".
 *
 * Returns 0 for success or negative errno for error. */
int verity_create(const char* path, const char* tree, char** roothash);

#endif // VERITY__H__
