// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef HEADER__H__
#define HEADER__H__

#include <stdint.h>

struct header {
	uint32_t magic;
	uint8_t rsvd[28];
	uint64_t tree_offset;
	uint64_t root_offset;
	uint64_t digest_offset;
	uint64_t key_offset;
};
enum {
	HEADER_MAGIC = 0x494d4721,
	HEADER_SIZE  = 64,
};

/* returns 0 on success or negative errno */
int container_header_parse(struct header* hdr, const uint8_t* buf, size_t size);
int container_header_serialize(const struct header* hdr, uint8_t* buf, size_t size);

#endif // HEADER__H__
