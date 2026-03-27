#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include "header.h"
#include "log.h"

_Static_assert(sizeof(struct header) == HEADER_SIZE, "struct header size unexpected\n");

/* Get sizeof() struct member */
#define member_size(type, member) (sizeof(((type *)0)->member))

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

int container_header_parse(struct header* hdr, const uint8_t* buf, size_t size)
{
	if ((size != HEADER_SIZE) || (buf == NULL) || (hdr == NULL))
		return -EINVAL;
	memset(hdr, 0, sizeof(*hdr));

	hdr->magic = u32fromle(buf + offsetof(struct header, magic));
	if (hdr->magic != HEADER_MAGIC) {
		pr_dbg("hdr->magic 0x%" PRIx32 " not the expected 0x%" PRIx32 "\n", hdr->magic, HEADER_MAGIC)
		return -ENOMSG; /* not of type container */
	}
	memcpy(&hdr->rsvd, buf + offsetof(struct header, rsvd), member_size(struct header, rsvd));
	hdr->tree_offset = u64fromle(buf + offsetof(struct header, tree_offset));
	hdr->root_offset = u64fromle(buf + offsetof(struct header, root_offset));
	hdr->digest_offset = u64fromle(buf + offsetof(struct header, digest_offset));
	hdr->key_offset = u64fromle(buf + offsetof(struct header, key_offset));
	return 0;
}

int container_header_serialize(const struct header* hdr, uint8_t* buf, size_t size)
{
	if ((size != HEADER_SIZE) || (buf == NULL) || (hdr == NULL))
		return -EINVAL;

	/* write to buffer */
	u32tole(hdr->magic, buf + offsetof(struct header, magic));
	memcpy(buf + offsetof(struct header, rsvd), &hdr->rsvd, member_size(struct header, rsvd));
	u64tole(hdr->tree_offset, buf + offsetof(struct header, tree_offset));
	u64tole(hdr->root_offset, buf + offsetof(struct header, root_offset));
	u64tole(hdr->digest_offset, buf + offsetof(struct header, digest_offset));
	u64tole(hdr->key_offset, buf + offsetof(struct header, key_offset));
	return 0;
}
