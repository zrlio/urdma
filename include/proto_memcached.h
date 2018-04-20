/* proto_memcached.h */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
 *
 * Copyright (c) 2016, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef PROTO_MEMCACHED_H
#define PROTO_MEMCACHED_H

enum memcached_magic {
	memcached_magic_request = 0x80,
	memcached_magic_response = 0x81,
};

enum memcached_response_status {
	memcached_no_error = 0,
	memcached_key_not_found = 1,
	memcached_key_exists = 2,
	memcached_value_too_large = 3,
	memcached_invalid_arguments = 4,
	memcached_item_not_stored = 5,
	memcached_non_numeric_value = 6,
	memcached_unknown_command = 0x81,
	memcached_out_of_memory = 0x82,
};

enum memcached_opcode {
	memcached_opcode_get = 0x00,
	memcached_opcode_set = 0x01,
        memcached_opcode_add = 0x02,
        memcached_opcode_replace = 0x03,
        memcached_opcode_delete = 0x04,
};

struct memcached_header {
	uint8_t magic;
	uint8_t opcode;
	uint16_t key_length;
	uint8_t extras_length;
	uint8_t data_type;
	uint16_t status; /* reserved for requests */
	uint32_t total_body_length;
	uint32_t opaque;
	uint64_t cas_version;

	/* Added for RDMA protocol capability */
	uint32_t rdma_stag;
	uint32_t rdma_length;
	uint64_t rdma_offset;
};

struct memcached_set_req_header {
	struct memcached_header head;
	uint32_t flags;
	uint32_t expire;
};

struct memcached_get_resp_header {
	struct memcached_header head;
	uint32_t flags;
	uint32_t value_len;
};

/** Returns a pointer to the key inside of a memcached header.
 *
 * Note 1: This will return a pointer even if there is no key in the packet,
 * this should be verified using the key_length field beforehand.
 *
 * Note 2: The key that is returned is directly from the packet and is NOT
 * null-terminated. */
static inline char *
memcached_header_key(struct memcached_header *head)
{
	return (char *)((uintptr_t)head + sizeof(*head) + head->extras_length);
} /* memcached_header_key */

/** Returns a pointer to the value inside of a memcached header.
 *
 * Note 1: This will return a pointer even if there is no value in the packet,
 * this should be verified using the length fields beforehand.
 *
 * Note 2: The value that is returned is directly from the packet.  It may be
 * binary data and is NOT null-terminated.  The length can be calculated from
 * other fields in the packet. */
static inline void *
memcached_header_value(struct memcached_header *head)
{
	return (void *)((uintptr_t)head + sizeof(*head) + head->extras_length
			+ rte_be_to_cpu_16(head->key_length));
} /* memcached_header_key */

#endif
