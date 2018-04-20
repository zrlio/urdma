/** @file kvstore_storage.h
 *
 * The overall layout is as follows:
 *
 * HEADER (PAGESIZE bytes, or 4096 if PAGESIZE and _SC_PAGESIZE not defined)
 * BUCKETS (main_bucket_count * sizeof(struct store_bucket) bytes)
 * BITMASK (slot_count / 8 bytes)
 * DATA (slot_count * KVSTORE_VALUE_LEN_MAX)
 */

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

/* These are the persistent data structures. */

#ifndef KVSTORE_STORAGE_H
#define KVSTORE_STORAGE_H

#include "kvstore_limits.h"

enum { ENTRIES_PER_BUCKET = 8 };

enum { KVSTORE_MAGIC = UINT16_C(0x1B4D) };

/** The format of the header stored in the first page of the file. */
struct store_header {
	uint16_t magic;
		/**< 1B4D, in machine endian format */
	uint16_t version;
		/**< version of the header format (0x00) */
	uint32_t main_bucket_count;
		/**< Total number of buckets in hash table. */
	uint32_t page_size;
		/**< Alignment of each section. */
	uint32_t reserved_12;
		/**< Reserved for future use; MUST be set to 0. */
	uint64_t slot_count;
		/**< Maximum number of data items that can be stored. */
	uint64_t value_max_size;
		/**< Maximum size of a value in the store.  Must be less than
		 * or equal to KVSTORE_VALUE_LEN_MAX. */
};

/** The format of each entry within a bucket. */
struct store_bucket_entry {
	uint64_t offset;
		/**< The offset of the entry, in bytes, from the start of the
		 * data section. */
	uint64_t cas_version;
		/**< The version of this item, used for CAS operations. */
	uint32_t value_size;
		/**< The length of the current value. */
	char key[KVSTORE_KEY_LEN_MAX];
		/**< The key, which is an ASCII string which may not contain
		 * null characters.  If the key is less than the maximum size,
		 * the entry will be padded with null characters.  If the key
		 * is the maximum size, there will be no terminating null
		 * character.
		 *
		 * If the first byte of the key is a null character, than the
		 * bucket is not in use. */
};

/** The store bucket.  The bucket consists of a small number entries, to allow
 * for quick lookup even with hash collisions. */
struct store_bucket {
	uint32_t version;
		/**< Currently unused. */
	struct store_bucket_entry entries[ENTRIES_PER_BUCKET];
		/**< An array of entries. */
};

/** Given an initial offset, return the offset of the main bucket array. */
static inline uintptr_t
kvstore_main_bucket_offset(uintptr_t start, struct store_header *header)
{
	return start + header->page_size;
} /* kvstore_main_bucket_offset */

/** Given the main bucket offset, return the bitmask offset. */
static inline uintptr_t
kvstore_bitmask_offset(uintptr_t mb_offset, struct store_header *header)
{
	return RTE_ALIGN_CEIL(mb_offset + header->main_bucket_count
			* sizeof(struct store_bucket), header->page_size);
} /* kvstore_bitmask_offset */

/** Given the bitmask offset, return the slot offset. */
static inline uintptr_t
kvstore_slot_offset(uintptr_t bitmask_offset, struct store_header *header)
{
	return RTE_ALIGN_CEIL(bitmask_offset + header->slot_count / 8,
			header->page_size);
} /* kvstore_slot_offset */

#endif
