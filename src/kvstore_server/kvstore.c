/* kvstore.c */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pam@zurich.ibm.com>
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

/* A very simple hashtable based key-value store */

#define _XOPEN_SOURCE 700
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#include <math.h>

#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_jhash.h>

#include "nvm.h"
#include "verbs.h"
#include "kvstore.h"
#include "kvstore_storage.h"

#define KV_OPEN_INLINE 16
#define KV_OPEN_MAX 1024

enum { KV_DEFAULT_STORAGE_SIZE = 1073741824 };

enum /*kv_elem_flags*/ {
	kv_elem_dirty = 1,
};

struct kv_elem {
	char key[KVSTORE_KEY_LEN_MAX];
	uint64_t cas_version;
	uint32_t flags;
	struct kv_handle handle;
	struct store_bucket_entry *pmem_entry;
};

struct kvstore {
	size_t cache_capacity;
	size_t count;
	struct kv_elem *cache;
	struct ibv_pd *pd;
	struct nvm_context *nvm_ctx;

	struct store_header *header;

	size_t main_bucket_count;
	struct store_bucket *main_buckets;

	size_t slot_count;
	uint64_t *bitmask;
	char *store;
};
static_assert(sizeof(struct store_bucket_entry) == 64, "sizeof store_bucket_entry");
static_assert(sizeof(struct store_bucket) == 520, "sizeof store_bucket");

static unsigned long
max_slot_count(unsigned long bucket_count, unsigned long page_size,
		unsigned long total_page_count, unsigned long long value_size)
{
	double bytes_per_bucket;
	double pages_per_slot;
	unsigned long remaining_pages;
	unsigned long res;

	assert(value_size % page_size == 0);
	bytes_per_bucket = (double)sizeof(struct store_bucket);
	remaining_pages = total_page_count - 1
		- ceil(bytes_per_bucket * bucket_count / page_size);
	pages_per_slot = 1.0 / (8 * page_size)
		+ value_size / page_size;
	res = remaining_pages / pages_per_slot;

	return res;
} /* max_slot_count */

static void
init_header(struct store_header *header, size_t storage_size)
{
	header->magic = 0x1B4D;
	header->version = 0;
	header->page_size = nvm_get_pagesize();
	header->reserved_12 = 0;
	header->value_max_size = KVSTORE_VALUE_LEN_MAX;
	for (header->main_bucket_count = 1024;
			header->main_bucket_count < (1UL << 31);
			header->main_bucket_count <<= 1) {
		header->slot_count = max_slot_count(
				header->main_bucket_count,
				header->page_size,
				storage_size / header->page_size,
				header->value_max_size);
		if (header->slot_count < header->main_bucket_count) {
			break;
		}
	}
	RTE_LOG(DEBUG, USER1, "Initialized device header with %" PRIu32 " buckets and %" PRIu64 " slots.\n",
			header->main_bucket_count, header->slot_count);
} /* init_header */

static bool
verify_header(struct store_header *header)
{
	unsigned int x;

	if (header->magic != KVSTORE_MAGIC) {
		return false;
	}
	if (header->version != 0) {
		return false;
	}
	if (header->main_bucket_count < header->slot_count) {
		return false;
	}
	if (header->value_max_size < header->page_size) {
		return false;
	}
	x = 0;
	do {
		x += header->page_size;
	} while (x < header->value_max_size);
	if (x != header->value_max_size) {
		return false;
	}
	return header->reserved_12 == 0;
}

struct kvstore *
kvstore_new(const char *partition_name, size_t cache_capacity,
		struct ibv_pd *pd)
{
	struct nvm_context *nvm_ctx;
	struct kvstore *store;
	uintptr_t addr;
	unsigned int x;

	if (partition_name) {
		nvm_ctx = nvm_open(partition_name);
	} else {
		nvm_ctx = nvm_open_anonymous(KV_DEFAULT_STORAGE_SIZE);
		if (nvm_ctx) {
			init_header((struct store_header *)nvm_ctx->addr,
					KV_DEFAULT_STORAGE_SIZE);
		}
	}
	if (!nvm_ctx) {
		goto errout;
	}

	store = malloc(sizeof(*store) + cache_capacity * sizeof(*store->cache));
	if (!store) {
		goto close_nvm_ctx;
	}

	store->header = nvm_ctx->addr;
	if (!verify_header(store->header)) {
		errno = ENOTRECOVERABLE;
		goto free_store;
	}

	store->nvm_ctx = nvm_ctx;
	store->cache_capacity = cache_capacity;
	store->count = 0;
	store->pd = pd;
	store->cache = (struct kv_elem *)(store + 1);

	for (x = 0; x < cache_capacity; ++x) {
		store->cache[x].key[0] = '\0';
		store->cache[x].handle.value = NULL;
	}

	addr = kvstore_main_bucket_offset((uintptr_t)nvm_ctx->addr,
			store->header);
	store->main_buckets = (struct store_bucket *)addr;

	addr = kvstore_bitmask_offset(addr, store->header);
	store->bitmask = (uint64_t *)addr;

	addr = kvstore_slot_offset(addr, store->header);
	store->store = (char *)addr;

	return store;

free_store:
	free(store);
close_nvm_ctx:
	nvm_close(nvm_ctx);
errout:
	return NULL;
}

void
kvstore_free(struct kvstore *store)
{
	unsigned x;

	for (x = 0; x < store->cache_capacity; ++x) {
		free(store->cache[x].handle.value);
	}
	nvm_close(store->nvm_ctx);
	free(store);
}

static void
do_flush(struct kvstore *store, struct kv_elem *elem)
{
	void *pmem_value;

	if (elem->flags & kv_elem_dirty) {
		pmem_value = (void *)((uintptr_t)store->store
				+ elem->pmem_entry->offset);
		memcpy(pmem_value, elem->handle.value, elem->handle.length);
		elem->pmem_entry->value_size = elem->handle.length;
		elem->pmem_entry->cas_version = elem->cas_version;
		//nvm_flush(store->nvm_ctx, pmem_value, elem->handle.length);
		elem->flags &= ~kv_elem_dirty;
	}
}

static void
kvstore_cache_evict(struct kvstore *store, struct kv_elem *elem, bool flush)
{
	ibv_dereg_mr(elem->handle.mr);
	if (flush) {
		do_flush(store, elem);
	}
	rte_free(elem->handle.value);
	elem->key[0] = '\0';
}

static int
fill_entry(struct kvstore *store, struct kv_elem *elem, int hash,
		const void *value, size_t value_len)
{
	elem->handle.value = rte_malloc("value",
			store->header->value_max_size, 64);
	if (!elem->handle.value) {
		goto errout;
	}
	elem->handle.length = value_len;
	if (value_len > 0) {
		memcpy(elem->handle.value, value, value_len);
	}

	elem->handle.mr = usiw_reg_mr_with_rkey(store->pd,
				elem->handle.value,
				elem->handle.length,
				IBV_ACCESS_REMOTE_READ|IBV_ACCESS_REMOTE_WRITE,
				hash);
	if (!elem->handle.mr) {
		goto free_handle_value;
	}

	return 0;

free_handle_value:
	rte_free(elem->handle.value);
errout:
	return -1;
}

/** Looks up a key/value pair from the mmap'd persistent store.  The hash must
 * have been previously returned by a negative kvstore_cache_search result. */
static struct kv_elem *
kvstore_lookup(struct kvstore *store, const char *key, uint32_t *hash)
{
	struct store_bucket_entry *entry;
	struct store_bucket *bucket;
	struct kv_elem *elem;
	unsigned int x;
	void *pmem_value;

	*hash = rte_jhash(key, strlen(key), 0);
	elem = &store->cache[*hash % store->cache_capacity];
	if (elem->key[0] && strcmp(key, elem->key) == 0) {
		return elem;
	}

	bucket = &store->main_buckets[*hash & (store->header->main_bucket_count - 1)];
	entry = NULL;
	for (x = 0; x < KVSTORE_KEY_LEN_MAX; ++x) {
		if (bucket->entries[x].key[0] != '\0'
				&& strcmp(bucket->entries[x].key, key) == 0) {
			entry = &bucket->entries[x];
			break;
		}
	}

	elem = &store->cache[*hash % store->cache_capacity];
	if (elem->key[0]) {
		kvstore_cache_evict(store, elem, true);
	}
	elem->flags = 0;
	strncpy(elem->key, key, sizeof(elem->key));
	elem->pmem_entry = entry;

	if (entry) {
		pmem_value = (void *)((uintptr_t)store->store
				+ elem->pmem_entry->offset);
		if (fill_entry(store, elem, *hash,
				pmem_value, entry->value_size) != 0) {
			return NULL;
		}
		elem->cas_version = entry->cas_version;
	}

	return elem;
}

static struct store_bucket_entry *
kvstore_pmem_reserve(struct kvstore *store, const char *key, uint32_t hash)
{
	struct store_bucket_entry *entry;
	struct store_bucket *bucket;
	unsigned int x, y;

	bucket = &store->main_buckets[hash & (store->header->main_bucket_count - 1)];
	entry = NULL;
	for (x = 0; x < KVSTORE_KEY_LEN_MAX; ++x) {
		if (bucket->entries[x].key[0] == '\0') {
			entry = &bucket->entries[x];
			break;
		}
	}
	if (!entry) {
		goto out_of_space;
	}

	for (x = 0; x < store->header->slot_count; ++x) {
		if (store->bitmask[x] != UINT64_MAX) {
			for (y = 0; y < 64; ++y) {
				if (!(store->bitmask[x] & (UINT64_C(1) << y))) {
					goto have_slot;
				}
			}
			/* We should never get here */
			assert(0);
		}
	}

out_of_space:
	errno = ENOMEM;
	return NULL;

have_slot:
	store->bitmask[x] |= UINT64_C(1) << y;
	entry->offset = (64 * x + y) * store->header->value_max_size;
	entry->value_size = 0;
	entry->cas_version = 0;
	strncpy(entry->key, key, sizeof(entry->key));
	return entry;
}

/** The returned handle is valid until the next call to any kvstore function,
 * which might evict it. */
struct kv_handle *
kvstore_object_get(struct kvstore *store, const char *key)
{
	struct kv_elem *elem;
	uint32_t hash;

	elem = kvstore_lookup(store, key, &hash);
	if (!elem) {
		return NULL;
	} else if (!elem->pmem_entry) {
		errno = ENOENT;
		return NULL;
	} else {
		return &elem->handle;
	}
}

static struct kv_handle *
kvstore_do_create(struct kvstore *store, struct kv_elem *elem, uint32_t hash,
		void *new_value, size_t value_len)
{
	struct store_bucket_entry *entry;

	entry = kvstore_pmem_reserve(store, elem->key, hash);
	if (!entry) {
		return NULL;
	}

	elem->pmem_entry = entry;

	if (fill_entry(store, elem, hash, new_value, value_len) != 0) {
		return NULL;
	}
	if (value_len > 0) {
		elem->flags |= kv_elem_dirty;
	}
	do_flush(store, elem);

	return &elem->handle;
}

struct kv_handle *
kvstore_object_create(struct kvstore *store, const char *key,
		void *new_value, size_t value_len)
{
	struct kv_elem *elem;
	uint32_t hash;

	if (value_len > store->header->value_max_size) {
		errno = EMSGSIZE;
		return NULL;
	}

	elem = kvstore_lookup(store, key, &hash);
	if (!elem) {
		return NULL;
	} else if (elem->pmem_entry) {
		errno = EEXIST;
		return NULL;
	}

	return kvstore_do_create(store, elem, hash, new_value, value_len);
}

static struct kv_handle *
kvstore_do_replace(struct kv_elem *elem, void *new_value, size_t value_len)
{
	memcpy(elem->handle.value, new_value, value_len);
	elem->flags |= kv_elem_dirty;
	elem->handle.length = value_len;
	elem->cas_version++;

	return &elem->handle;
}

struct kv_handle *
kvstore_object_replace(struct kvstore *store, const char *key,
		void *new_value, size_t value_len)
{
	struct kv_elem *elem;
	uint32_t hash;

	if (value_len > store->header->value_max_size) {
		errno = EMSGSIZE;
		return NULL;
	}

	elem = kvstore_lookup(store, key, &hash);
	if (!elem) {
		return NULL;
	} else if (!elem->pmem_entry) {
		errno = ENOENT;
		return NULL;
	}

	return kvstore_do_replace(elem, new_value, value_len);
}

struct kv_handle *
kvstore_object_set(struct kvstore *store, const char *key,
		void *new_value, size_t value_len)
{
	struct kv_elem *elem;
	uint32_t hash;

	if (value_len > store->header->value_max_size) {
		errno = EMSGSIZE;
		return NULL;
	}

	elem = kvstore_lookup(store, key, &hash);
	if (!elem) {
		return NULL;
	} else if (!elem->pmem_entry) {
		return kvstore_do_create(store, elem, hash,
				new_value, value_len);
	} else {
		return kvstore_do_replace(elem, new_value, value_len);
	}
}

int
kvstore_object_flush(struct kvstore *store, const char *key)
{
	struct kv_elem *elem;
	uint32_t hash;

	elem = kvstore_lookup(store, key, &hash);
	if (!elem) {
		return -1;
	} else if (!elem->pmem_entry) {
		errno = ENOENT;
		return -1;
	}

	do_flush(store, elem);

	return 0;
}

int
kvstore_object_delete(struct kvstore *store, const char *key)
{
	struct kv_elem *elem;
	unsigned int x;
	uint32_t hash;

	elem = kvstore_lookup(store, key, &hash);
	if (!elem) {
		return -1;
	} else if (!elem->pmem_entry) {
		errno = ENOENT;
		return -1;
	}

	kvstore_cache_evict(store, elem, false);

	x = elem->pmem_entry->offset / store->header->value_max_size;
	store->bitmask[x & ~63] &= ~(UINT64_C(1) << (x & 63));
	elem->pmem_entry->key[0] = '\0';
	return 0;
}

uint64_t
kvstore_cas_version(const struct kv_handle *handle)
{
	const struct kv_elem *elem = container_of(handle,
			struct kv_elem, handle);
	return elem->cas_version;
} /* kvstore_cas_version */
