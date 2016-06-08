/* kvstore.h */

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

#ifndef KVSTORE_H
#define KVSTORE_H

#include "kvstore_limits.h"
#include "verbs.h"

struct kvstore;
struct kvstore_elem;

struct kv_handle {
	void *value;
	struct ibv_mr *mr;
	size_t length;
};

enum /*kv_open_flags*/ {
	kv_must_exist = 1,
};

struct kvstore *
kvstore_new(const char *partition_name, size_t cache_capacity,
            struct ibv_pd *pd);

void
kvstore_free(struct kvstore *store);

struct kv_handle *
kvstore_object_create(struct kvstore *store, const char *key,
		void *new_value, size_t value_len);

struct kv_handle *
kvstore_object_get(struct kvstore *store, const char *key);

struct kv_handle *
kvstore_object_set(struct kvstore *store, const char *key,
		void *new_value, size_t value_len);

struct kv_handle *
kvstore_object_replace(struct kvstore *store, const char *key,
		void *new_value, size_t value_len);

int
kvstore_object_flush(struct kvstore *store, const char *key);

int
kvstore_object_delete(struct kvstore *store, const char *key);

uint64_t
kvstore_cas_version(const struct kv_handle *h);

#endif
