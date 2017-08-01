/* binheap.h */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pmacarth@iol.unh.edu>
 *
 * Copyright (c) 2017, University of New Hampshire
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

#ifndef BINHEAP_H
#define BINHEAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct binheap {
	size_t size;
	size_t capacity;
	uint32_t arr[];
};

struct binheap *binheap_new(size_t capacity);
int binheap_insert(struct binheap *binheap, uint32_t v);
int binheap_peek(struct binheap *binheap, uint32_t *v);
int binheap_pop(struct binheap *binheap);

static inline bool
binheap_empty(struct binheap *binheap)
{
	return binheap->size == 0;
}

#endif
