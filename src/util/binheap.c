/* binheap.c */

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

#include "binheap.h"
#include <assert.h>
#include <stdlib.h>

#define SWAP(a, b) { \
		typeof(a) tmp = a; \
		a = b; \
		b = tmp; \
	}

static int array_min(uint32_t *arr, int i, int j)
{
	if (arr[j] < arr[i])
		return j;
	else
		return i;
}

static void array_swap(uint32_t *arr, int i, int j)
{
	SWAP(arr[i], arr[j]);
}

static void push_down(struct binheap *binheap, int index)
{
	int next;

	while (index != 0) {
		next = (index - 1) / 2;
		if (binheap->arr[index] < binheap->arr[next]) {
			array_swap(binheap->arr, index, next);
			index = next;
		} else {
			return;
		}
	}
}

/* Insert element v into binheap while preserving the heap invariant. The
 * caller is responsible for ensuring the heap remains within its capacity. */
int binheap_insert(struct binheap *binheap, uint32_t v)
{
	assert(binheap->size <= binheap->capacity);
	if (binheap->size == binheap->capacity) {
		return -1;
	}
	binheap->arr[binheap->size] = v;
	push_down(binheap, binheap->size++);
	return 0;
}	/* binheap_insert */

/* Returns the minimum element of the heap without removing it. */
int binheap_peek(struct binheap *binheap, uint32_t *v)
{
	if (binheap->size == 0) {
		return -1;
	}

	*v = binheap->arr[0];
	return 0;
}	/* binheap_peek */

/* Removes the minimum element of the heap while preserving the heap
 * invariant. */
int binheap_pop(struct binheap *binheap)
{
	int index = 0, min;
	unsigned int left, right;

	if (binheap->size == 0) {
		return -1;
	}
	array_swap(binheap->arr, 0, --binheap->size);
	while ((left = index * 2 + 1) < binheap->size) {
		min = array_min(binheap->arr, index, left);
		right = left + 1;
		if (right < binheap->size) {
			min = array_min(binheap->arr, min, right);
		}

		if (min != index) {
			array_swap(binheap->arr, index, min);
			index = min;
		} else {
			break;
		}
	}
	return 0;
}	/* binheap_pop */

/* Creates a binheap with the given capacity >= 0. The binheap will be able to
 * hold elements of type uint32_t and calling minheap_peek() will return the
 * minimum element placed into it. */
struct binheap *
binheap_new(size_t capacity)
{
	struct binheap *heap;

	assert(capacity != 0);

	heap = malloc(sizeof(*heap) + capacity * sizeof(uint32_t));
	if (heap) {
		heap->capacity = capacity;
		heap->size = 0;
	}
	return heap;
}	/* binheap_new */
