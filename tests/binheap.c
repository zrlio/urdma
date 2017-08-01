/* tests/binheap.c */

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

/* This file contains tests for our open-coded binary heap code */

#include "binheap.h"
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static const uint32_t magic = 0xA1C;

#define array_size(arr) (sizeof(arr) / sizeof(*arr))

#define FAIL(format, ...) \
	do { \
		do_fail("%s: " format, __func__, ##__VA_ARGS__); \
	} while (0);

static void do_fail(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);

	exit(EXIT_FAILURE);
}

static void test_peek_empty(void)
{
	struct binheap *h = binheap_new(1);
	uint32_t v;
	int ret;

	v = magic;
	ret = binheap_peek(h, &v);
	if (!ret) {
		FAIL("binheap_peek returned %d on empty heap\n", ret);
	}
	if (v != magic) {
		FAIL("binheap_peek set v=%d expected unchanged\n", v);
	}

	free(h);
}

static void test_insert_one(void)
{
	struct binheap *h = binheap_new(1);
	uint32_t v;
	int ret;

	binheap_insert(h, magic);

	ret = binheap_peek(h, &v);
	if (ret) {
		FAIL("binheap_peek returned %d after element inserted\n", ret);
	}
	if (v != magic) {
		FAIL("binheap_peek set v=%d expected %d\n", v, magic);
	}

	ret = binheap_pop(h);
	if (ret != 0) {
		FAIL("binheap_pop returned %d expected 0\n", v);
	}

	free(h);
}

static void test_insert_inorder(void)
{
	struct binheap *h = binheap_new(8);
	uint32_t i, v;

	binheap_insert(h, 1);
	binheap_insert(h, 2);
	binheap_insert(h, 3);
	binheap_insert(h, 4);
	binheap_insert(h, 5);
	binheap_insert(h, 6);
	binheap_insert(h, 7);
	binheap_insert(h, 8);

	for (i = 1; i <= 8; ++i) {
		binheap_peek(h, &v);
		if (v != i) {
			FAIL("binheap_peek set v=%d expected %d\n", v, i);
		}
		binheap_pop(h);
	}

	free(h);
}

static void test_insert_reverse(void)
{
	struct binheap *h = binheap_new(8);
	uint32_t i, v;

	binheap_insert(h, 8);
	binheap_insert(h, 7);
	binheap_insert(h, 6);
	binheap_insert(h, 5);
	binheap_insert(h, 4);
	binheap_insert(h, 3);
	binheap_insert(h, 2);
	binheap_insert(h, 1);

	for (i = 1; i <= 8; ++i) {
		binheap_peek(h, &v);
		if (v != i) {
			FAIL("binheap_peek set v=%d expected %d\n", v, i);
		}
		binheap_pop(h);
	}

	free(h);
}

static void test_pop_left_smallest(void)
{
	struct binheap *h = binheap_new(4);
	uint32_t expected[] = {1, 2, 3};
	static_assert(array_size(expected) == 3, "array_size");
	uint32_t v, *p, *end;

	binheap_insert(h, 2);
	binheap_insert(h, 1);
	binheap_insert(h, 3);

	for (p = expected, end = expected + array_size(expected);
			p != end; ++p) {
		binheap_peek(h, &v);
		if (v != *p) {
			FAIL("binheap_peek set v=%" PRIu32 " expected %" PRIu32 "\n",
					v, *p);
		}
		binheap_pop(h);
	}

	free(h);
}

static void test_pop_right_smallest(void)
{
	struct binheap *h = binheap_new(4);
	uint32_t expected[] = {1, 2, 3};
	uint32_t v, *p, *end;

	binheap_insert(h, 2);
	binheap_insert(h, 3);
	binheap_insert(h, 1);

	for (p = expected, end = expected + array_size(expected);
			p != end; ++p) {
		binheap_peek(h, &v);
		if (v != *p) {
			FAIL("binheap_peek set v=%d expected %d\n",
					v, *p);
		}
		binheap_pop(h);
	}

	free(h);
}

int main(__attribute__((__unused__)) int argc,
	 __attribute__((__unused__)) char *argv[])
{
	test_peek_empty();
	test_insert_one();
	test_insert_inorder();
	test_insert_reverse();
	test_pop_left_smallest();
	test_pop_right_smallest();
}
