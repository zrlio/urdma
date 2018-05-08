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

#include <stdio.h>
#include <stdlib.h>
#include "list.h"

LIST_HEAD(listhead, entry) head;

struct entry {
	int value;
	LIST_ENTRY(entry) entries;
};

void
print_list(FILE *stream, struct listhead *head)
{
	struct entry *e, **prev;
	fprintf(stream, "< ");
	LIST_FOR_EACH(e, head, entries, prev) {
		fprintf(stream, "%d ", e->value);
	}
	fprintf(stream, ">\n");
}

int
main(void)
{
	struct entry *e, *e2, **prev;
	int x;

	LIST_INIT(&head);
	printf("Empty list\n");
	print_list(stdout, &head);

	printf("Inserting 10 values\n");
	for (x = 0; x < 10; ++x) {
		e = malloc(sizeof(*e));
		e->value = x;
		LIST_INSERT_HEAD(&head, e, entries);
	}
	print_list(stdout, &head);

	printf("Removing 7\n");
	LIST_FOR_EACH(e, &head, entries, prev) {
		if (e->value == 7) {
			LIST_REMOVE(e, entries);
		}
	}
	print_list(stdout, &head);

	printf("Adding 14\n");
	LIST_FOR_EACH(e, &head, entries, prev) {
		if (e->value == 6) {
			e2 = malloc(sizeof(*e));
			e2->value = 14;
			LIST_INSERT_AFTER(e, e2, entries);
		}
	}
	print_list(stdout, &head);

	printf("Removing all elements\n");
	LIST_FOR_EACH(e, &head, entries, prev) {
		LIST_REMOVE(e, entries);
	}
	print_list(stdout, &head);
}
