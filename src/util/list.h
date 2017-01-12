/* list.h */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2016, IBM Corporation
 * Copyright (c) 2016, University of New Hampshire
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

/* Macros to extend the BSD queue data structures. */

#ifndef LIST_H
#define LIST_H

#include <stddef.h>
#include <sys/queue.h>

/** Declares a new tailq head type named <type>_tailq_head. */
#define DECLARE_TAILQ_HEAD(type) \
	TAILQ_HEAD(type ##_tailq_head, type)

/** Iterates through all elements of the list.  lptr will contain each element
 * in sequence.  prev is used internally to keep a pointer to the previous
 * element, so that the current element may be deleted inside the loop.
 * Deletion of any element except the current is undefined. */
#define LIST_FOR_EACH(lptr, head, name, prev) \
	for ((prev) = &(head)->lh_first, (lptr) = *(prev); (lptr) != NULL; \
			(prev) = ((lptr) == (*prev)) \
			? &(lptr)-> name .le_next : (prev), (lptr) = *(prev))

/** Iterates through all elements of the tailq.  lptr will contain each element
 * in sequence.  prev is used internally to keep a pointer to the previous
 * element, so that the current element may be deleted inside the loop.
 * Deletion of any element except the current is undefined. */
#define TAILQ_FOR_EACH(lptr, head, name, prev) \
	for ((prev) = &(head)->tqh_first, (lptr) = *(prev); (lptr) != NULL; \
			(prev) = ((lptr) == (*prev)) \
			? &(lptr)-> name .tqe_next : (prev), (lptr) = *(prev))

#endif
