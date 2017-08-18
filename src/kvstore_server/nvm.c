/* server/nvm.c */

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_log.h>

#include "nvm.h"

#if defined(PAGESIZE) && PAGESIZE >= 0
#define DEFAULT_PAGE_SIZE PAGESIZE
#else
#define DEFAULT_PAGE_SIZE 4096
#endif

struct nvm_context *
nvm_open(const char *partition_name)
{
	struct nvm_context *ctx;
	struct stat st;
	int fd;

	fd = open(partition_name, O_RDWR);
	if (fd < 0) {
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
		goto close_fd;
	}

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		goto close_fd;
	}

	ctx->size = st.st_size;
	ctx->addr = mmap(NULL, ctx->size, PROT_READ|PROT_WRITE, MAP_SHARED,
			fd, 0);
	if (ctx->addr == MAP_FAILED) {
		goto free_ctx;
	}

	if (close(fd) < 0) {
		nvm_close(ctx);
		goto out;
	}
	return ctx;

free_ctx:
	free(ctx);

close_fd:
	close(fd);

out:
	return NULL;
} /* nvm_open */


struct nvm_context *
nvm_open_anonymous(size_t storage_size)
{
	struct nvm_context *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		goto err_out;
	}

	ctx->size = storage_size;
	ctx->addr = mmap(NULL, storage_size, PROT_READ|PROT_WRITE,
			MAP_SHARED|MAP_ANONYMOUS, 0, 0);
	if (ctx->addr == MAP_FAILED) {
		goto free_ctx;
	}

	return ctx;

free_ctx:
	free(ctx);
err_out:
	return NULL;
} /* nvm_open_anonymous */

void
nvm_close(struct nvm_context *ctx)
{
	if (munmap(ctx->addr, ctx->size) < 0) {
		RTE_LOG(DEBUG, USER2, "Error unmapping fake NVM partition at %p",
				ctx->addr);
	}
	free(ctx);
} /* nvm_close */

unsigned long
nvm_get_pagesize(void)
{
	long pagesize;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0) {
		pagesize = DEFAULT_PAGE_SIZE;
	}
	return pagesize;
} /* nvm_get_pagesize */

void
nvm_flush(__attribute__((unused)) struct nvm_context *ctx,
		void *addr, size_t length)
{
	unsigned long mask;
	uintptr_t aligned_addr;
	uintptr_t diff;

	mask = nvm_get_pagesize() - 1;

	aligned_addr = (uintptr_t)addr;
	diff = aligned_addr & mask;
	aligned_addr = aligned_addr - diff;
	length = length + diff;
	if (msync((void *)aligned_addr, length, MS_SYNC) < 0) {
		RTE_LOG(ERR, USER2, "Error flushing NVM partition: mapped address %" PRIxPTR " length %zu: %s\n",
				aligned_addr, length, strerror(errno));
	}
} /* nvm_flush */
