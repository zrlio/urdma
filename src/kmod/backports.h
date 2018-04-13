/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2008-2016, IBM Corporation
 * Copyright (c) 2016-2017, University of New Hampshire
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

#ifndef USIW_BACKPORTS_H
#define USIW_BACKPORTS_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
/* Introduced in Linux commit 3ebeebc38b4b and first appeared in
 * Linux 3.2-rc1. */
#define HAVE_RFC_6581 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
/* Introduced in Linux commit 94dcba3309d97 and first appeared in
 * Linux 4.2-rc1. */
#define HAVE_STRUCT_IB_CQ_INIT_ATTR 1
/* Introduced in Linux commit 2528e33e68092 and first appeared in
 * Linux 4.2-rc1. */
#define HAVE_IB_QUERY_DEVICE_UDATA 1
/* Introduced in Linux commits a97e2d86a9b88 and 4cd7c9479aff3, which first
 * appeared in Linux 4.2-rc1. */
#define HAVE_IB_PROCESS_MAD_SIZES 1
/* Introduced in Linux commit 7738613e7cb41 and first appeared in
 * Linux 4.2-rc1. */
#define HAVE_IB_GET_PORT_IMMUTABLE 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
/* Introduced in Linux commit 036b10635739f and first appeared in
 * Linux 4.3-rc1. */
#define HAVE_IB_DISASSOCIATE_CONTEXT 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
/* Removed in Linux commit b7d3e0a94fe1, which first appeared in
 * Linux 4.5-rc1. */
#define HAVE_IB_REG_PHYS_MR 1
/* Removed in Linux commit feb7c1e38bcc, which first appeared in
 * Linux 4.5-rc1. */
#define HAVE_IB_BIND_MW 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
/* The iWARP port mapper was added to core in Linux commit b493d91d333e, which
 * first appeared in Linux 4.6-rc1.  After this commit, we need to use the
 * mapped local and remote addresses rather than the user-requested ones. */
#define m_local_addr  local_addr
#define m_remote_addr remote_addr
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
/* struct dma_attrs was removed in Linux commit 00085f1efa38 ("dma-mapping: use
 * unsigned long for dma_attrs") which first appeared in Linux 4.8-rc1. */
typedef struct dma_attrs *dma_attrs_t;
#else
typedef unsigned long dma_attrs_t;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#define HAVE_CREATE_AH_UDATA 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define HAVE_DEVICE_ARCHDATA_DMA_OPS 1
#define HAVE_IB_DMA_MAPPING_OPS 1
#define kref_read(ref) (atomic_read(&((ref)->refcount)))
#define ib_dma_device(rdma_dev) ((rdma_dev).dma_device)
#else
#define ib_dma_device(rdma_dev) ((rdma_dev).dev.parent)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#define HAVE_STRUCT_RDMA_AH_ATTR 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define HAVE_DMA_MAP_OPS_SET_DMA_MASK 1
#endif

#endif
