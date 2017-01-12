/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2008-2016, IBM Corporation
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

#ifndef URDMA_KABI_H
#define URDMA_KABI_H

#include <linux/types.h>

/*
 * user commands/command responses must correlate with the siw_abi
 * in user land.
 */

#define URDMA_ABI_VERSION_MIN 0
#define URDMA_ABI_VERSION_MAX 0

#define VERSION_ID_URDMA	3
#define URDMA_VENDOR_ID		0x626d74	/* ascii 'bmt' for now */
#define URDMA_VENDOR_PART_ID	0x0816

#define	URDMA_NODE_DESC		"Userspace RDMA"
#define URDMA_DEV_PREFIX	"urdma_"

struct urdma_uresp_create_cq {
	uint32_t	cq_id;
};

struct urdma_udata_create_qp {
	uint32_t	ord_max;
	uint32_t	ird_max;
	uint16_t	urdmad_dev_id;
	uint16_t	urdmad_qp_id;
	uint16_t	rxq;
	uint16_t	txq;
};

struct urdma_uresp_create_qp {
	uint32_t	kmod_qp_id;
};

struct urdma_uresp_alloc_ctx {
	uint32_t	dev_id;
	uint32_t	event_fd;
};

struct urdma_cq_event {
	uint32_t	event_type;
	uint32_t	cq_id;
};

struct urdma_qp_connected_event {
	uint32_t	event_type;
	uint32_t	kmod_qp_id;
	uint16_t	urdmad_dev_id;
	uint16_t	urdmad_qp_id;
	uint32_t	src_ipv4;
	uint16_t	src_port;
	uint32_t	dst_ipv4;
	uint8_t		dst_ether[6];
	uint16_t	dst_port;
	uint8_t		ord_max;
	uint8_t		ird_max;
	uint16_t	rxq;
	uint16_t	txq;
};

struct urdma_qp_disconnected_event {
	uint32_t	event_type;
	uint16_t	urdmad_dev_id;
	uint16_t	urdmad_qp_id;
};

struct urdma_qp_rtr_event {
	uint32_t	event_type;
	uint32_t	kmod_qp_id;
};

struct urdma_event_storage {
	uint32_t	event_type;
	char		buf[sizeof(struct urdma_qp_connected_event) - 4];
};

enum urdma_event_type {
	SIW_EVENT_COMP_POSTED	= 0,
		/**< Sent from userspace to kernel to indicate that the
		 * associated completion channel should be woken up. */
	SIW_EVENT_QP_CONNECTED	 = 1,
		/**< Sent from the kernel to userspace to indicate that a
		 * connection is ready. */
	SIW_EVENT_QP_RTR	 = 2,
		/**< Sent from userspace to the kernel in response to a
		 * QP_CONNECTED event to indicate that we are ready to receive
		 * messages on the queue pair (flow director filters have been
		 * set up and DPDK queues enabled). */
	SIW_EVENT_QP_DISCONNECTED = 3,
		/**< Sent from the kernel to userspace to indicate that a
		 * connection has been torn down. */
};

#endif
