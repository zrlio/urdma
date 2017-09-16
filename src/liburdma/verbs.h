/* verbs.h */

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

#ifndef VERBS_H
#define VERBS_H

#include <inttypes.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/uio.h>

#include <infiniband/verbs.h>

#include <rte_ether.h>
#include <rte_timer.h>

#define URDMA_DEVICE_VENDOR_ID		0x626d74
#define URDMA_DEVICE_VENDOR_PART_ID	0x0816

struct urdma_ah {
	struct ether_addr ether_addr;
	uint16_t udp_port;
	uint32_t ipv4_addr;
};

struct urdma_qp_stats {
        uintmax_t *recv_count_histo;
		/**< An array of recv_max_burst_size + 1 elements.  The
		 * element at index X corresponds to the number of times that a
		 * burst of X messages was received by a call to
		 * rte_eth_rx_burst(). */
	size_t recv_max_burst_size;
		/**< The maximum burst size that usiw requests from DPDK. */
};

struct urdma_qp_stats_ex {
	size_t size;
		/**< The size of this structure filled in by urdma. Any fields
		 * beyond this size are undefined. */
	struct urdma_qp_stats base;
		/**< Base stats from initial (non-versioned) stats
		 * structure. */
	uintmax_t recv_psn_gap_count;
		/**< The number of times a packet was received with a PSN that
		 * was not the next expected PSN. */
	uintmax_t recv_retransmit_count;
		/**< The number of received retransmissions. */
	uintmax_t recv_sack_count;
		/**< The number of received SACK packets. */
};

struct ibv_mr *
urdma_reg_mr_with_rkey(struct ibv_pd *pd, void *addr, size_t len, int access,
		uint32_t rkey);

int
urdma_accl_post_recv(struct ibv_qp *qp, void *addr, size_t length,
		void *context);

int
urdma_accl_post_recvv(struct ibv_qp *qp, const struct iovec *iov,
		size_t iov_size, void *context);

int
urdma_accl_post_send(struct ibv_qp *qp, void *addr, size_t length,
		struct urdma_ah *ah, void *context);

int
urdma_accl_post_sendv(struct ibv_qp *qp, struct iovec *iov, size_t iov_size,
		struct urdma_ah *ah, void *context);

int
urdma_accl_post_write(struct ibv_qp *qp, void *addr, size_t length,
		struct urdma_ah *ah, uint64_t remote_addr,
		uint32_t rkey, void *context);

int
urdma_accl_post_read(struct ibv_qp *qp, void *addr, size_t length,
		struct urdma_ah *ah, uint64_t remote_addr,
		uint32_t rkey, void *context);

void
urdma_query_qp_stats(const struct ibv_qp *restrict qp,
		struct urdma_qp_stats *restrict stats);

struct urdma_qp_stats_ex *
urdma_query_qp_stats_ex(const struct ibv_qp *qp);

#endif
