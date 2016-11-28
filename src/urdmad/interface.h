/* src/urdmad/interface.h */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Author: Patrick MacArthur <patrick@patrickmacarthur.net>
 *
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
 *   - Neither the names of IBM, UNH, nor the names of its contributors may be
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

#ifndef URDMAD_INTERFACE_H
#define URDMAD_INTERFACE_H

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_kni.h>
#include <rte_spinlock.h>

#define PENDING_DATAGRAM_INFO_SIZE 32
#define RX_BURST_SIZE 32
#define RX_DESC_COUNT_MAX 512
#define TX_DESC_COUNT_MAX 512
#define URDMA_MAX_QP 63

#ifndef container_of
#define container_of(ptr, type, field) \
	((type *)((uint8_t *)(ptr) - offsetof(type, field)))
#endif

enum usiw_port_flags {
	port_checksum_offload = 1,
	port_fdir = 2,
};

LIST_HEAD(urdmad_qp_head, urdmad_qp);

struct usiw_port {
	int portid;
	uint64_t timer_freq;

	struct rte_mempool *rx_mempool;
	struct rte_mempool *tx_ddp_mempool;
	struct rte_mempool *tx_hdr_mempool;

	uint16_t rx_desc_count;
	uint16_t tx_desc_count;
	uint16_t max_qp;
	struct urdmad_qp_head avail_qp;
	struct urdmad_qp *qp;

	uint64_t flags;

	struct rte_kni *kni;
	struct ether_addr ether_addr;
	uint32_t ipv4_addr;
	int ipv4_prefix_len;

	char kni_name[RTE_KNI_NAMESIZE];
	struct rte_eth_dev_info dev_info;
};

struct urdma_fd {
	int fd;
	void (*data_ready)(struct urdma_fd *fd);
};

struct urdma_process {
	struct urdma_fd fd;
	LIST_ENTRY(urdma_process) entry;
	struct urdmad_qp_head owned_qps;
	uint32_t core_mask[RTE_MAX_LCORE / 32];
};

struct usiw_driver {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_link_cache;

	struct urdma_fd chardev;
	struct urdma_fd listen;
	LIST_HEAD(urdma_process_head, urdma_process) processes;
	int epoll_fd;
	int port_count;
	uint16_t progress_lcore;
	struct usiw_port ports[];
};

#endif
