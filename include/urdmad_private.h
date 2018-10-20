/* include/urdmad_private.h */

#ifndef URDMAD_PRIVATE_H
#define URDMAD_PRIVATE_H

/*
 * Userspace Software iWARP library for DPDK
 *
 * Internal socket protocol and ABI structures for urdmad
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

#include <stdatomic.h>
#include <stdint.h>
#include <pthread.h>
#include <ccan/list/list.h>

#include <rte_ether.h>

#define URDMA_SOCK_PROTO_VERSION 1

/** Internal state machine of the queue pair. */
enum urdma_qp_state {
	usiw_qp_unbound = 0,
		/**< Queue pair not yet bound to remote endpoint. */
	usiw_qp_connected = 1,
		/**< Connection established by kernel CM. */
	usiw_qp_running = 2,
		/**< Userspace QP is connected to remote endpoint. */
	usiw_qp_shutdown = 3,
		/**< Shutdown has been triggered by RDMA CM. */
	usiw_qp_error = 4,
		/**< Queue pair has been invalidated. */
};

/** Fields of the queue pair that must be accessible from urdmad and verbs
 * processes. */
struct urdmad_qp {
	atomic_uint conn_state;
		/**< The state of the queue pair's connection. */
	uint8_t ord_max;
		/**< Negotiated maximum number of outstanding RDMA READ
		 * requests to the remote endpoint. */
	uint8_t ird_max;
		/**< Negotiated maximum number of incoming RDMA READ
		 * requests. */
	pthread_mutex_t conn_event_lock;
		/**< Protects conn_state and related variables. */

	uint16_t dev_id;
		/**< DPDK device/port index. */
	uint16_t qp_id;
		/**< Index into urdmad queue pair array. */
	uint16_t rx_queue;
		/**< Hardware receive queue to use for this queue pair. */
	uint16_t tx_queue;
		/**< Hardware transmit queue to use for this queue pair. */
	uint16_t local_udp_port;
		/**< UDP port assigned to local endpoint. */
	uint16_t remote_udp_port;
		/**< UDP port assigned to remote endpoint. */
	uint32_t local_ipv4_addr;
		/**< IPv4 address of local endpoint. */
	uint32_t remote_ipv4_addr;
		/**< IPv4 address of remote endpoint. */
	struct ether_addr remote_ether_addr;
		/**< MAC address of remote endpoint. */

	uint16_t rx_desc_count;
		/**< Hardware receive descriptors on this RX queue. */
	uint16_t tx_desc_count;
		/**< Hardware receive descriptors on this TX queue. */
	uint16_t rx_burst_size;
		/**< Size of array passed to rte_eth_rx_burst(). */
	uint16_t tx_burst_size;
		/**< Size of array passed to rte_eth_tx_burst(). */
	uint16_t mtu;
		/**< Device MTU. */

	struct list_node urdmad__entry;
		/**< Private field used only by urdmad to thread onto list. */
};

/* The messages defined for the sockets protocol. */
enum urdmad_sock_msg_op {
	urdma_sock_create_qp_req = 1,
	urdma_sock_create_qp_resp = 2,
	urdma_sock_destroy_qp_req = 3,
	urdma_sock_hello_req = 4,
	urdma_sock_hello_resp = 5,
};

struct urdmad_sock_msg {
	uint32_t opcode;
	uint16_t dev_id;
	uint16_t qp_id;
};

struct urdmad_sock_qp_msg {
	struct urdmad_sock_msg hdr;
	uint64_t ptr;
};

struct urdmad_sock_hello_req {
	struct urdmad_sock_msg hdr;
	uint8_t proto_version;
	uint8_t reserved9;
	uint16_t req_lcore_count;
};
static_assert(offsetof(struct urdmad_sock_hello_req, reserved9) == 9,
		"hello_req reserved9 field is at wrong offset");

struct urdmad_sock_hello_resp {
	struct urdmad_sock_msg hdr;
	uint8_t proto_version;
	uint8_t max_lcore;
	uint16_t device_count;
	uint32_t reserved12;
	uint64_t rdma_atomic_mutex_addr;
	uint32_t lcore_mask[RTE_MAX_LCORE / 32];
	uint16_t max_qp[];
};
static_assert(offsetof(struct urdmad_sock_hello_resp, reserved12) == 12,
		"reserved12 field is at wrong offset");

union urdmad_sock_any_msg {
	struct urdmad_sock_msg hdr;
	struct urdmad_sock_qp_msg qp;
	struct urdmad_sock_hello_req hello_req;
	struct urdmad_sock_hello_resp hello_resp;
};

#endif
