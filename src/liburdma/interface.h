/* interface.h */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
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

#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdatomic.h>
#include <stdbool.h>
#include <semaphore.h>

#include <ccan/list/list.h>

#include "infiniband/driver.h"

#include <uthash.h>

#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_kni.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_spinlock.h>

#include "urdmad_private.h"
#include "binheap.h"
#include "verbs.h"

#define MAX_RECV_WR 1023
#define MAX_SEND_WR 1023
#define DPDK_VERBS_IOV_LEN_MAX 32
#define DPDK_VERBS_RDMA_READ_IOV_LEN_MAX 1
#define MAX_MR_SIZE (UINT32_C(1) << 30)
#define USIW_IRD_MAX 128
#define USIW_ORD_MAX 128

/* MUST be a power of 2 minus 1 */
#define NEW_CTX_MAX 31

#define STAG_TYPE_MASK      UINT32_C(0xFF000000)
#define STAG_MASK           UINT32_C(0x00FFFFFF)
#define STAG_TYPE_MR        (UINT32_C(0x00) << 24)
#define STAG_TYPE_RDMA_READ (UINT32_C(0x01) << 24)
#define STAG_RDMA_READ(x) (STAG_TYPE_RDMA_READ | ((x) & STAG_MASK))

#if defined(HAVE_FUNC_RTE_RING_DEQUEUE_BURST_4)
#define RING_DEQUEUE_BURST(a, b, c) (rte_ring_dequeue_burst((a), (b), (c), NULL))
#elif defined(HAVE_FUNC_RTE_RING_DEQUEUE_BURST_3)
#define RING_DEQUEUE_BURST(a, b, c) (rte_ring_dequeue_burst((a), (b), (c)))
#else
#error rte_ring_dequeue_burst not available
#endif

#if defined(HAVE_FUNC_RTE_RING_ENQUEUE_BURST_4)
#define RING_ENQUEUE_BURST(a, b, c) (rte_ring_enqueue_burst((a), (b), (c), NULL))
#elif defined(HAVE_FUNC_RTE_RING_ENQUEUE_BURST_3)
#define RING_ENQUEUE_BURST(a, b, c) (rte_ring_enqueue_burst((a), (b), (c)))
#else
#error rte_ring_enqueue_burst not available
#endif

struct usiw_context;
struct usiw_device;
struct usiw_qp;

struct arp_entry {
	struct ether_addr ether_addr;
	struct usiw_send_wqe *request;
};

struct usiw_recv_ooo_range {
	uint64_t offset_start;
	uint64_t offset_end;
};

struct usiw_wc {
	void *wr_context;
	enum ibv_wc_status status;
	enum ibv_wc_opcode opcode;
	uint32_t byte_len;
	uint32_t qp_num;

	uint32_t wc_flags; // it can be 0 or IBV_WC_WITH_IMM
	uint32_t imm_data; // valid when IBV_WC_WITH_IMM is set.
};

struct usiw_recv_wqe {
	void *wr_context;
	struct ee_state *remote_ep;
	struct list_node active;
	uint32_t msn;
	bool complete;
	size_t total_request_size;
	size_t recv_size;
	size_t input_size;

	uint32_t imm_data; // the immeidate data

	size_t iov_count;
	struct iovec iov[];
};

struct pending_datagram_info {
	uint64_t next_retransmit;
	struct usiw_send_wqe *wqe;
	struct read_atomic_response_state *readresp;
	uint16_t transmit_count;
	uint16_t ddp_length;
	uint32_t ddp_raw_cksum;
	uint32_t psn;
};

enum usiw_send_wqe_state {
	SEND_WQE_INIT = 0,
	SEND_WQE_TRANSFER,
	SEND_WQE_WAIT,
	SEND_WQE_COMPLETE,
};

enum usiw_send_opcode {
	usiw_wr_send = 0,
	usiw_wr_write = 1,
	usiw_wr_read = 2,
	usiw_wr_atomic = 3,

	usiw_wr_send_with_imm = 4,
	usiw_wr_write_with_imm = 5,
};

enum {
	usiw_send_signaled = 1,
	usiw_send_inline = 2,
};

struct usiw_send_wqe {
	enum usiw_send_opcode opcode;
	void *wr_context;
	struct ee_state *remote_ep;
	uint64_t remote_addr;
	uint64_t atomic_add_swap;
	uint64_t atomic_compare;
	uint8_t atomic_opcode;
	uint32_t rkey;
	uint32_t flags;
	struct list_node active;
	uint32_t index;
	enum usiw_send_wqe_state state;
	uint32_t msn;
	uint32_t local_stag; /* only used for READs */
	size_t total_length;
	size_t bytes_sent;
	size_t bytes_acked;

	uint32_t imm_data;

	size_t iov_count;
	struct iovec iov[];
};

struct usiw_mr {
	struct ibv_mr mr;
	struct usiw_mr *next;
	int access;
};

/* Lookup table for memory regions */
struct usiw_mr_table {
	struct ibv_pd pd;
	size_t capacity;
	size_t mr_count;
	struct usiw_mr *entries[0];
};

struct usiw_send_wqe_queue {
	struct rte_ring *ring;
	struct rte_ring *free_ring;
	struct list_head active_head;
	char *storage;
	int max_wr;
	int max_sge;
	unsigned int max_inline;
	rte_spinlock_t lock;
};

struct usiw_recv_wqe_queue {
	struct rte_ring *ring;
	struct rte_ring *free_ring;
	struct list_head active_head;
	uint32_t next_msn;
	char *storage;
	int max_wr;
	int max_sge;
	rte_spinlock_t lock;
};

struct psn_range {
	uint32_t min;
	uint32_t max;
};

enum {
	trp_recv_missing = 1,
	trp_ack_update = 2,
};

struct ee_state {
	uint32_t expected_read_msn;
	uint32_t expected_ack_msn;
	uint32_t next_send_msn;
	uint32_t next_read_msn;
	uint32_t next_ack_msn;

	/* TX TRP state */
	uint32_t send_last_acked_psn;
	uint32_t send_next_psn;
	uint32_t send_max_psn;

	/* RX TRP state */
	uint32_t recv_ack_psn;
	/* This tracks both READ and atomic responses */
	struct binheap *recv_rresp_last_psn;

	uint32_t trp_flags;
	struct psn_range recv_sack_psn;

	struct rte_mbuf **tx_pending;
	struct rte_mbuf **tx_head;
	int tx_pending_size;

	/* This fields are only used if the NIC does not support
	 * filtering. */
	struct rte_ring *rx_queue;
};

struct read_atomic_response_state {
	char *vaddr;
	uint32_t sink_stag; /* network byte order */
	bool active;
	enum {
		read_response,
		atomic_response,
	} type;
	struct list_node qp_entry;
	struct ee_state *sink_ep;

	union {
		struct {
			uint32_t msg_size;
			uint64_t sink_offset; /* host byte order */
		} read;
		struct {
			unsigned int opcode;
			uint32_t req_id;
			uint64_t add_swap;
			uint64_t add_swap_mask;
			uint64_t compare;
			uint64_t compare_mask;
			bool done;
		} atomic;
	};
};

enum {
	usiw_qp_sig_all = 0x1,
};

/** This structure contains fields used by my initial reliable datagram-style
 * verbs interface.  This will be used for transition to the reliable connected
 * queue pairs and the libibverbs interface. */
struct usiw_qp {
	atomic_uint refcnt;
	struct urdmad_qp *shm_qp;
	uint16_t qp_flags;

	struct list_node ctx_entry;
	UT_hash_handle hh;
	struct usiw_context *ctx;
	struct usiw_device *dev;
	struct usiw_cq *send_cq;

	/* txq_end points one entry beyond the last entry in the table
	 * the table is full when txq_end == txq + tx_burst_size
	 * the burst should be flushed at that point
	 */
	struct rte_mbuf **txq_end;
	struct rte_mbuf **txq;

	struct usiw_send_wqe_queue sq;

	struct rte_eth_fdir_filter fdir_filter;
        struct urdma_qp_stats_ex stats;

	uint64_t timer_last;
	struct usiw_recv_wqe_queue rq0;

	struct read_atomic_response_state *readresp_store;
	uint32_t readresp_head_msn;
	uint8_t ord_active;

	struct usiw_cq *recv_cq;
	struct usiw_mr_table *pd;

	struct ee_state remote_ep;

	struct ibv_qp ib_qp;
};

struct usiw_cq {
	atomic_uint refcnt;
	struct ibv_cq ib_cq;
	struct rte_ring *cqe_ring;
	struct rte_ring *free_ring;
	struct usiw_wc *storage;
	size_t capacity;
	size_t qp_count;
	uint32_t cq_id;
	atomic_bool notify_flag;
};

enum usiw_device_flags {
	port_checksum_offload = 1,
	port_fdir = 2,
};

/* A context handle which provides an indirection for accessing the actual
 * context from the progress thread.  The reason we need this is that the
 * context may be freed by the verbs layer while we still have a reference to
 * it.  When the user calls ibv_close_device(3), we atomically set the pointer
 * in this handle to 0.  The progress thread then removes the entry from the
 * list and frees it. */
struct usiw_context_handle {
	struct list_node driver_entry;
	atomic_uintptr_t ctxp;
};

struct usiw_context {
	struct verbs_context vcontext;
	struct usiw_device *dev;
	int event_fd;
	struct usiw_context_handle *h;
	struct list_head qp_active;
	atomic_uint qp_init_count;
		/**< The number of queue pairs in the INIT state. */
	struct usiw_qp *qp;
		/**< Hash table of all non-destroyed queue pairs in any
		 * state.  Guarded by qp_lock. */
	rte_spinlock_t qp_lock;
};


static inline struct usiw_context *
usiw_get_context(struct ibv_context *ctx)
{
	struct verbs_context *vctx = verbs_get_ctx(ctx);
	return container_of(vctx, struct usiw_context, vcontext);
} /* usiw_get_context */

struct usiw_device {
	struct verbs_device vdev;
	struct rte_mempool *rx_mempool;
	struct rte_mempool *tx_ddp_mempool;
	struct rte_mempool *tx_hdr_mempool;
	struct urdmad_queue_range *queue_ranges;
	struct usiw_driver *driver;
	uint16_t portid;
	uint16_t max_qp;
	uint64_t flags;
	struct ether_addr ether_addr;
	uint32_t ipv4_addr;
	int urdmad_fd;
};

struct usiw_driver {
	sem_t go;
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct nl_cache *addr_cache;
	struct list_head ctxs;
	struct rte_ring *new_ctxs;
	int urdmad_fd;
	uint32_t lcore_mask[RTE_MAX_LCORE / 32];
	uint16_t device_count;
	uint16_t *max_qp;
	pthread_mutex_t *rdma_atomic_mutex;
};

/** Starts the progress thread. */
void
start_progress_thread(void);

/** Adds an IB user context to the list of contexts to be managed by the
 * progress thread. */
int
driver_add_context(struct usiw_context *ctx);

struct usiw_mr **
usiw_mr_lookup(struct usiw_mr_table *tbl, uint32_t rkey);

/* Internal-only helper used by usiw_dereg_mr */
void
usiw_dereg_mr_real(struct usiw_mr_table *tbl, struct usiw_mr **mr);

/* Places a pointer to the next send WQE in *wqe and returns 0 if one is
 * available.  If one is not available, returns -ENOSPC.
 *
 * The caller is responsible for enqueuing the WQE after it is filled in;
 * otherwise the behavior is undefined. */
int
qp_get_next_send_wqe(struct usiw_qp *qp, struct usiw_send_wqe **wqe);

/* Returns the send WQE to the free set.  The caller must set still_in_hash if
 * the WQE is in the hashtable, in which case this function will also remove
 * the WQE from the hash. */
void
qp_free_send_wqe(struct usiw_qp *qp, struct usiw_send_wqe *wqe,
		bool still_in_hash);

/* Places a pointer to the next receive WQE in *wqe and returns 0 if one is
 * available.  If one is not available, returns -ENOSPC.
 *
 * The caller is responsible for enqueuing the WQE after it is filled in;
 * otherwise the behavior is undefined. */
int
qp_get_next_recv_wqe(struct usiw_qp *qp, struct usiw_recv_wqe **wqe);

int
usiw_send_wqe_queue_init(uint32_t qpn, struct usiw_send_wqe_queue *q,
		uint32_t max_send_wr, uint32_t max_sge);

void
usiw_send_wqe_queue_destroy(struct usiw_send_wqe_queue *q);

int
usiw_recv_wqe_queue_init(uint32_t qpn, struct usiw_recv_wqe_queue *q,
		uint32_t max_recv_wr, uint32_t max_sge);

void
usiw_recv_wqe_queue_destroy(struct usiw_recv_wqe_queue *q);

void
urdma_do_destroy_cq(struct usiw_cq *cq);

void
usiw_do_destroy_qp(struct usiw_qp *qp);

int
kni_loop(void *arg);

#ifdef NDEBUG
#define cq_check_sanity(x) do { } while (0)
#else
void
cq_check_sanity(struct usiw_cq *cq);
#endif

/* These two functions are actually defined in verbs.h but are *not* intended
 * to be public API, so they are declared here in this internal-only header
 * instead. */
struct verbs_context *
urdma_alloc_context(struct ibv_device *device, int cmd_fd);

void
urdma_free_context(struct ibv_context *ctx);

#endif
