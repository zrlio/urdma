/* interface.c */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pam@zurich.ibm.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "interface.h"
#include "list.h"
#include "proto.h"
#include "urdma_kabi.h"
#include "util.h"

#define IP_HDR_PROTO_UDP 17
#define RETRANSMIT_MAX 5

struct packet_context {
	struct ee_state *src_ep;
	size_t ddp_seg_length;
	struct rdmap_packet *rdmap;
	uint32_t psn;
};

struct ether_addr ether_bcast = {
	.addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

struct usiw_send_wqe_key {
	uint16_t wr_opcode;
	uint32_t wr_key_data;
};

struct usiw_recv_wqe_key {
	uint32_t msn;
};

/** Compares two 32-bit unsigned integers using the rules in RFC 1982 with
 * SERIAL_BITS=32.  Returns true if and only if s1 < s2. */
static bool
serial_less_32(uint32_t s1, uint32_t s2)
{
	return (s1 < s2 && s2 - s1 < (UINT32_C(1) << 31))
		|| (s1 > s2 && s1 - s2 > (UINT32_C(1) << 31));
} /* serial_less_32 */

/** Compares two 32-bit unsigned integers using the rules in RFC 1982 with
 * SERIAL_BITS=32.  Returns true if and only if s1 > s2. */
static bool
serial_greater_32(uint32_t s1, uint32_t s2)
{
	return (s1 < s2 && s2 - s1 > (UINT32_C(1) << 31))
		|| (s1 > s2 && s1 - s2 < (UINT32_C(1) << 31));
} /* serial_greater_32 */


struct usiw_mr **
usiw_mr_lookup(struct usiw_mr_table *tbl, uint32_t rkey)
{
	struct usiw_mr **candidate;

	for (candidate = &tbl->entries[rkey % tbl->capacity];
			*candidate != NULL; candidate = &(*candidate)->next) {
		if ((*candidate)->mr.rkey == rkey) {
			return candidate;
		}
	}

	return NULL;
} /* usiw_mr_lookup */


void
usiw_dereg_mr_real(__attribute__((unused)) struct usiw_mr_table *tbl,
		struct usiw_mr **mr)
{
	struct usiw_mr *free_mr = *mr;
	*mr = (*mr)->next;
	free(free_mr);
} /* usiw_dereg_mr_real */

int
usiw_send_wqe_queue_init(uint32_t qpn, struct usiw_send_wqe_queue *q,
		uint32_t max_send_wr, uint32_t max_send_sge)
{
	char name[RTE_RING_NAMESIZE];
	int ret;

	snprintf(name, RTE_RING_NAMESIZE, "qpn%" PRIu32 "_send", qpn);
	q->ring = rte_malloc(NULL, rte_ring_get_memsize(max_send_wr + 1),
			RTE_CACHE_LINE_SIZE);
	if (!q->ring)
		return -rte_errno;
	ret = rte_ring_init(q->ring, name, max_send_wr + 1,
			RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ret)
		return ret;

	q->storage = calloc(max_send_wr + 1, sizeof(struct usiw_send_wqe)
			+ max_send_sge * sizeof(struct iovec));
	q->bitmask = malloc((max_send_wr + 1) / 8);
	if (!q->bitmask || !q->storage)
		return -errno;
	memset(q->bitmask, INT_MAX, (max_send_wr + 1) / 8);

	TAILQ_INIT(&q->active_head);
	rte_spinlock_init(&q->lock);
	q->max_wr = max_send_wr;
	q->max_sge = max_send_sge;
	return 0;
} /* usiw_send_wqe_queue_init */

void
usiw_send_wqe_queue_destroy(struct usiw_send_wqe_queue *q)
{
	free(q->bitmask);
	rte_free(q->ring);
} /* usiw_send_wqe_queue_destroy */

static void
usiw_send_wqe_queue_add_active(struct usiw_send_wqe_queue *q,
		struct usiw_send_wqe *wqe)
{
	TAILQ_INSERT_TAIL(&q->active_head, wqe, active);
} /* usiw_send_wqe_queue_add_active */

static void
usiw_send_wqe_queue_del_active(struct usiw_send_wqe_queue *q,
		struct usiw_send_wqe *wqe)
{
	TAILQ_REMOVE(&q->active_head, wqe, active);
} /* usiw_send_wqe_queue_del_active */

static int
usiw_send_wqe_queue_lookup(struct usiw_send_wqe_queue *q,
		uint16_t wr_opcode, uint32_t wr_key_data,
		struct usiw_send_wqe **wqe)
{
	struct usiw_send_wqe *lptr, **prev;
	RTE_LOG(DEBUG, USER1, "LOOKUP active send WQE opcode=%" PRIu8 " key_data=%" PRIu32 "\n",
			wr_opcode, wr_key_data);
	TAILQ_FOR_EACH(lptr, &q->active_head, active, prev) {
		if (lptr->opcode != wr_opcode) {
			continue;
		}
		switch (lptr->opcode) {
		case usiw_wr_send:
			if (wr_key_data == lptr->msn) {
				*wqe = lptr;
				return 0;
			}
			break;
		case usiw_wr_write:
			if (wr_key_data == lptr->rkey) {
				*wqe = lptr;
				return 0;
			}
			break;
		case usiw_wr_read:
			if (wr_key_data == STAG_RDMA_READ(lptr->msn)) {
				*wqe = lptr;
				return 0;
			}
			break;
		}
	}
	return -ENOENT;
} /* usiw_send_wqe_queue_lookup */

int
usiw_recv_wqe_queue_init(uint32_t qpn, struct usiw_recv_wqe_queue *q,
		uint32_t max_recv_wr, uint32_t max_recv_sge)
{
	char name[RTE_RING_NAMESIZE];
	int ret;

	snprintf(name, RTE_RING_NAMESIZE, "qpn%" PRIu32 "_recv", qpn);
	q->ring = rte_malloc(NULL, rte_ring_get_memsize(max_recv_wr + 1),
			RTE_CACHE_LINE_SIZE);
	if (!q->ring)
		return -rte_errno;
	ret = rte_ring_init(q->ring, name, max_recv_wr + 1,
			RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ret)
		return ret;

	q->storage = calloc(max_recv_wr + 1, sizeof(struct usiw_recv_wqe)
			+ max_recv_sge * sizeof(struct iovec));
	q->bitmask = malloc((max_recv_wr + 1) / 8);
	if (!q->bitmask || !q->storage)
		return -errno;
	memset(q->bitmask, INT_MAX, (max_recv_wr + 1) / 8);

	TAILQ_INIT(&q->active_head);
	rte_spinlock_init(&q->lock);
	q->max_wr = max_recv_wr;
	q->max_sge = max_recv_sge;
	return 0;
} /* usiw_recv_wqe_queue_init */

void
usiw_recv_wqe_queue_destroy(struct usiw_recv_wqe_queue *q)
{
	free(q->bitmask);
	rte_free(q->ring);
} /* usiw_recv_wqe_queue_destroy */

static void
usiw_recv_wqe_queue_add_active(struct usiw_recv_wqe_queue *q,
		struct usiw_recv_wqe *wqe)
{
	RTE_LOG(DEBUG, USER1, "ADD active recv WQE msn=%" PRIu32 "\n",
			wqe->msn);
	TAILQ_INSERT_TAIL(&q->active_head, wqe, active);
} /* usiw_recv_wqe_queue_add_active */

static void
usiw_recv_wqe_queue_del_active(struct usiw_recv_wqe_queue *q,
		struct usiw_recv_wqe *wqe)
{
	RTE_LOG(DEBUG, USER1, "DEL active recv WQE msn=%" PRIu32 "\n",
			wqe->msn);
	TAILQ_REMOVE(&q->active_head, wqe, active);
} /* usiw_recv_wqe_queue_del_active */

static int
usiw_recv_wqe_queue_lookup(struct usiw_recv_wqe_queue *q,
		uint32_t msn, struct usiw_recv_wqe **wqe)
{
	struct usiw_recv_wqe *lptr, **prev;
	RTE_LOG(DEBUG, USER1, "LOOKUP active recv WQE msn=%" PRIu32 "\n",
			msn);
	TAILQ_FOR_EACH(lptr, &q->active_head, active, prev) {
		if (lptr->msn == msn) {
			*wqe = lptr;
			return 0;
		}
	}
	return -ENOENT;
} /* usiw_recv_wqe_queue_lookup */


/* Transmits all packets currently in the transmit queue.  The queue will be
 * empty when this function returns.
 *
 * FIXME: It may be possible for this to never return if there is any error
 * that prevents packets from being transmitted. */
static void
flush_tx_queue(struct usiw_qp *qp)
{
	struct rte_mbuf **begin;
	int ret;

	begin = qp->txq;
	do {
		ret = rte_eth_tx_burst(qp->port->portid, qp->tx_queue,
			begin, qp->txq_end - begin);
		if (ret > 0) {
			RTE_LOG(DEBUG, USER1, "Transmitted %d packets\n", ret);
		}
		begin += ret;
	} while (begin != qp->txq_end);
	qp->txq_end = qp->txq;
} /* flush_tx_queue */

/* Prepends an Ethernet header to the frame and enqueues it on the given port.
 * The ether_type should be in host byte order. */
static void
enqueue_ether_frame(struct rte_mbuf *sendmsg, unsigned int ether_type,
		struct usiw_qp *qp, struct ether_addr *dst_addr)
{
	struct ether_hdr *eth = (struct ether_hdr *)rte_pktmbuf_prepend(sendmsg,
								sizeof(*eth));

	ether_addr_copy(dst_addr, &eth->d_addr);
	rte_eth_macaddr_get(qp->port->portid, &eth->s_addr);
	eth->ether_type = rte_cpu_to_be_16(ether_type);
	sendmsg->l2_len = sizeof(*eth);
#ifdef DEBUG_PACKET_HEADERS
	RTE_LOG(DEBUG, USER1, "Enqueue packet to transmit queue:\n");
	rte_pktmbuf_dump(stderr, sendmsg, 128);
#endif

	*(qp->txq_end++) = sendmsg;
	if (qp->txq_end == qp->txq + TX_BURST_SIZE) {
		RTE_LOG(DEBUG, USER1, "TX queue filled; early flush forced\n");
		flush_tx_queue(qp);
	}
} /* enqueue_ether_frame */

/* Appends a skeleton IPv4 header to the packet.  src_addr and dst_addr are in
 * network byte order. */
static struct ipv4_hdr *
prepend_ipv4_header(struct rte_mbuf *sendmsg, int next_proto_id,
					uint32_t src_addr, uint32_t dst_addr)
{
	struct ipv4_hdr *ip;
	size_t payload_length;

	payload_length = rte_pktmbuf_pkt_len(sendmsg);
	ip = (struct ipv4_hdr *)rte_pktmbuf_prepend(sendmsg, sizeof(*ip));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = rte_cpu_to_be_16(sizeof(*ip) + payload_length);
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = next_proto_id;
	ip->hdr_checksum = 0;
	ip->src_addr = src_addr;
	ip->dst_addr = dst_addr;
	sendmsg->l3_len = sizeof(*ip);

	if (!(sendmsg->ol_flags & PKT_TX_IP_CKSUM)) {
		ip->hdr_checksum = rte_ipv4_cksum(ip);
	}

	return ip;
} /* prepend_ipv4_header */


/* Appends a skeleton IPv4 header to the packet.  Note that this sets the
 * checksum to 0, which must either be computed in full or offloaded (in which
 * case the IP psuedo-header checksum must be pre-computed by the caller).
 * src_port and dst_port should be in network byte order. */
static struct udp_hdr *
prepend_udp_header(struct rte_mbuf *sendmsg, unsigned int src_port,
			unsigned int dst_port)
{
	struct udp_hdr *udp;
	size_t payload_length;

	payload_length = rte_pktmbuf_pkt_len(sendmsg);
	udp = (struct udp_hdr *)rte_pktmbuf_prepend(sendmsg, sizeof(*udp));
	udp->src_port = src_port;
	udp->dst_port = dst_port;
	udp->dgram_cksum = 0;
	udp->dgram_len = rte_cpu_to_be_16(sizeof(*udp) + payload_length);
	sendmsg->l4_len = sizeof(*udp);

	return udp;
} /* prepend_udp_header */

/** Adds a UDP datagram to our packet TX queue to be transmitted when the queue
 * is next flushed.
 *
 * @param qp
 *   The queue pair that is sending this datagram.
 * @param sendmsg
 *   The mbuf containing the datagram to send.
 * @param dest
 *   The address handle of the destination for this datagram.
 * @param payload_checksum
 *   The non-complemented checksum of the packet payload.  Ignored if
 *   checksum_offload is enabled.
 */
static void
send_udp_dgram(struct usiw_qp *qp, struct rte_mbuf *sendmsg,
		struct urdma_ah *dest, uint32_t raw_cksum)
{
	struct udp_hdr *udp;
	struct ipv4_hdr *ip;

	if (qp->port->flags & port_checksum_offload) {
		sendmsg->ol_flags
			|= PKT_TX_UDP_CKSUM|PKT_TX_IPV4|PKT_TX_IP_CKSUM;
	}

	udp = prepend_udp_header(sendmsg, qp->udp_port, dest->udp_port);
	ip = prepend_ipv4_header(sendmsg, IP_HDR_PROTO_UDP,
			qp->port->ipv4_addr, dest->ipv4_addr);

	udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, sendmsg->ol_flags);
	if (!(sendmsg->ol_flags & PKT_TX_UDP_CKSUM)) {
		raw_cksum += udp->dgram_cksum + udp->src_port
					+ udp->dst_port + udp->dgram_len;
		/* Add any carry bits into the checksum. */
		while (raw_cksum > UINT16_MAX) {
			raw_cksum = (raw_cksum >> 16) + (raw_cksum & 0xffff);
		}
		udp->dgram_cksum = (raw_cksum == UINT16_MAX) ? UINT16_MAX
					: ~raw_cksum;
	}

	enqueue_ether_frame(sendmsg, ETHER_TYPE_IPv4, qp, &dest->ether_addr);
} /* send_udp_dgram */

static int
resend_ddp_segment(struct usiw_qp *qp, struct rte_mbuf *sendmsg,
		struct ee_state *ep)
{
	struct pending_datagram_info *info;
	struct rte_mbuf *hdr;
	struct trp_hdr *trp;
	uint32_t payload_raw_cksum = 0;

	info = (struct pending_datagram_info *)(sendmsg + 1);
	info->next_retransmit = rte_get_timer_cycles()
		+ rte_get_timer_hz() / 100;
	if (info->transmit_count++ > RETRANSMIT_MAX) {
		return -EIO;
	}

	hdr = rte_pktmbuf_alloc(qp->port->tx_hdr_mempool);
	if (!hdr) {
		return -ENOMEM;
	}

	sendmsg = rte_pktmbuf_clone(sendmsg, sendmsg->pool);

	trp = (struct trp_hdr *)rte_pktmbuf_append(hdr, sizeof(*trp));
	trp->psn = rte_cpu_to_be_32(info->psn);
	trp->ack_psn = rte_cpu_to_be_32(ep->recv_ack_psn);
	trp->opcode = rte_cpu_to_be_16(0);
	if (!(ep->trp_flags & trp_recv_missing)) {
		ep->trp_flags &= ~trp_ack_update;
	}

	rte_pktmbuf_chain(hdr, sendmsg);
	if (!qp->port->flags & port_checksum_offload) {
		payload_raw_cksum = info->ddp_raw_cksum
			+ rte_raw_cksum(trp, sizeof(*trp));
	}
	send_udp_dgram(qp, hdr, &ep->ah, payload_raw_cksum);

	return 0;
} /* resend_ddp_segment */

static inline struct rte_mbuf **
tx_pending_entry(struct ee_state *ep, uint32_t psn)
{
	int index = psn & (ep->tx_pending_size - 1);
	return &ep->tx_pending[index];

} /* tx_pending_entry */

static uint32_t
send_ddp_segment(struct usiw_qp *qp, struct rte_mbuf *sendmsg,
		struct ee_state *ep, struct usiw_send_wqe *wqe,
		size_t payload_length)
{
	struct pending_datagram_info *pending;
	uint32_t psn = ep->send_next_psn++;

	pending = (struct pending_datagram_info *)(sendmsg + 1);
	pending->wqe = wqe;
	pending->transmit_count = 0;
	pending->ddp_length = payload_length;
	if (!qp->port->flags & port_checksum_offload) {
		pending->ddp_raw_cksum = rte_raw_cksum(
				rte_pktmbuf_mtod(sendmsg, void *),
				rte_pktmbuf_data_len(sendmsg));
	}
	pending->psn = psn;

	assert(*tx_pending_entry(ep, psn) == NULL);
	*tx_pending_entry(ep, psn) = sendmsg;

	resend_ddp_segment(qp, sendmsg, ep);
	return psn;
} /* send_ddp_segment */


static void
send_trp_sack(struct usiw_qp *qp)
{
	struct rte_mbuf *sendmsg;
	struct ee_state *ep = &qp->remote_ep;
	struct trp_hdr *trp;

	assert(ep->trp_flags & trp_recv_missing);
	sendmsg = rte_pktmbuf_alloc(qp->port->tx_hdr_mempool);
	trp = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
	trp->psn = rte_cpu_to_be_32(ep->recv_sack_psn.min);
	trp->ack_psn = rte_cpu_to_be_32(ep->recv_sack_psn.max);
	trp->opcode = rte_cpu_to_be_16(trp_sack);

	ep->trp_flags &= ~trp_ack_update;

	send_udp_dgram(qp, sendmsg, &ep->ah,
			(qp->port->flags & port_checksum_offload)
					? 0 : rte_raw_cksum(trp, sizeof(*trp)));
} /* send_trp_sack */


static void
send_trp_fin(struct usiw_qp *qp)
{
	struct ee_state *ep = &qp->remote_ep;
	struct rte_mbuf *sendmsg;
	struct trp_hdr *trp;

	sendmsg = rte_pktmbuf_alloc(qp->port->tx_hdr_mempool);
	trp = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
	trp->psn = rte_cpu_to_be_32(ep->send_next_psn);
	trp->ack_psn = rte_cpu_to_be_32(ep->recv_ack_psn);
	trp->opcode = rte_cpu_to_be_16(trp_fin);

	if (!(ep->trp_flags & trp_recv_missing)) {
		ep->trp_flags &= ~trp_ack_update;
	}

	send_udp_dgram(qp, sendmsg, &ep->ah,
			(qp->port->flags & port_checksum_offload)
					? 0 : rte_raw_cksum(trp, sizeof(*trp)));

	/* Force flush of TX queue since we are shutting down, but we still
	 * need the receiver to get the FIN packet */
	flush_tx_queue(qp);
} /* send_trp_fin */


static void
send_trp_ack(struct usiw_qp *qp)
{
	struct ee_state *ep = &qp->remote_ep;
	struct rte_mbuf *sendmsg;
	struct trp_hdr *trp;

	assert(!(ep->trp_flags & trp_recv_missing));
	sendmsg = rte_pktmbuf_alloc(qp->port->tx_hdr_mempool);
	trp = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
	trp->psn = rte_cpu_to_be_32(ep->send_next_psn);
	trp->ack_psn = rte_cpu_to_be_32(ep->recv_ack_psn);
	trp->opcode = rte_cpu_to_be_16(0);
	ep->trp_flags &= ~trp_ack_update;

	send_udp_dgram(qp, sendmsg, &ep->ah,
			(qp->port->flags & port_checksum_offload)
					? 0 : rte_raw_cksum(trp, sizeof(*trp)));
} /* send_trp_ack */


#define FREE_WQE_BODY(queue) \
	do { \
		qp-> queue .bitmask[wqe->index >> 6] \
			|= UINT64_C(1) << (wqe->index & 63); \
	} while (0)

/** Returns the given send WQE back to the free pool.  It is removed from the
 * active set if still_active is true.  The sq lock MUST be locked when
 * calling this function. */
void
qp_free_send_wqe(struct usiw_qp *qp, struct usiw_send_wqe *wqe,
		bool still_active)
{
	if (still_active) {
		usiw_send_wqe_queue_del_active(&qp->sq, wqe);
	}
	FREE_WQE_BODY(sq);
} /* qp_free_send_wqe */

/** Returns the given receive WQE back to the free pool.  It is removed from
 * the active set if still_in_hash is true.  The rq lock MUST be locked when
 * calling this function. */
static void
qp_free_recv_wqe(struct usiw_qp *qp, struct usiw_recv_wqe *wqe)
{
	usiw_recv_wqe_queue_del_active(&qp->rq0, wqe);
	FREE_WQE_BODY(rq0);
} /* qp_free_recv_wqe */

#undef FREE_WQE_BODY

int
qp_get_next_send_wqe(struct usiw_qp *qp, struct usiw_send_wqe **wqe)
{
	size_t send_wqe_size = sizeof(struct usiw_send_wqe)
				+ qp->sq.max_sge * sizeof(struct iovec);
	int x, ret;

	rte_spinlock_lock(&qp->sq.lock);
	ret = -ENOSPC;
	for (x = 0; x < qp->sq.max_wr; ++x) {
		if (qp->sq.bitmask[x >> 6] & (UINT64_C(1) << (x & 63))) {
			*wqe = (struct usiw_send_wqe *)(qp->sq.storage
					+ x * send_wqe_size);
			(*wqe)->index = x;
			qp->sq.bitmask[x >> 6] &= ~(UINT64_C(1) << (x & 63));
			ret = 0;
			break;
		}
	}
	rte_spinlock_unlock(&qp->sq.lock);
	return ret;
} /* qp_get_next_send_wqe */

int
qp_get_next_recv_wqe(struct usiw_qp *qp, struct usiw_recv_wqe **wqe)
{
	size_t recv_wqe_size = sizeof(struct usiw_recv_wqe)
				+ qp->rq0.max_sge * sizeof(struct iovec);
	int x, ret;

	rte_spinlock_lock(&qp->rq0.lock);
	ret = -ENOSPC;
	for (x = 0; x < qp->rq0.max_wr; ++x) {
		if (qp->rq0.bitmask[x >> 6] & (UINT64_C(1) << (x & 63))) {
			*wqe = (struct usiw_recv_wqe *)(qp->rq0.storage
					+ x * recv_wqe_size);
			(*wqe)->index = x;
			qp->rq0.bitmask[x >> 6] &= ~(UINT64_C(1) << (x & 63));
			ret = 0;
			break;
		}
	}
	rte_spinlock_unlock(&qp->rq0.lock);
	return ret;
} /* qp_get_next_recv_wqe */


/** Retrieves a free CQE from the completion queue.  This acquires the lock on
 * the CQ, which must be released by calling finish_post_cqe(). */
static int
get_next_cqe(struct usiw_cq *cq, struct usiw_wc **cqe)
{
	void *p;
	int ret;

	ret = rte_ring_dequeue(cq->free_ring, &p);
	if (ret < 0) {
		*cqe = NULL;
		return ret;
	}
	*cqe = p;
	return 0;
} /* get_next_cqe */

/** Places a filled-in CQE into the completion queue.  This releases the lock on
 * the CQ, which must have been acquired previously via get_next_cqe(). */
static void
finish_post_cqe(struct usiw_cq *cq, struct usiw_wc *cqe)
{
	struct urdma_cq_event event;
	struct usiw_context *ctx;
	ssize_t ret;

	rte_spinlock_lock(&cq->lock);
	ret = rte_ring_enqueue(cq->cqe_ring, cqe);
	rte_spinlock_unlock(&cq->lock);
	assert(ret == 0);
	ctx = usiw_get_context(cq->ib_cq.context);
	assert(ctx != NULL);
	if (ctx && rte_atomic32_read(&cq->notify_count)) {
		rte_atomic32_dec(&cq->notify_count);
		event.event_type = SIW_EVENT_COMP_POSTED;
		event.cq_id = cq->cq_id;
		ret = write(ctx->event_fd, &event, sizeof(event));
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "write to event fd: %s\n",
					strerror(errno));
		} else if ((size_t)ret < sizeof(event)) {
			RTE_LOG(ERR, USER1, "partial write to event fd: %zd/%zu bytes\n",
					ret, sizeof(event));
		}
	}
} /* finish_post_cqe */


/** post_recv_cqe posts a CQE corresponding to a receive WQE, and frees the
 * completed WQE.  Locking on the CQ ensures that any operation done prior to
 * this will be seen by other threads prior to the completion being delivered.
 * This ensures that new operations can be posted immediately. */
static int
post_recv_cqe(struct usiw_qp *qp, struct usiw_recv_wqe *wqe,
		enum ibv_wc_status status)
{
	struct usiw_wc *cqe;
	struct usiw_cq *cq;
	int ret;

	cq = qp->recv_cq;
	ret = get_next_cqe(cq, &cqe);
	if (ret < 0) {
		RTE_LOG(NOTICE, USER1, "Failed to post recv CQE: %s\n",
				strerror(-ret));
		return ret;
	}
	cqe->wr_context = wqe->wr_context;
	cqe->status = status;
	cqe->opcode = IBV_WC_RECV;
	cqe->byte_len = wqe->input_size;
	cqe->qp_num = qp->ib_qp.qp_num;
	memcpy(&cqe->ah, &wqe->remote_ep->ah, sizeof(cqe->ah));

	qp_free_recv_wqe(qp, wqe);
	finish_post_cqe(cq, cqe);
	return 0;
} /* post_recv_cqe */


static enum ibv_wc_opcode
get_ibv_send_wc_opcode(enum usiw_send_opcode ours)
{
	switch (ours) {
	case usiw_wr_send:
		return IBV_WC_SEND;
	case usiw_wr_write:
		return IBV_WC_RDMA_WRITE;
	case usiw_wr_read:
		return IBV_WC_RDMA_READ;
	default:
		assert(0);
		return -1;
	}
} /* get_ibv_send_wc_opcode */


/** post_send_cqe posts a CQE corresponding to a send WQE, and frees the
 * completed WQE.  Locking on the CQ ensures that any operation done prior to
 * this will be seen by other threads prior to the completion being delivered.
 * This ensures that new operations can be posted immediately. */
static int
post_send_cqe(struct usiw_qp *qp, struct usiw_send_wqe *wqe,
		enum ibv_wc_status status)
{
	struct usiw_wc *cqe;
	struct usiw_cq *cq;
	int ret;

	cq = qp->send_cq;
	ret = get_next_cqe(cq, &cqe);
	if (ret < 0) {
		RTE_LOG(NOTICE, USER1, "Failed to post send CQE: %s\n",
				strerror(-ret));
		return ret;
	}
	cqe->wr_context = wqe->wr_context;
	cqe->status = status;
	cqe->opcode = get_ibv_send_wc_opcode(wqe->opcode);
	cqe->qp_num = qp->ib_qp.qp_num;
	memcpy(&cqe->ah, &wqe->remote_ep->ah, sizeof(cqe->ah));

	qp_free_send_wqe(qp, wqe, true);
	finish_post_cqe(cq, cqe);
	return 0;
} /* post_send_cqe */


static void
rq_flush(struct usiw_qp *qp)
{
	struct usiw_recv_wqe *wqe, **prev;

	rte_spinlock_lock(&qp->rq0.lock);
	while (rte_ring_dequeue(qp->rq0.ring, (void **)&wqe) == 0) {
		wqe->msn = qp->remote_ep.expected_recv_msn++;
		usiw_recv_wqe_queue_add_active(&qp->rq0, wqe);
	}
	TAILQ_FOR_EACH(wqe, &qp->rq0.active_head, active, prev) {
		post_recv_cqe(qp, wqe, IBV_WC_WR_FLUSH_ERR);
	}
	rte_spinlock_unlock(&qp->rq0.lock);
} /* rq_flush */


static void
sq_flush(struct usiw_qp *qp)
{
	struct usiw_send_wqe *wqe, **prev;

	rte_spinlock_lock(&qp->sq.lock);
	while (rte_ring_dequeue(qp->sq.ring, (void **)&wqe) == 0) {
		usiw_send_wqe_queue_add_active(&qp->sq, wqe);
	}
	TAILQ_FOR_EACH(wqe, &qp->sq.active_head, active, prev) {
		post_send_cqe(qp, wqe, IBV_WC_WR_FLUSH_ERR);
	}
	rte_spinlock_unlock(&qp->sq.lock);
} /* sq_flush */


static void
memcpy_from_iov(char * restrict dest, size_t dest_size,
		const struct iovec * restrict src, size_t iov_count,
		size_t offset)
{
	unsigned y;
	size_t prev, pos, cur;
	char *src_iov_base;

	pos = 0;
	for (y = 0, prev = 0; pos < dest_size && y < iov_count; ++y) {
		if (prev <= offset && offset < prev + src[y].iov_len) {
			cur = RTE_MIN(prev + src[y].iov_len - offset,
					dest_size - pos);
			src_iov_base = src[y].iov_base;
			memcpy(dest + pos, src_iov_base + offset - prev,
					cur);
			pos += cur;
			offset += cur;
		}
		prev += src[y].iov_len;
	}
} /* memcpy_from_iov */


static void
do_rdmap_send(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	struct rdmap_untagged_packet *new_rdmap;
	struct rte_mbuf *sendmsg;
	unsigned int packet_length;
	size_t payload_length;
	uint16_t mtu;

	rte_eth_dev_get_mtu(qp->port->portid, &mtu);
	mtu = RDMAP_MAX_PAYLOAD(mtu, struct rdmap_untagged_packet);

	while (wqe->bytes_sent < wqe->total_length
			&& serial_less_32(wqe->remote_ep->send_next_psn,
					wqe->remote_ep->send_max_psn)) {
		sendmsg = rte_pktmbuf_alloc(qp->port->tx_ddp_mempool);

		payload_length = RTE_MIN(mtu, wqe->total_length
				- wqe->bytes_sent);
		packet_length = RDMAP_UNTAGGED_ALLOC_SIZE(payload_length);
		new_rdmap = (struct rdmap_untagged_packet *)rte_pktmbuf_append(
					sendmsg, packet_length);
		new_rdmap->head.ddp_flags = (wqe->total_length
				- wqe->bytes_sent <= mtu)
			? DDP_V1_UNTAGGED_LAST_DF
			: DDP_V1_UNTAGGED_DF;
		new_rdmap->head.rdmap_info = rdmap_opcode_send | RDMAP_V1;
		new_rdmap->head.sink_stag = rte_cpu_to_be_32(0);
		new_rdmap->qn = rte_cpu_to_be_32(0);
		new_rdmap->msn = rte_cpu_to_be_32(wqe->msn);
		new_rdmap->mo = rte_cpu_to_be_32(wqe->bytes_sent);
		if (wqe->flags & usiw_send_inline) {
			memcpy(PAYLOAD_OF(new_rdmap),
					(char *)wqe->iov + wqe->bytes_sent,
					payload_length);
		} else {
			memcpy_from_iov(PAYLOAD_OF(new_rdmap), payload_length,
					wqe->iov, wqe->iov_count,
					wqe->bytes_sent);
		}

		send_ddp_segment(qp, sendmsg, wqe->remote_ep, wqe,
				payload_length);
		RTE_LOG(DEBUG, USER1, "SEND transmit msn=%" PRIu32 " [%zu-%zu]\n",
				wqe->msn,
				wqe->bytes_sent,
				wqe->bytes_sent + payload_length);

		wqe->bytes_sent += payload_length;
	}

	if (wqe->bytes_sent == wqe->total_length) {
		wqe->state = SEND_WQE_WAIT;
	}
} /* do_rdmap_send */


static void
do_rdmap_write(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	struct rdmap_tagged_packet *new_rdmap;
	struct rte_mbuf *sendmsg;
	unsigned int packet_length;
	size_t payload_length;
	uint16_t mtu;

	rte_eth_dev_get_mtu(qp->port->portid, &mtu);
	mtu = RDMAP_MAX_PAYLOAD(mtu, struct rdmap_tagged_packet);

	while (wqe->bytes_sent < wqe->total_length
			&& serial_less_32(wqe->remote_ep->send_next_psn,
					wqe->remote_ep->send_max_psn)) {
		sendmsg = rte_pktmbuf_alloc(qp->port->tx_ddp_mempool);

		payload_length = RTE_MIN(mtu, wqe->total_length
				- wqe->bytes_sent);
		packet_length = RDMAP_TAGGED_ALLOC_SIZE(payload_length);
		new_rdmap = (struct rdmap_tagged_packet *)rte_pktmbuf_append(
					sendmsg, packet_length);
		new_rdmap->head.ddp_flags = (wqe->total_length
				- wqe->bytes_sent <= mtu)
			? DDP_V1_TAGGED_LAST_DF
			: DDP_V1_TAGGED_DF;
		new_rdmap->head.rdmap_info = RDMAP_V1 | rdmap_opcode_rdma_write;
		new_rdmap->head.sink_stag = rte_cpu_to_be_32(wqe->rkey);
		new_rdmap->offset = rte_cpu_to_be_64(wqe->remote_addr
				 + wqe->bytes_sent);
		if (wqe->flags & usiw_send_inline) {
			memcpy(PAYLOAD_OF(new_rdmap),
					(char *)wqe->iov + wqe->bytes_sent,
					payload_length);
		} else {
			memcpy_from_iov(PAYLOAD_OF(new_rdmap), payload_length,
					wqe->iov, wqe->iov_count,
					wqe->bytes_sent);
		}

		send_ddp_segment(qp, sendmsg, wqe->remote_ep, wqe,
				payload_length);
		RTE_LOG(DEBUG, USER1, "RDMA WRITE transmit bytes %zu through %zu\n",
				wqe->bytes_sent,
				wqe->bytes_sent + payload_length);

		wqe->bytes_sent += payload_length;
	}

	if (wqe->bytes_sent == wqe->total_length) {
		wqe->state = SEND_WQE_WAIT;
	}
} /* do_rdmap_write */


static void
do_rdmap_read_request(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	struct rdmap_readreq_packet *new_rdmap;
	struct rte_mbuf *sendmsg;
	struct ibv_mr *temp_mr;
	unsigned int packet_length;
	uint32_t rkey;
	uint16_t mtu;

	if (wqe->state != SEND_WQE_TRANSFER) {
		return;
	}

	if (qp->ird_active >= qp->ird_max) {
		/* Cannot issue more than ird_max simultaneous RDMA READ
		 * Requests. */
		return;
	} else if (wqe->remote_ep->send_next_psn
			== wqe->remote_ep->send_max_psn
			|| serial_greater_32(wqe->remote_ep->send_next_psn,
				wqe->remote_ep->send_max_psn)) {
		/* We have reached the maximum number of credits we are allowed
		 * to send. */
		return;
	}

	rkey = STAG_RDMA_READ(wqe->msn);
	temp_mr = urdma_reg_mr_with_rkey(&qp->pd->pd, wqe->iov[0].iov_base,
			wqe->iov[0].iov_len, IBV_ACCESS_REMOTE_WRITE,
			rkey);
	if (!temp_mr) {
		/* FIXME: issue error completion */
		rte_atomic16_set(&qp->conn_state, usiw_qp_error);
		return;
	}
	qp->ird_active++;

	rte_eth_dev_get_mtu(qp->port->portid, &mtu);

	sendmsg = rte_pktmbuf_alloc(qp->port->tx_ddp_mempool);

	packet_length = sizeof(*new_rdmap);
	new_rdmap = (struct rdmap_readreq_packet *)rte_pktmbuf_append(
				sendmsg, packet_length);
	new_rdmap->untagged.head.ddp_flags = DDP_V1_UNTAGGED_LAST_DF;
	new_rdmap->untagged.head.rdmap_info
		= rdmap_opcode_rdma_read_request | RDMAP_V1;
	new_rdmap->untagged.head.sink_stag = rte_cpu_to_be_32(rkey);
	new_rdmap->untagged.qn = rte_cpu_to_be_32(1);
	new_rdmap->untagged.msn = rte_cpu_to_be_32(wqe->msn);
	new_rdmap->untagged.mo = rte_cpu_to_be_32(0);
	new_rdmap->sink_offset
		= rte_cpu_to_be_64((uintptr_t)wqe->iov[0].iov_base);
	new_rdmap->read_msg_size = rte_cpu_to_be_32(wqe->iov[0].iov_len);
	new_rdmap->source_stag = rte_cpu_to_be_32(wqe->rkey);
	new_rdmap->source_offset = rte_cpu_to_be_64(wqe->remote_addr);

	send_ddp_segment(qp, sendmsg, wqe->remote_ep, wqe, 0);

	wqe->state = SEND_WQE_WAIT;
} /* do_rdmap_read_request */

static struct rdmap_terminate_payload *
terminate_append_ddp_header(struct rdmap_packet *orig, struct rte_mbuf *sendmsg,
		struct rdmap_terminate_packet *term)
{
	struct rdmap_terminate_payload *p;
	size_t hdr_size;

	term->hdrct = rdmap_hdrct_m|rdmap_hdrct_d;
	if (DDP_GET_T(orig->ddp_flags)) {
		hdr_size = sizeof(struct rdmap_tagged_packet);
	} else {
		hdr_size = sizeof(struct rdmap_untagged_packet);
	}
	p = (struct rdmap_terminate_payload *)rte_pktmbuf_append(sendmsg,
								hdr_size);
	memcpy(&p->payload, orig, hdr_size);
	return p;
} /* terminate_append_ddp_header */

static void
do_rdmap_terminate(struct usiw_qp *qp, struct packet_context *orig,
		enum rdmap_errno errcode)
{
	struct rte_mbuf *sendmsg = rte_pktmbuf_alloc(qp->port->tx_ddp_mempool);
	struct rdmap_terminate_packet *new_rdmap;
	struct rdmap_terminate_payload *payload;

	new_rdmap = (struct rdmap_terminate_packet *)rte_pktmbuf_append(sendmsg,
					sizeof(*new_rdmap));
	new_rdmap->untagged.head.ddp_flags = DDP_V1_UNTAGGED_LAST_DF;
	new_rdmap->untagged.head.rdmap_info
		= rdmap_opcode_terminate | RDMAP_V1;
	new_rdmap->untagged.head.sink_stag = 0;
	new_rdmap->untagged.qn = rte_cpu_to_be_32(2);
	new_rdmap->untagged.msn = rte_cpu_to_be_32(1);
	new_rdmap->untagged.mo = rte_cpu_to_be_32(0);
	new_rdmap->error_code = rte_cpu_to_be_16(errcode);
	new_rdmap->reserved = 0;
	switch (errcode & 0xff00) {
	case 0x0100:
		/* Error caused by RDMA Read Request */
		new_rdmap->hdrct = rdmap_hdrct_m|rdmap_hdrct_d|rdmap_hdrct_r;

		payload = (struct rdmap_terminate_payload *)rte_pktmbuf_append(sendmsg,
				2 + sizeof(struct rdmap_readreq_packet));
		memcpy(&payload->payload, orig->rdmap,
				sizeof(struct rdmap_readreq_packet));
		break;
	case 0x0200:
	case 0x1200:
		/* Error caused by DDP or RDMAP untagged message other than
		 * Read Request */
		if (orig) {
			payload = terminate_append_ddp_header(orig->rdmap,
					sendmsg, new_rdmap);
		} else {
			new_rdmap->hdrct = 0;
			payload = NULL;
		}
		break;
	case 0x1000:
	case 0x1100:
		/* DDP layer error */
		payload = terminate_append_ddp_header(orig->rdmap,
				sendmsg, new_rdmap);
		break;
	case 0x0000:
	default:
		new_rdmap->hdrct = 0;
		payload = NULL;
		break;
	}

	if (payload) {
		payload->ddp_seg_len = rte_cpu_to_be_16(orig->ddp_seg_length);
	}
	(void)send_ddp_segment(qp, sendmsg, orig->src_ep, NULL, 0);
} /* do_rdmap_terminate */


static void
memcpy_to_iov(struct iovec * restrict dest, size_t iov_count,
		const char * restrict src, size_t src_size, size_t offset)
{
	unsigned y;
	size_t prev, pos, cur;
	char *dest_iov_base;

	pos = 0;
	for (y = 0, prev = 0; pos < src_size && y < iov_count; ++y) {
		if (prev <= offset && offset < prev + dest[y].iov_len) {
			cur = RTE_MIN(prev + dest[y].iov_len - offset,
					src_size - pos);
			dest_iov_base = dest[y].iov_base;
			memcpy(dest_iov_base + offset - prev, src + pos,
					cur);
			pos += cur;
			offset += cur;
		}
		prev += dest[y].iov_len;
	}
} /* memcpy_to_iov */


static void
process_send(struct usiw_qp *qp, struct packet_context *orig)
{
	struct usiw_recv_wqe *wqe;
	struct rdmap_untagged_packet *rdmap
		= (struct rdmap_untagged_packet *)orig->rdmap;
	struct ee_state *ee = orig->src_ep;
	uint32_t msn;
	size_t offset;
	size_t payload_length;
	int ret;

	ret = usiw_recv_wqe_queue_lookup(&qp->rq0,
			rte_be_to_cpu_32(rdmap->msn), &wqe);
	assert(ret != -EINVAL);
	if (ret < 0) {
		msn = rte_be_to_cpu_32(rdmap->msn);
		if (msn == ee->expected_recv_msn) {
			ee->expected_recv_msn++;
		} else if (serial_less_32(msn, ee->expected_recv_msn)) {
			/* This is a duplicate of a previously received
			 * message */
			do_rdmap_terminate(qp, orig,
					ddp_error_untagged_invalid_msn);
			return;
		} else {
			/* else, we received this message out of order */
			assert(serial_greater_32(msn, ee->expected_recv_msn));
			RTE_LOG(DEBUG, USER1, "Received msn=%" PRIu32 " but expected msn=%" PRIu32 "\n",
					msn, ee->expected_recv_msn);
		}

		ret = rte_ring_dequeue(qp->rq0.ring, (void **)&wqe);
		if (ret != 0) {
			do_rdmap_terminate(qp, orig,
					ddp_error_untagged_no_buffer);
			rte_exit(EXIT_FAILURE, "rte_ring_dequeue rq0.ring port %u queue %u: %s\n",
					qp->port->portid,
					qp->rx_queue, rte_strerror(-ret));
		}

		wqe->remote_ep = ee;
		wqe->msn = msn;

		usiw_recv_wqe_queue_add_active(&qp->rq0, wqe);
	}

	offset = rte_be_to_cpu_32(rdmap->mo);
	payload_length = orig->ddp_seg_length - sizeof(struct rdmap_untagged_packet);
	if (offset + payload_length > wqe->total_request_size) {
		RTE_LOG(DEBUG, USER1, "DROP: offset=%zu + payload_length=%zu > wr_len=%zu\n",
				offset, payload_length, wqe->total_request_size);
		do_rdmap_terminate(qp, orig,
				ddp_error_untagged_message_too_long);
		return;
	}

	if (DDP_GET_L(rdmap->head.ddp_flags)) {
		if (wqe->input_size != 0) {
			RTE_LOG(DEBUG, USER1, "silently DROP duplicate last packet.\n");
			return;
		}
		wqe->input_size = offset + payload_length;
	}

	memcpy_to_iov(wqe->iov, wqe->iov_count, PAYLOAD_OF(rdmap),
			payload_length, offset);
	wqe->recv_size += payload_length;

	assert(wqe->input_size == 0 || wqe->recv_size <= wqe->input_size);
	if (wqe->recv_size == wqe->input_size) {
		rte_spinlock_lock(&qp->rq0.lock);
		post_recv_cqe(qp, wqe, IBV_WC_SUCCESS);
		rte_spinlock_unlock(&qp->rq0.lock);
	}
}	/* process_send */


static int
respond_rdma_read(struct usiw_qp *qp)
{
	struct rdmap_tagged_packet *new_rdmap;
	struct read_response_state *readresp, **prev;
	struct rte_mbuf *sendmsg;
	size_t dgram_length;
	size_t payload_length;
	uint16_t mtu;
	int count;

	rte_eth_dev_get_mtu(qp->port->portid, &mtu);
	mtu = RDMAP_MAX_PAYLOAD(mtu, struct rdmap_tagged_packet);

	count = 0;
	TAILQ_FOR_EACH(readresp, &qp->readresp_active, qp_entry, prev) {
		while (readresp->msg_size > 0
				&& serial_less_32(readresp->sink_ep->send_next_psn,
					readresp->sink_ep->send_max_psn)) {
			sendmsg = rte_pktmbuf_alloc(qp->port->tx_ddp_mempool);

			payload_length = RTE_MIN(mtu, readresp->msg_size);
			dgram_length = RDMAP_TAGGED_ALLOC_SIZE(payload_length);

			new_rdmap = (struct rdmap_tagged_packet *)rte_pktmbuf_append(
					sendmsg, dgram_length);
			new_rdmap->head.ddp_flags = (readresp->msg_size <= mtu)
				? DDP_V1_TAGGED_LAST_DF : DDP_V1_TAGGED_DF;
			new_rdmap->head.rdmap_info = RDMAP_V1
				| rdmap_opcode_rdma_read_response;
			new_rdmap->head.sink_stag = readresp->sink_stag;
			new_rdmap->offset = rte_cpu_to_be_64(readresp->sink_offset);
			memcpy(PAYLOAD_OF(new_rdmap), readresp->vaddr,
					payload_length);

			(void)send_ddp_segment(qp, sendmsg, readresp->sink_ep,
					NULL, payload_length);
			readresp->vaddr += payload_length;
			readresp->msg_size -= payload_length;
			readresp->sink_offset += payload_length;
			count++;
		}

		if (readresp->msg_size == 0) {
			/* Signal that this is done */
			TAILQ_REMOVE(&qp->readresp_active, readresp, qp_entry);
			TAILQ_INSERT_TAIL(&qp->readresp_empty, readresp, qp_entry);
		}
	}
	return count;
} /* respond_rdma_read */


static void
process_rdma_read_request(struct usiw_qp *qp, struct packet_context *orig)
{
	struct rdmap_readreq_packet *rdmap
		= (struct rdmap_readreq_packet *)orig->rdmap;
	struct read_response_state *readresp;
	uint32_t rkey;
	uint32_t msn;
	struct usiw_mr **candidate;
	struct usiw_mr *mr;

	msn = rte_be_to_cpu_32(rdmap->untagged.msn);
	if (msn != orig->src_ep->expected_read_msn) {
		RTE_LOG(DEBUG, USER1, "RDMA READ failure: expected MSN %" PRIu32 " received %" PRIu32 "\n",
				orig->src_ep->expected_read_msn, msn);
		do_rdmap_terminate(qp, orig, ddp_error_untagged_invalid_msn);
		return;
	}
	orig->src_ep->expected_read_msn++;

	rkey = rte_be_to_cpu_32(rdmap->source_stag);
	candidate = usiw_mr_lookup(qp->pd, rkey);
	if (!candidate) {
		RTE_LOG(DEBUG, USER1, "RDMA READ failure: invalid rkey %" PRIx32 "\n",
				rkey);
		do_rdmap_terminate(qp, orig, rdmap_error_stag_invalid);
		return;
	}

	mr = *candidate;
	uintptr_t vaddr = (uintptr_t)rte_be_to_cpu_64(rdmap->source_offset);
	uint32_t rdma_length = rte_be_to_cpu_32(rdmap->read_msg_size);
	if (vaddr < (uintptr_t)mr->mr.addr || vaddr + rdma_length
			> (uintptr_t)mr->mr.addr + mr->mr.length) {
		RTE_LOG(DEBUG, USER1, "RDMA READ failure: source [%" PRIxPTR ", %" PRIxPTR
				"] outside of memory region [%" PRIxPTR ", %" PRIxPTR "]\n",
				vaddr, vaddr + rdma_length,
				(uintptr_t)mr->mr.addr,
				(uintptr_t)mr->mr.addr + mr->mr.length);
		do_rdmap_terminate(qp, orig,
				rdmap_error_base_or_bounds_violation);
		return;
	}

	readresp = qp->readresp_empty.tqh_first;
	if (!readresp) {
		RTE_LOG(DEBUG, USER1, "RDMA READ failure: exceeded ord_max %" PRIu8 "\n",
				qp->ord_max);
		do_rdmap_terminate(qp, orig,
				rdmap_error_remote_stream_catastrophic);
		return;
	}
	TAILQ_REMOVE(&qp->readresp_empty, readresp, qp_entry);
	TAILQ_INSERT_TAIL(&qp->readresp_active, readresp, qp_entry);

	readresp->vaddr = (void *)vaddr;
	readresp->msg_size = rdma_length;
	readresp->sink_stag = rdmap->untagged.head.sink_stag;
	readresp->sink_offset = rte_be_to_cpu_64(rdmap->sink_offset);
	readresp->sink_ep = orig->src_ep;
}	/* process_rdma_read_request */


static void
process_rdma_read_response(struct usiw_qp *qp, struct packet_context *orig)
{
	struct rdmap_tagged_packet *rdmap;
	struct usiw_send_wqe *read_wqe;
	struct usiw_mr **mr;
	uint32_t rdma_length;
	int ret;

	rdmap = (struct rdmap_tagged_packet *)orig->rdmap;
	/* FIXME: stag != msn; need to disambiguate */
	ret = usiw_send_wqe_queue_lookup(&qp->sq,
			usiw_wr_read, rte_be_to_cpu_32(rdmap->head.sink_stag),
			&read_wqe);

	if (ret < 0 || !read_wqe || read_wqe->opcode != usiw_wr_read) {
		RTE_LOG(DEBUG, USER1, "Unexpected RDMA READ response!\n");
		do_rdmap_terminate(qp, orig, rdmap_error_opcode_unexpected);
		return;
	}

	rdma_length = orig->ddp_seg_length - sizeof(*rdmap);

	read_wqe->bytes_sent += rdma_length;
	assert(read_wqe->bytes_sent <= read_wqe->iov[0].iov_len);
	if (read_wqe->bytes_sent == read_wqe->iov[0].iov_len) {
		/* We have received the last datagram */
		mr = usiw_mr_lookup(qp->pd, STAG_RDMA_READ(read_wqe->msn));
		if (mr) {
			usiw_dereg_mr_real(qp->pd, mr);
		}

		rte_spinlock_lock(&qp->sq.lock);
		if (read_wqe->flags & usiw_send_signaled) {
			post_send_cqe(qp, read_wqe, IBV_WC_SUCCESS);
		} else {
			qp_free_send_wqe(qp, read_wqe, true);
		}
		rte_spinlock_unlock(&qp->sq.lock);
		assert(qp->ird_active > 0);
		qp->ird_active--;
	}
}	/* process_rdma_read_response */


static void
qp_shutdown(struct usiw_qp *qp)
{
	struct ibv_qp_attr qp_attr;
	struct ibv_modify_qp cmd;
	int ret;

	send_trp_fin(qp);

	rte_atomic16_set(&qp->conn_state, usiw_qp_error);
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_ERR;
	ibv_cmd_modify_qp(&qp->ib_qp, &qp_attr, IBV_QP_STATE,
			&cmd, sizeof(cmd));

	sq_flush(qp);
	rq_flush(qp);

	ret = rte_eth_dev_filter_ctrl(qp->port->portid,
			RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_DELETE,
			&qp->fdir_filter);
	if (ret) {
		RTE_LOG(DEBUG, USER1, "Could not delete fdir filter for qp %" PRIu32 ": %s\n",
				qp->ib_qp.qp_num, rte_strerror(ret));
	}
} /* qp_shutdown */


static void
process_terminate(struct usiw_qp *qp, struct packet_context *orig)
{
	struct usiw_send_wqe *wqe;
	struct rdmap_terminate_packet *rdmap;
	struct rdmap_readreq_packet *rreq;
	struct rdmap_tagged_packet *t;
	enum ibv_wc_status wc_status;
	struct usiw_mr **mr;
	uint_fast16_t errcode;
	int ret;

	rdmap = (struct rdmap_terminate_packet *)orig->rdmap;
	errcode = rte_be_to_cpu_16(rdmap->error_code);
	if (!(rdmap->hdrct & rdmap_hdrct_d)) {
		RTE_LOG(DEBUG, USER1, "Received TERMINATE with error code %#" PRIxFAST16 " and no DDP header\n",
			errcode);
		wqe = NULL;
		goto out;
	}

	switch (errcode & 0xff00) {
	case 0x0100:
		/* RDMA Read Request Error */
		rreq = (struct rdmap_readreq_packet *)(rdmap + 1);
		ret = usiw_send_wqe_queue_lookup(&qp->sq, usiw_wr_read,
				rte_be_to_cpu_32(rreq->untagged.head.sink_stag),
				&wqe);
		if (ret < 0 || !wqe || wqe->opcode != usiw_wr_read) {
			RTE_LOG(DEBUG, USER1, "TERMINATE sink_stag=%" PRIu32 " has no matching RDMA Read Request\n",
				rte_be_to_cpu_32(rreq->untagged.head.sink_stag));
			return;
		}
		mr = usiw_mr_lookup(qp->pd, STAG_RDMA_READ(wqe->msn));
		if (mr) {
			usiw_dereg_mr_real(qp->pd, mr);
		}
		wc_status = IBV_WC_REM_ACCESS_ERR;
		break;
	case 0x1100:
		/* DDP Tagged Message Error (RDMA Write/RDMA Read Response) */
		t = (struct rdmap_tagged_packet *)(rdmap + 1);
		wc_status = IBV_WC_REM_ACCESS_ERR;
		switch (RDMAP_GET_OPCODE(t->head.rdmap_info)) {
		case rdmap_opcode_rdma_write:
			ret = usiw_send_wqe_queue_lookup(&qp->sq,
					usiw_wr_write,
					rte_be_to_cpu_32(t->head.sink_stag),
					&wqe);
			if (ret < 0 || !wqe) {
				RTE_LOG(DEBUG, USER1, "TERMINATE sink_stag=%" PRIu32 " has no matching RDMA WRITE operation\n",
						rte_be_to_cpu_32(t->head.sink_stag));
				return;
			}
			break;
		case rdmap_opcode_rdma_read_response:
			RTE_LOG(DEBUG, USER1, "TERMINATE for RDMA READ Response with sink_stag=%" PRIu32 ": error code %" PRIxFAST16 "\n",
						rte_be_to_cpu_32(t->head.sink_stag),
						errcode);
			return;
		default:
			RTE_LOG(DEBUG, USER1, "TERMINATE sink_stag=%" PRIu32 " has tagged message error but invalid opcode %u\n",
					rte_be_to_cpu_32(t->head.sink_stag),
					RDMAP_GET_OPCODE(t->head.rdmap_info));
			return;
		}
		break;
	default:
		RTE_LOG(DEBUG, USER1, "Received TERMINATE with unhandled error code %#" PRIxFAST16 "\n",
			errcode);
		wqe = NULL;
		break;
	}

out:
	if (wqe) {
		rte_spinlock_lock(&qp->sq.lock);
		post_send_cqe(qp, wqe, wc_status);
		rte_spinlock_unlock(&qp->sq.lock);
	} else {
		qp_shutdown(qp);
	}
} /* process_terminate */


/** Complete the requested WQE if and only if all completion ordering rules
 * have been met. */
static void
try_complete_wqe(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	/* We cannot post the completion until all previous WQEs have
	 * completed. */
	if (wqe == qp->sq.active_head.tqh_first) {
		rte_spinlock_lock(&qp->sq.lock);
		if (wqe->flags & usiw_send_signaled) {
			post_send_cqe(qp, wqe, IBV_WC_SUCCESS);
		} else {
			qp_free_send_wqe(qp, wqe, true);
		}
		rte_spinlock_unlock(&qp->sq.lock);
	}
} /* try_complete_wqe */


static void
do_process_ack(struct usiw_qp *qp, struct usiw_send_wqe *wqe,
		struct pending_datagram_info *pending)
{
	wqe->bytes_acked += pending->ddp_length;
	assert(wqe->bytes_sent >= wqe->bytes_acked);

	if (wqe->bytes_acked == wqe->total_length) {
		assert(wqe->state == SEND_WQE_WAIT);
		wqe->state = SEND_WQE_COMPLETE;
		try_complete_wqe(qp, wqe);
	}
} /* do_process_ack */


static void
maybe_sack_pending(struct pending_datagram_info *pending, uint32_t psn_min,
		uint32_t psn_max)
{
	if ((psn_min == pending->psn || serial_less_32(psn_min, pending->psn))
			&& serial_less_32(pending->psn, psn_max)) {
		pending->next_retransmit = UINT64_MAX;
	}
} /* maybe_sack_pending */


static void
process_trp_sack(struct ee_state *ep, uint32_t psn_min, uint32_t psn_max)
{
	struct pending_datagram_info *info;
	struct rte_mbuf **sendmsg, **start, **end;

	sendmsg = start = ep->tx_head;
	end = ep->tx_pending + ep->tx_pending_size;
	if (!*sendmsg) {
		return;
	}

	do {
		info = (struct pending_datagram_info *)(sendmsg + 1);
		maybe_sack_pending(info, psn_min, psn_max);

		if (++sendmsg == end) {
			sendmsg = ep->tx_pending;
		}
	} while (sendmsg != start && *sendmsg);
} /* process_trp_sack */


static void
sweep_unacked_packets(struct usiw_qp *qp, uint64_t now)
{
	struct pending_datagram_info *pending;
	struct ee_state *ep = &qp->remote_ep;
	struct rte_mbuf **end, **p, *sendmsg;
	int count;

	end = ep->tx_pending + ep->tx_pending_size;
	if (!*ep->tx_head) {
		return;
	}

	for (count = 0; count < ep->tx_pending_size
			&& (sendmsg = *ep->tx_head) != NULL; count++) {
		pending = (struct pending_datagram_info *)(sendmsg + 1);
		if (serial_less_32(pending->psn, ep->send_last_acked_psn)) {
			/* Packet was acked */
			if (pending->wqe) {
				do_process_ack(qp, pending->wqe, pending);
			}
			rte_pktmbuf_free(sendmsg);
			*ep->tx_head = NULL;
			if (++ep->tx_head == end) {
				ep->tx_head = ep->tx_pending;
			}
		} else {
			break;
		}
	}

	p = ep->tx_head;
	while (count < ep->tx_pending_size && (sendmsg = *p) != NULL) {
		pending = (struct pending_datagram_info *)(sendmsg + 1);
		if (now > pending->next_retransmit
				&& resend_ddp_segment(qp, sendmsg, ep) < 0) {
			RTE_LOG(NOTICE, USER1, "retransmit limit (%d) exceeded psn=%" PRIu32 "\n",
					RETRANSMIT_MAX,
					pending->psn);
			if (pending->wqe) {
				rte_spinlock_lock(&qp->sq.lock);
				post_send_cqe(qp, pending->wqe, IBV_WC_RETRY_EXC_ERR);
				rte_spinlock_unlock(&qp->sq.lock);
			}
			rte_atomic16_set(&qp->conn_state, usiw_qp_error);
			if (p == ep->tx_head) {
				*ep->tx_head = NULL;
				if (++ep->tx_head == end) {
					ep->tx_head = ep->tx_pending;
				}
			} else {
				pending->next_retransmit = UINT64_MAX;
			}
		}
		if (++p == end) {
			p = ep->tx_pending;
		}
	}
} /* sweep_unacked_packets */


static void
ddp_place_tagged_data(struct usiw_qp *qp, struct packet_context *orig)
{
	struct rdmap_tagged_packet *rdmap;
	struct usiw_mr **candidate;
	struct usiw_mr *mr;
	uintptr_t vaddr;
	uint32_t rkey;
	uint32_t rdma_length;
	unsigned int opcode;

	rdmap = (struct rdmap_tagged_packet *)orig->rdmap;
	rkey = rte_be_to_cpu_32(rdmap->head.sink_stag);
	candidate = usiw_mr_lookup(qp->pd, rkey);
	if (!candidate) {
		RTE_LOG(DEBUG, USER1, "received DDP tagged message with invalid stag %" PRIx32 "\n",
				rkey);
		do_rdmap_terminate(qp, orig, ddp_error_tagged_stag_invalid);
		return;
	}

	mr = *candidate;
	vaddr = (uintptr_t)rte_be_to_cpu_64(rdmap->offset);
	rdma_length = orig->ddp_seg_length - sizeof(*rdmap);
	if (vaddr < (uintptr_t)mr->mr.addr || vaddr + rdma_length
			> (uintptr_t)mr->mr.addr + mr->mr.length) {
		RTE_LOG(DEBUG, USER1, "received DDP tagged message with destination [%" PRIxPTR ", %" PRIxPTR "] outside of memory region [%" PRIxPTR ", %" PRIxPTR "]\n",
				vaddr, vaddr + rdma_length,
				(uintptr_t)mr->mr.addr,
				(uintptr_t)mr->mr.addr + mr->mr.length);
		do_rdmap_terminate(qp, orig,
				ddp_error_tagged_base_or_bounds_violation);
		return;
	}

	memcpy((void *)vaddr, PAYLOAD_OF(rdmap), rdma_length);
	RTE_LOG(DEBUG, USER1, "Wrote %" PRIu32 " bytes to tagged buffer with stag=%" PRIx32 " at %" PRIx64 "\n",
			rdma_length, rkey, vaddr);

	opcode = RDMAP_GET_OPCODE(orig->rdmap->rdmap_info);
	switch (opcode) {
	case rdmap_opcode_rdma_write:
		break;
	case rdmap_opcode_rdma_read_response:
		process_rdma_read_response(qp, orig);
		break;
	default:
		RTE_LOG(DEBUG, USER1, "received DDP tagged message with invalid opcode %" PRIx8 "\n",
				opcode);
		do_rdmap_terminate(qp, orig, rdmap_error_opcode_unexpected);
	}
} /* ddp_place_tagged_data */


struct ee_state *
usiw_get_ee_context(struct usiw_qp *qp, struct urdma_ah *ah)
{
	struct ee_state *ee = &qp->remote_ep;
	return (is_same_ether_addr(&ah->ether_addr, &ee->ah.ether_addr)
			&& ah->ipv4_addr == ee->ah.ipv4_addr
			&& ah->udp_port == ee->ah.udp_port) ? ee : NULL;
} /* usiw_get_ee_context */


static void
process_data_packet(struct usiw_qp *qp, struct rte_mbuf *mbuf)
{
	struct packet_context ctx;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct trp_hdr *trp_hdr;
	struct urdma_ah ah;
	uint16_t trp_opcode;

#ifdef DEBUG_PACKET_HEADERS
	RTE_LOG(DEBUG, USER1, "Begin processing received packet:\n");
	rte_pktmbuf_dump(stderr, mbuf, 128);
#endif

	if (mbuf->ol_flags & (PKT_RX_L4_CKSUM_BAD|PKT_RX_IP_CKSUM_BAD)) {
		if (RTE_LOG_LEVEL >= RTE_LOG_DEBUG) {
			uint16_t actual_udp_checksum, actual_ipv4_cksum;
			ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
					struct ipv4_hdr *, sizeof(*eth_hdr));
			udp_hdr = rte_pktmbuf_mtod_offset(mbuf,
					struct udp_hdr *,
					sizeof(*eth_hdr) + sizeof(*ipv4_hdr));
			actual_udp_checksum = udp_hdr->dgram_cksum;
			udp_hdr->dgram_cksum = 0;
			actual_ipv4_cksum = ipv4_hdr->hdr_checksum;
			ipv4_hdr->hdr_checksum = 0;
			RTE_LOG(DEBUG, USER1, "ipv4 expected cksum %#" PRIx16 " got %#" PRIx16 "\n",
					rte_ipv4_cksum(ipv4_hdr),
					actual_ipv4_cksum);
			RTE_LOG(DEBUG, USER1, "udp expected cksum %#" PRIx16 " got %#" PRIx16 "\n",
				rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr),
				actual_udp_checksum);
		}
		RTE_LOG(DEBUG, USER1, "Drop packet with bad UDP/IP checksum\n");
		return;
	}

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ether_addr_copy(&eth_hdr->s_addr, &ah.ether_addr);

	ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*eth_hdr));
	assert(ipv4_hdr->next_proto_id == IP_HDR_PROTO_UDP);
	assert(ipv4_hdr->dst_addr == qp->port->ipv4_addr);
	ah.ipv4_addr = ipv4_hdr->src_addr;

	udp_hdr = (struct udp_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*ipv4_hdr));
	assert(udp_hdr->dst_port == qp->udp_port);
	ah.udp_port = udp_hdr->src_port;

	ctx.src_ep = usiw_get_ee_context(qp, &ah);
	if (!ctx.src_ep) {
		/* Drop the packet; do not send TERMINATE */
		return;
	}

	trp_hdr = (struct trp_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*udp_hdr));
	trp_opcode = rte_be_to_cpu_16(trp_hdr->opcode) & trp_opcode_mask;
	switch (trp_opcode) {
	case 0:
		/* Normal opcode */
		break;
	case trp_sack:
		/* This is a selective acknowledgement */
		RTE_LOG(NOTICE, USER1, "receive SACK [%" PRIu32 ", %" PRIu32 "); send_ack_psn %" PRIu32 "\n",
				rte_be_to_cpu_32(trp_hdr->psn),
				rte_be_to_cpu_32(trp_hdr->ack_psn),
				ctx.src_ep->send_last_acked_psn);
		process_trp_sack(ctx.src_ep, rte_be_to_cpu_32(trp_hdr->psn),
				rte_be_to_cpu_32(trp_hdr->ack_psn));
		return;
	case trp_fin:
		/* This is a finalize packet */
		qp_shutdown(qp);
		return;
	default:
		RTE_LOG(NOTICE, USER1, "receive unexpected opcode %" PRIu16 "; dropping\n",
				trp_opcode >> trp_opcode_shift);
		return;
	}

	/* Update sender state based on received ack_psn */
	ctx.src_ep->send_last_acked_psn = rte_be_to_cpu_32(trp_hdr->ack_psn);
	ctx.src_ep->send_max_psn = ctx.src_ep->send_last_acked_psn
					+ ctx.src_ep->tx_pending_size - 1;

	if (rte_be_to_cpu_16(udp_hdr->dgram_len) <=
					sizeof(*udp_hdr) + sizeof(*trp_hdr)) {
		/* No DDP segment attached; ignore PSN */
		RTE_LOG(DEBUG, USER1, "got ACK psn %" PRIu32 "; now last_acked_psn %" PRIu32 " send_next_psn %" PRIu32 " send_max_psn %" PRIu32 "\n",
						ctx.psn,
						ctx.src_ep->send_last_acked_psn,
						ctx.src_ep->send_next_psn,
						ctx.src_ep->send_max_psn);
		return;
	}

	ctx.psn = rte_be_to_cpu_32(trp_hdr->psn);
	if (ctx.psn == ctx.src_ep->recv_ack_psn) {
		ctx.src_ep->recv_ack_psn++;
		if ((ctx.src_ep->trp_flags & trp_recv_missing)
				&& ctx.src_ep->recv_ack_psn
				== ctx.src_ep->recv_sack_psn.min) {
			ctx.src_ep->recv_ack_psn
				= ctx.src_ep->recv_sack_psn.max;
			ctx.src_ep->trp_flags &= ~trp_recv_missing;
		}
		ctx.src_ep->trp_flags |= trp_ack_update;
	} else if (serial_less_32(ctx.src_ep->recv_ack_psn, ctx.psn)) {
		/* We detected a sequence number gap.  Try to build a
		 * contiguous range so we can send a SACK to lower the number
		 * of retransmissions. */
		RTE_LOG(DEBUG, USER1, "receive psn %" PRIu32 "; next expected psn %" PRIu32 "\n",
				ctx.psn,
				ctx.src_ep->recv_ack_psn);
		if (ctx.src_ep->trp_flags & trp_recv_missing) {
			if (ctx.psn == ctx.src_ep->recv_sack_psn.max) {
				ctx.src_ep->recv_sack_psn.max = ctx.psn + 1;
				ctx.src_ep->trp_flags |= trp_ack_update;
			} else if (ctx.psn + 1
					== ctx.src_ep->recv_sack_psn.min) {
				ctx.src_ep->recv_sack_psn.min = ctx.psn;
				if (ctx.src_ep->recv_sack_psn.min
						== ctx.src_ep->recv_ack_psn) {
					ctx.src_ep->recv_ack_psn
						= ctx.src_ep->recv_sack_psn.max;
					ctx.src_ep->trp_flags &= ~trp_recv_missing;
				}
				ctx.src_ep->trp_flags |= trp_ack_update;
			} else if (serial_less_32(ctx.psn,
						ctx.src_ep->recv_sack_psn.min)
					|| serial_greater_32(ctx.psn,
						ctx.src_ep->recv_sack_psn.max)) {
				/* We've run out of ways to track this
				 * datagram; drop it and wait for it to be
				 * retransmitted along with the surrounding
				 * datagrams. */
				RTE_LOG(NOTICE, USER1, "got out of range psn %" PRIu32 "; next expected %" PRIu32 " sack range: [%" PRIu32 ",%" PRIu32 "]\n",
						ctx.psn, ctx.src_ep->recv_ack_psn,
						ctx.src_ep->recv_sack_psn.min,
						ctx.src_ep->recv_sack_psn.max);
				return;
			} else {
				/* This segment has been handled; drop the
				 * duplicate. */
				return;
			}
		} else {
			ctx.src_ep->trp_flags |= trp_recv_missing|trp_ack_update;
			ctx.src_ep->recv_sack_psn.min = ctx.psn;
			ctx.src_ep->recv_sack_psn.max = ctx.psn + 1;
		}
	} else {
		/* This is a retransmission of a packet which we have already
		 * acknowledged; throw it away. */
		RTE_LOG(NOTICE, USER1, "got retransmission psn %" PRIu32 "\n",
						ctx.psn);
		return;
	}

	ctx.ddp_seg_length = rte_be_to_cpu_16(udp_hdr->dgram_len)
					- sizeof(*udp_hdr) - sizeof(*trp_hdr);
	ctx.rdmap = (struct rdmap_packet *)rte_pktmbuf_adj(mbuf,
							sizeof(*trp_hdr));

	if (DDP_GET_DV(ctx.rdmap->ddp_flags) != 0x1) {
		do_rdmap_terminate(qp, &ctx,
				DDP_GET_T(ctx.rdmap->ddp_flags)
				? ddp_error_tagged_version_invalid
				: ddp_error_untagged_version_invalid);
		return;
	}

	if (RDMAP_GET_RV(ctx.rdmap->rdmap_info) != 0x1) {
		do_rdmap_terminate(qp, &ctx, rdmap_error_version_invalid);
		return;
	}

	if (DDP_GET_T(ctx.rdmap->ddp_flags)) {
		return ddp_place_tagged_data(qp, &ctx);
	} else {
		switch (RDMAP_GET_OPCODE(ctx.rdmap->rdmap_info)) {
			case rdmap_opcode_send:
			case rdmap_opcode_send_inv:
			case rdmap_opcode_send_se:
			case rdmap_opcode_send_se_inv:
				process_send(qp, &ctx);
				break;
			case rdmap_opcode_rdma_read_request:
				process_rdma_read_request(qp, &ctx);
				break;
			case rdmap_opcode_terminate:
				process_terminate(qp, &ctx);
				break;
			default:
				do_rdmap_terminate(qp, &ctx,
						rdmap_error_opcode_unexpected);
				return;
		}
	}
}	/* process_ipv4_packet */


static void
progress_send_wqe(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	if (wqe->state == SEND_WQE_COMPLETE) {
		try_complete_wqe(qp, wqe);
		return;
	}

	switch (wqe->opcode) {
	case usiw_wr_send:
		do_rdmap_send((struct usiw_qp *)qp, wqe);
		break;
	case usiw_wr_write:
		do_rdmap_write((struct usiw_qp *)qp, wqe);
		break;
	case usiw_wr_read:
		do_rdmap_read_request((struct usiw_qp *)qp, wqe);
		break;
	}
} /* progress_send_wqe */


static int
process_receive_queue(struct usiw_qp *qp, void *prefetch_addr, uint64_t *now)
{
	struct rte_mbuf *rxmbuf[RX_BURST_SIZE];
	uint16_t rx_count, pkt;

	/* Get burst of RX packets */
	if (qp->port->flags & port_fdir) {
		rx_count = rte_eth_rx_burst(qp->port->portid, qp->rx_queue,
				rxmbuf, RX_BURST_SIZE);
	} else if (qp->remote_ep.rx_queue) {
		rx_count = rte_ring_dequeue_burst(qp->remote_ep.rx_queue,
				(void **)rxmbuf, RX_BURST_SIZE);
	} else {
		rx_count = 0;
	}
	qp->stats.recv_count_histo[rx_count]++;
	if (rx_count != 0) {
		rte_prefetch0(rte_pktmbuf_mtod(rxmbuf[0], void *));
		if (now) {
			*now = rte_get_timer_cycles();
		}
		for (pkt = 0; pkt < rx_count - 1; ++pkt) {
			rte_prefetch0(rte_pktmbuf_mtod(rxmbuf[pkt + 1], void *));
			process_data_packet(qp, rxmbuf[pkt]);
			rte_pktmbuf_free(rxmbuf[pkt]);
		}
		if (prefetch_addr) {
			rte_prefetch0(prefetch_addr);
		}
		process_data_packet(qp, rxmbuf[rx_count - 1]);
		rte_pktmbuf_free(rxmbuf[rx_count - 1]);
	} else if (now) {
		*now = rte_get_timer_cycles();
	}

	return rx_count;
}

/* Make forward progress on the queue pair.  This does not guarantee that
 * everything that could be done will be done, but rather that if this function
 * is called at a regular interval, user operations will eventually complete
 * (given that the network and remote nodes are operational). */
static void
progress_qp(struct usiw_qp *qp)
{
	struct usiw_send_wqe *send_wqe, **prev;
	uint64_t now;
	int scount, ret;

	/* Receive loop fills in now for us */
	process_receive_queue(qp, qp->sq.active_head.tqh_first, &now);

	/* Call any timers only once per millisecond */
	sweep_unacked_packets(qp, now);

	scount = 0;
	TAILQ_FOR_EACH(send_wqe, &qp->sq.active_head, active, prev) {
		if (send_wqe->active.tqe_next) {
			rte_prefetch0(send_wqe->active.tqe_next);
		}
		assert(send_wqe->state != SEND_WQE_INIT);
		progress_send_wqe(qp, send_wqe);
		if (send_wqe->state == SEND_WQE_TRANSFER
				|| send_wqe->opcode == usiw_wr_write) {
			scount++;
		}
	}
	if (scount == 0) {
		ret = rte_ring_dequeue(qp->sq.ring, (void **)&send_wqe);
		if (ret == 0) {
			assert(send_wqe->state == SEND_WQE_INIT);
			send_wqe->state = SEND_WQE_TRANSFER;
			switch (send_wqe->opcode) {
				case usiw_wr_send:
					send_wqe->msn = send_wqe->remote_ep
							->next_send_msn++;
					break;
				case usiw_wr_read:
					send_wqe->msn = send_wqe->remote_ep
							->next_read_msn++;
					break;
				case usiw_wr_write:
					break;
			}
			usiw_send_wqe_queue_add_active(&qp->sq, send_wqe);
			progress_send_wqe(qp, send_wqe);
			scount = 1;
		}
	}

	scount += respond_rdma_read(qp);

	if (qp->remote_ep.trp_flags & trp_ack_update) {
		if (unlikely(qp->remote_ep.trp_flags & trp_recv_missing)) {
			send_trp_sack(qp);
		} else {
			send_trp_ack(qp);
		}
	}

	flush_tx_queue(qp);
} /* progress_qp */


/* Sets up the interface to use the given receive queue for messages to its UDP
 * port. */
static int
setup_filter_fdir(struct usiw_qp *qp)
{
	struct rte_eth_fdir_filter *fdirf;
	struct usiw_port *port;
	int retval;

	port = qp->port;
	fdirf = &qp->fdir_filter;
	memset(fdirf, 0, sizeof(*fdirf));
	fdirf->input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
	fdirf->input.flow.udp4_flow.ip.dst_ip = port->ipv4_addr;
	fdirf->action.behavior = RTE_ETH_FDIR_ACCEPT;
	fdirf->action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;
	fdirf->soft_id = qp->rx_queue;
	fdirf->action.rx_queue = qp->rx_queue;
	fdirf->input.flow.udp4_flow.dst_port = qp->udp_port;
	RTE_LOG(DEBUG, USER1, "fdir: assign rx queue %d: IP address %" PRIx32 ", UDP port %" PRIu16 "\n",
				fdirf->action.rx_queue,
				rte_be_to_cpu_32(port->ipv4_addr),
				rte_be_to_cpu_16(qp->udp_port));
	retval = rte_eth_dev_filter_ctrl(port->portid, RTE_ETH_FILTER_FDIR,
			RTE_ETH_FILTER_ADD, fdirf);
	if (retval != 0) {
		RTE_LOG(CRIT, USER1, "Could not add fdir UDP filter: %s\n",
				strerror(-retval));
	}
	return retval;
} /* setup_filter_fdir */


static int
set_peer_addr(struct usiw_qp *qp, const uint8_t *ether_addr,
		uint32_t addr, uint16_t port)
{
	struct ee_state *ee = &qp->remote_ep;

	/* FIXME: Get this from the peer */
	ee->send_max_psn = ee->tx_pending_size = qp->port->rx_desc_count / 2;
	ee->tx_pending = calloc(ee->send_max_psn, sizeof(*ee->tx_pending));
	if (!ee->tx_pending) {
		free(ee);
		return -ENOMEM;
	}
	memcpy(&ee->ah.ether_addr, ether_addr, ETHER_ADDR_LEN);
	ee->ah.ipv4_addr = addr;
	ee->ah.udp_port = port;
	ee->expected_recv_msn = 1;
	ee->expected_read_msn = 1;
	ee->expected_ack_msn = 1;
	ee->next_send_msn = 1;
	ee->next_read_msn = 1;
	ee->next_ack_msn = 1;

	ee->tx_head = ee->tx_pending;

	return 0;
} /* set_peer_addr */


void
usiw_do_destroy_qp(struct usiw_qp *qp)
{
	sem_destroy(&qp->conn_event_sem);
	usiw_recv_wqe_queue_destroy(&qp->rq0);
	usiw_send_wqe_queue_destroy(&qp->sq);
	free(qp->readresp_store);

	rte_ring_enqueue(qp->port->avail_qp, qp);
} /* usiw_do_destroy_qp */


static struct usiw_qp *
lookup_qp_id(struct usiw_context *ctx, uint32_t qp_id)
{
	struct usiw_qp *qp;

	rte_spinlock_lock(&ctx->qp_lock);
	if (ctx->qp) {
		fprintf(stderr, "%p\n", &ctx->qp->hh);
	}
	HASH_FIND(hh, ctx->qp, &qp_id, sizeof(qp_id), qp);
	rte_spinlock_unlock(&ctx->qp_lock);
	if (qp) {
		rte_atomic32_inc(&qp->refcnt);
		return qp;
	}
	return NULL;
} /* lookup_qp_id */


static void
poll_conn_state(struct usiw_context *ctx, int timeout)
{
	struct urdma_qp_connected_event event;
	struct urdma_qp_rtr_event rtr_event;
	struct usiw_qp *qp;
	struct pollfd pollfd;
	unsigned int x;
	ssize_t ret;

	if (timeout) {
		pollfd.fd = ctx->event_fd;
		pollfd.events = POLLIN;
		ret = poll(&pollfd, 1, timeout);
		if (ret == 0) {
			return;
		} else if (ret < 0) {
			static bool warned = false;
			if (!warned) {
				RTE_LOG(ERR, USER1, "Error polling event file for reading: %s\n",
						strerror(errno));
				warned = true;
			}
			rte_atomic16_set(&qp->conn_state, usiw_qp_error);
			return;
		}
	}

	ret = read(ctx->event_fd, &event, sizeof(event));
	if (ret < 0 && errno == EAGAIN) {
		return;
	}
	if (ret < 0 || (size_t)ret < sizeof(event)) {
		static bool warned = false;
		if (!warned) {
			if (ret < 0) {
				RTE_LOG(ERR, USER1, "Error reading event file: %s\n",
						strerror(errno));
			} else {
				RTE_LOG(ERR, USER1, "Read only %zd/%zu bytes\n",
						ret, sizeof(event));
			}
			warned = true;
		}
		return;
	}

	qp = lookup_qp_id(ctx, event.qp_id);
	if (!qp) {
		RTE_LOG(ERR, USER1, "Got connection event for unknown queue pair %" PRIu32 "\n",
				event.qp_id);
		return;
	}
	rte_spinlock_lock(&qp->conn_event_lock);
	assert(event.src_port != 0);
	assert(rte_atomic16_read(&qp->conn_state) != usiw_qp_connected);

	qp->ord_max = event.ord_max;
	qp->ird_max = event.ird_max;
	qp->readresp_store = calloc(qp->ird_max,
			sizeof(*qp->readresp_store));
	if (!qp->readresp_store) {
		RTE_LOG(DEBUG, USER1, "Set up readresp_store failed: %s\n",
						strerror(errno));
		rte_atomic16_set(&qp->conn_state, usiw_qp_error);
		rte_spinlock_unlock(&qp->conn_event_lock);
		return;
	}
	for (x = 0; x < qp->ird_max; ++x) {
		TAILQ_INSERT_TAIL(&qp->readresp_empty,
				&qp->readresp_store[x],
				qp_entry);
	}

	set_peer_addr(qp, event.dst_ether, event.dst_ipv4,
			event.dst_port);

	qp->udp_port = event.src_port;
	if (ctx->port->flags & port_fdir) {
		ret = setup_filter_fdir(qp);
		if (ret < 0) {
			RTE_LOG(DEBUG, USER1, "Set up flow director filter failed: %s\n",
						rte_strerror(ret));
			rte_atomic16_set(&qp->conn_state, usiw_qp_error);
			rte_spinlock_unlock(&qp->conn_event_lock);
			return;
		}
	} else {
		char name[RTE_RING_NAMESIZE];
		snprintf(name, RTE_RING_NAMESIZE, "qp%u_rxring",
				qp->ib_qp.qp_num);
		qp->remote_ep.rx_queue = rte_ring_create(name,
				qp->port->rx_desc_count, rte_socket_id(),
				RING_F_SP_ENQ|RING_F_SC_DEQ);
		if (!qp->remote_ep.rx_queue) {
			RTE_LOG(DEBUG, USER1, "Set up rx ring failed: %s\n",
						rte_strerror(ret));
			rte_atomic16_set(&qp->conn_state, usiw_qp_error);
			rte_spinlock_unlock(&qp->conn_event_lock);
			return;
		}
	}

	/* Start the queues now that we have bound to an interface */
	ret = rte_eth_dev_rx_queue_start(qp->port->portid,
			qp->rx_queue);
	if (ret < 0) {
		RTE_LOG(DEBUG, USER1, "Enable RX queue %u failed: %s\n",
				qp->rx_queue, rte_strerror(ret));
		rte_atomic16_set(&qp->conn_state, usiw_qp_error);
		rte_spinlock_unlock(&qp->conn_event_lock);
		return;
	}

	ret = rte_eth_dev_tx_queue_start(qp->port->portid,
			qp->tx_queue);
	if (ret < 0) {
		RTE_LOG(DEBUG, USER1, "Enable RX queue %u failed: %s\n",
				qp->tx_queue, rte_strerror(ret));
		rte_atomic16_set(&qp->conn_state, usiw_qp_error);
		rte_spinlock_unlock(&qp->conn_event_lock);
		return;
	}

	rtr_event.event_type = SIW_EVENT_QP_RTR;
	rtr_event.qp_id = qp->ib_qp.qp_num;
	ret = write(ctx->event_fd, &rtr_event, sizeof(rtr_event));
	if (ret < 0 || (size_t)ret < sizeof(rtr_event)) {
		static bool warned = false;
		if (!warned) {
			if (ret < 0) {
				RTE_LOG(ERR, USER1, "Error writing event file: %s\n",
						strerror(errno));
			} else {
				RTE_LOG(ERR, USER1, "Wrote only %zd/%zu bytes\n",
						ret, sizeof(rtr_event));
			}
			warned = true;
		}
		rte_atomic16_set(&qp->conn_state, usiw_qp_error);
		rte_spinlock_unlock(&qp->conn_event_lock);
		return;
	}

	rte_atomic16_set(&qp->conn_state, usiw_qp_connected);
	rte_atomic32_dec(&ctx->qp_init_count);
	rte_spinlock_unlock(&qp->conn_event_lock);
	LIST_INSERT_HEAD(&ctx->qp_active, qp, ctx_entry);

	sem_post(&qp->conn_event_sem);
} /* poll_conn_state */


static struct usiw_qp *
find_matching_qp(struct usiw_context *ctx, struct rte_mbuf *pkt)
{
	struct usiw_qp *qp, **prev;
	struct ether_hdr *ether;
	struct ipv4_hdr *ipv4;
	struct udp_hdr *udp;
	struct urdma_ah *ah;

	ether = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	if (ether->ether_type != ETHER_TYPE_IPv4) {
		return NULL;
	}
	ipv4 = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(*ether));
	if (ipv4->next_proto_id != IP_HDR_PROTO_UDP) {
		return NULL;
	}
	udp = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *,
			sizeof(*ether) + sizeof(*ipv4));

	LIST_FOR_EACH(qp, &ctx->qp_active, ctx_entry, prev) {
		ah = &qp->remote_ep.ah;
		if (ah->ipv4_addr == ipv4->dst_addr
				&& ah->udp_port == udp->dst_port) {
			return qp;
		}
	}

	return NULL;
} /* find_matching_qp */


static void
kni_process_burst(struct usiw_port *port,
		struct rte_mbuf **rxmbuf, int count)
{
	struct usiw_qp *qp;
	int i, j;

	if (port->ctx && !(port->flags & port_fdir)) {
		for (i = j = 0; i < count; i++) {
			while (i + j < count
					&& (qp = find_matching_qp(port->ctx,
							rxmbuf[i + j]))) {
				rte_ring_enqueue(qp->remote_ep.rx_queue,
						rxmbuf[i + j]);
				j++;
			}
			if (i + j < count) {
				rxmbuf[i] = rxmbuf[i + j];
			}
		}

		count -= j;
	}
	rte_kni_tx_burst(port->kni, rxmbuf, count);
} /* kni_process_burst */


int
kni_loop(void *arg)
{
	struct usiw_driver *driver = arg;
	struct usiw_port *port;
	struct usiw_qp *qp, **prev;
	struct rte_mbuf *rxmbuf[RX_BURST_SIZE];
	unsigned int count;
	int portid, ret;

	while (1) {
		for (portid = 0; portid < driver->port_count; ++portid) {
			port = &driver->ports[portid];
			ret = rte_kni_handle_request(port->kni);
			if (ret) {
				break;
			}

			count = rte_kni_rx_burst(port->kni,
					rxmbuf, RX_BURST_SIZE);
			if (count) {
				rte_eth_tx_burst(port->portid, 0,
					rxmbuf, count);
			}

			count = rte_eth_rx_burst(port->portid, 0,
						rxmbuf, RX_BURST_SIZE);
			if (count) {
				kni_process_burst(port, rxmbuf, count);
			}

			if (!port->ctx) {
				continue;
			}

			if (rte_atomic32_read(&port->ctx->qp_init_count) > 0) {
				poll_conn_state(port->ctx, 0);
			}

			LIST_FOR_EACH(qp, &port->ctx->qp_active, ctx_entry, prev) {
				switch (rte_atomic16_read(&qp->conn_state)) {
				case usiw_qp_connected:
					progress_qp(qp);
					break;
				case usiw_qp_shutdown:
					qp_shutdown(qp);
					/* qp_shutdown() transitions to
					 * usiw_qp_error */
				case usiw_qp_error:
					LIST_REMOVE(qp, ctx_entry);
					if (rte_atomic32_sub_return(&qp->refcnt,
								1) == 0) {
						usiw_do_destroy_qp(qp);
					}
					break;
				default:
					break;
				}
			}
		}
	}

	return EXIT_FAILURE;
} /* kni_loop */
