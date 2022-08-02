/* interface.c */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
 *
 * Copyright (c) 2016, IBM Corporation
 * Copyright (c) 2016-2018, University of New Hampshire
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

#include <ccan/list/list.h>

#include <rte_config.h>
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
	size_t wqe_size;
	char name[RTE_RING_NAMESIZE];
	int i, ret;

	snprintf(name, RTE_RING_NAMESIZE, "qpn%" PRIu32 "_send", qpn);
	q->ring = rte_malloc(NULL, rte_ring_get_memsize(max_send_wr + 1),
			RTE_CACHE_LINE_SIZE);
	if (!q->ring)
		return -rte_errno;
	ret = rte_ring_init(q->ring, name, max_send_wr + 1,
			RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ret)
		return ret;

	snprintf(name, RTE_RING_NAMESIZE, "qpn%" PRIu32 "_send_free", qpn);
	q->free_ring = rte_malloc(NULL, rte_ring_get_memsize(max_send_wr + 1),
				  RTE_CACHE_LINE_SIZE);
	if (!q->free_ring)
		return -rte_errno;
	ret = rte_ring_init(q->free_ring, name, max_send_wr + 1,
			RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ret)
		return ret;

	wqe_size = sizeof(struct usiw_send_wqe)
					+ max_send_sge * sizeof(struct iovec);
	q->storage = calloc(max_send_wr, wqe_size);
	if (!q->storage)
		return -errno;

	for (i = 0; i < max_send_wr; i++) {
		rte_ring_enqueue(q->free_ring, q->storage + i * wqe_size);
	}

	list_head_init(&q->active_head);
	rte_spinlock_init(&q->lock);
	q->max_wr = max_send_wr;
	q->max_sge = max_send_sge;
	return 0;
} /* usiw_send_wqe_queue_init */

void
usiw_send_wqe_queue_destroy(struct usiw_send_wqe_queue *q)
{
	rte_free(q->ring);
	rte_free(q->free_ring);
	free(q->storage);
} /* usiw_send_wqe_queue_destroy */

static void
usiw_send_wqe_queue_add_active(struct usiw_send_wqe_queue *q,
		struct usiw_send_wqe *wqe)
{
	list_add_tail(&q->active_head, &wqe->active);
} /* usiw_send_wqe_queue_add_active */

static void
usiw_send_wqe_queue_del_active(struct usiw_send_wqe_queue *q,
		struct usiw_send_wqe *wqe)
{
	list_del(&wqe->active);
} /* usiw_send_wqe_queue_del_active */

static int
usiw_send_wqe_queue_lookup(struct usiw_send_wqe_queue *q,
		uint16_t wr_opcode, uint32_t wr_key_data,
		struct usiw_send_wqe **wqe)
{
	struct usiw_send_wqe *lptr, *next;
	RTE_LOG(DEBUG, USER1, "LOOKUP active send WQE opcode=%" PRIu8 " key_data=%" PRIu32 "\n",
			wr_opcode, wr_key_data);
	list_for_each_safe(&q->active_head, lptr, next, active) {
		if (lptr->opcode != wr_opcode) {
			continue;
		}
		switch (lptr->opcode) {
		case usiw_wr_send:
		case usiw_wr_atomic:
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
			if (wr_key_data == lptr->local_stag) {
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
	size_t wqe_size;
	char name[RTE_RING_NAMESIZE];
	int i, ret;

	snprintf(name, RTE_RING_NAMESIZE, "qpn%" PRIu32 "_recv", qpn);
	q->ring = rte_malloc(NULL, rte_ring_get_memsize(max_recv_wr + 1),
			RTE_CACHE_LINE_SIZE);
	if (!q->ring)
		return -rte_errno;
	ret = rte_ring_init(q->ring, name, max_recv_wr + 1,
			RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ret)
		return ret;

	snprintf(name, RTE_RING_NAMESIZE, "qpn%" PRIu32 "_recv_free", qpn);
	q->free_ring = rte_malloc(NULL, rte_ring_get_memsize(max_recv_wr + 1),
				  RTE_CACHE_LINE_SIZE);
	if (!q->free_ring)
		return -rte_errno;
	ret = rte_ring_init(q->free_ring, name, max_recv_wr + 1,
			RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ret)
		return ret;

	wqe_size = sizeof(struct usiw_recv_wqe)
					+ max_recv_sge * sizeof(struct iovec);
	q->storage = calloc(max_recv_wr + 1, wqe_size);
	if (!q->storage)
		return -errno;

	for (i = 0; i < max_recv_wr; ++i) {
		rte_ring_enqueue(q->free_ring, q->storage + i * wqe_size);
	}

	list_head_init(&q->active_head);
	rte_spinlock_init(&q->lock);
	q->max_wr = max_recv_wr;
	q->max_sge = max_recv_sge;
	q->next_msn = 1;
	return 0;
} /* usiw_recv_wqe_queue_init */

void
usiw_recv_wqe_queue_destroy(struct usiw_recv_wqe_queue *q)
{
	rte_free(q->ring);
	rte_free(q->free_ring);
	free(q->storage);
} /* usiw_recv_wqe_queue_destroy */

static void
usiw_recv_wqe_queue_add_active(struct usiw_recv_wqe_queue *q,
		struct usiw_recv_wqe *wqe)
{
	RTE_LOG(DEBUG, USER1, "ADD active recv WQE msn=%" PRIu32 "\n",
			wqe->msn);
	list_add_tail(&q->active_head, &wqe->active);
} /* usiw_recv_wqe_queue_add_active */

static void
usiw_recv_wqe_queue_del_active(struct usiw_recv_wqe_queue *q,
		struct usiw_recv_wqe *wqe)
{
	RTE_LOG(DEBUG, USER1, "DEL active recv WQE msn=%" PRIu32 "\n",
			wqe->msn);
	list_del(&wqe->active);
} /* usiw_recv_wqe_queue_del_active */

static int
usiw_recv_wqe_queue_lookup(struct usiw_recv_wqe_queue *q,
		uint32_t msn, struct usiw_recv_wqe **wqe)
{
	struct usiw_recv_wqe *lptr, *next;
	RTE_LOG(DEBUG, USER1, "LOOKUP active recv WQE msn=%" PRIu32 "\n",
			msn);
	list_for_each_safe(&q->active_head, lptr, next, active) {
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
		// if(qp->txq_end == begin) {
		// 	return;
		// }
		ret = rte_eth_tx_burst(qp->dev->portid, qp->shm_qp->tx_queue,
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
	rte_eth_macaddr_get(qp->dev->portid, &eth->s_addr);
	eth->ether_type = rte_cpu_to_be_16(ether_type);
	sendmsg->l2_len = sizeof(*eth);
#ifdef DEBUG_PACKET_HEADERS
	RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Enqueue packet to transmit queue:\n",
		qp->shm_qp->dev_id, qp->shm_qp->qp_id);
	rte_pktmbuf_dump(stderr, sendmsg, 128);
#endif

	*(qp->txq_end++) = sendmsg;
	if (qp->txq_end == qp->txq + qp->shm_qp->tx_burst_size) {
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
		uint32_t raw_cksum)
{
	struct udp_hdr *udp;
	struct ipv4_hdr *ip;

	if (qp->dev->flags & port_checksum_offload) {
		sendmsg->ol_flags
			|= PKT_TX_UDP_CKSUM|PKT_TX_IPV4|PKT_TX_IP_CKSUM;
	}

	udp = prepend_udp_header(sendmsg, qp->shm_qp->local_udp_port,
			qp->shm_qp->remote_udp_port);
	ip = prepend_ipv4_header(sendmsg, IP_HDR_PROTO_UDP,
			qp->dev->ipv4_addr,
			qp->shm_qp->remote_ipv4_addr);

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

	enqueue_ether_frame(sendmsg, ETHER_TYPE_IPv4, qp,
			&qp->shm_qp->remote_ether_addr);
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

	hdr = rte_pktmbuf_alloc(qp->dev->tx_hdr_mempool);
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
	if (!qp->dev->flags & port_checksum_offload) {
		payload_raw_cksum = info->ddp_raw_cksum
			+ rte_raw_cksum(trp, sizeof(*trp));
	}
	send_udp_dgram(qp, hdr, payload_raw_cksum);

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
		struct read_atomic_response_state *readresp,
		struct usiw_send_wqe *wqe, size_t payload_length)
{
	struct pending_datagram_info *pending;
	uint32_t psn = qp->remote_ep.send_next_psn++;

	pending = (struct pending_datagram_info *)(sendmsg + 1);
	pending->wqe = wqe;
	pending->readresp = readresp;
	pending->transmit_count = 0;
	pending->ddp_length = payload_length;
	if (!qp->dev->flags & port_checksum_offload) {
		pending->ddp_raw_cksum = rte_raw_cksum(
				rte_pktmbuf_mtod(sendmsg, void *),
				rte_pktmbuf_data_len(sendmsg));
	}
	pending->psn = psn;

	assert(*tx_pending_entry(&qp->remote_ep, psn) == NULL);
	*tx_pending_entry(&qp->remote_ep, psn) = sendmsg;

	resend_ddp_segment(qp, sendmsg, &qp->remote_ep);
	return psn;
} /* send_ddp_segment */


static void
send_trp_sack(struct usiw_qp *qp)
{
	struct rte_mbuf *sendmsg;
	struct ee_state *ep = &qp->remote_ep;
	struct trp_hdr *trp;

	assert(ep->trp_flags & trp_recv_missing);
	sendmsg = rte_pktmbuf_alloc(qp->dev->tx_hdr_mempool);
	trp = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
	trp->psn = rte_cpu_to_be_32(ep->recv_sack_psn.min);
	trp->ack_psn = rte_cpu_to_be_32(ep->recv_sack_psn.max);
	trp->opcode = rte_cpu_to_be_16(trp_sack);

	ep->trp_flags &= ~trp_ack_update;

	send_udp_dgram(qp, sendmsg,
			(qp->dev->flags & port_checksum_offload)
					? 0 : rte_raw_cksum(trp, sizeof(*trp)));
} /* send_trp_sack */


static void
send_trp_fin(struct usiw_qp *qp)
{
	struct ee_state *ep = &qp->remote_ep;
	struct rte_mbuf *sendmsg;
	struct trp_hdr *trp;

	sendmsg = rte_pktmbuf_alloc(qp->dev->tx_hdr_mempool);
	trp = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
	trp->psn = rte_cpu_to_be_32(ep->send_next_psn);
	trp->ack_psn = rte_cpu_to_be_32(ep->recv_ack_psn);
	trp->opcode = rte_cpu_to_be_16(trp_fin);

	if (!(ep->trp_flags & trp_recv_missing)) {
		ep->trp_flags &= ~trp_ack_update;
	}

	send_udp_dgram(qp, sendmsg,
			(qp->dev->flags & port_checksum_offload)
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
	sendmsg = rte_pktmbuf_alloc(qp->dev->tx_hdr_mempool);
	trp = (struct trp_hdr *)rte_pktmbuf_append(sendmsg, sizeof(*trp));
	trp->psn = rte_cpu_to_be_32(ep->send_next_psn);
	trp->ack_psn = rte_cpu_to_be_32(ep->recv_ack_psn);
	trp->opcode = rte_cpu_to_be_16(0);
	ep->trp_flags &= ~trp_ack_update;

	send_udp_dgram(qp, sendmsg,
			(qp->dev->flags & port_checksum_offload)
					? 0 : rte_raw_cksum(trp, sizeof(*trp)));
} /* send_trp_ack */


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
	rte_ring_enqueue(qp->sq.free_ring, wqe);
} /* qp_free_send_wqe */

/** Returns the given receive WQE back to the free pool.  It is removed from
 * the active set if still_in_hash is true.  The rq lock MUST be locked when
 * calling this function. */
static void
qp_free_recv_wqe(struct usiw_qp *qp, struct usiw_recv_wqe *wqe)
{
	usiw_recv_wqe_queue_del_active(&qp->rq0, wqe);
	rte_ring_enqueue(qp->rq0.free_ring, wqe);
} /* qp_free_recv_wqe */


int
qp_get_next_send_wqe(struct usiw_qp *qp, struct usiw_send_wqe **wqe)
{
	int ret;

	rte_spinlock_lock(&qp->sq.lock);
	ret = rte_ring_dequeue(qp->sq.free_ring, (void **)wqe);
	rte_spinlock_unlock(&qp->sq.lock);
	if (ret == -ENOENT)
		ret = -ENOSPC;
	return ret;
} /* qp_get_next_send_wqe */

int
qp_get_next_recv_wqe(struct usiw_qp *qp, struct usiw_recv_wqe **wqe)
{
	int ret;

	rte_spinlock_lock(&qp->rq0.lock);
	ret = rte_ring_dequeue(qp->rq0.free_ring, (void **)wqe);
	rte_spinlock_unlock(&qp->rq0.lock);
	if (ret == -ENOENT)
		ret = -ENOSPC;
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

	ret = rte_ring_enqueue(cq->cqe_ring, cqe);
	assert(ret == 0);
	ctx = usiw_get_context(cq->ib_cq.context);
	assert(ctx != NULL);

	if (ctx && atomic_exchange(&cq->notify_flag, false)) {
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
	cqe->imm_data = wqe->imm_data;
	cqe->wc_flags = IBV_WC_WITH_IMM;

	qp_free_recv_wqe(qp, wqe);
	finish_post_cqe(cq, cqe);
	return 0;
} /* post_recv_cqe */


static enum ibv_wc_opcode
get_ibv_send_wc_opcode(struct usiw_send_wqe *wqe)
{
	switch (wqe->opcode) {
	case usiw_wr_send:
	case usiw_wr_send_with_imm:
		return IBV_WC_SEND;
	case usiw_wr_write:
	case usiw_wr_write_with_imm:
		return IBV_WC_RDMA_WRITE;
	case usiw_wr_read:
		return IBV_WC_RDMA_READ;
	case usiw_wr_atomic:
		switch (wqe->atomic_opcode) {
		case rdmap_atomic_fetchadd:
			return IBV_WC_FETCH_ADD;
			break;
		case rdmap_atomic_cmpswap:
			return IBV_WC_COMP_SWAP;
			break;
		}
		break;
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
	cqe->opcode = get_ibv_send_wc_opcode(wqe);
	cqe->qp_num = qp->ib_qp.qp_num;

	qp_free_send_wqe(qp, wqe, true);
	finish_post_cqe(cq, cqe);
	return 0;
} /* post_send_cqe */


static void
rq_flush(struct usiw_qp *qp)
{
	struct usiw_recv_wqe *wqe, *next;

	rte_spinlock_lock(&qp->rq0.lock);
	while (rte_ring_dequeue(qp->rq0.ring, (void **)&wqe) == 0) {
		wqe->msn = qp->rq0.next_msn++;
		usiw_recv_wqe_queue_add_active(&qp->rq0, wqe);
	}
	list_for_each_safe(&qp->rq0.active_head, wqe, next, active) {
		post_recv_cqe(qp, wqe, IBV_WC_WR_FLUSH_ERR);
	}
	rte_spinlock_unlock(&qp->rq0.lock);
} /* rq_flush */


static void
sq_flush(struct usiw_qp *qp)
{
	struct usiw_send_wqe *wqe, *next;

	rte_spinlock_lock(&qp->sq.lock);
	while (rte_ring_dequeue(qp->sq.ring, (void **)&wqe) == 0) {
		usiw_send_wqe_queue_add_active(&qp->sq, wqe);
	}
	list_for_each_safe(&qp->sq.active_head, wqe, next, active) {
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
			rte_memcpy(dest + pos, src_iov_base + offset - prev,
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
	uint16_t mtu = qp->shm_qp->mtu;

	if (wqe->state != SEND_WQE_TRANSFER) {
		return;
	}

	while ((wqe->bytes_sent < wqe->total_length || 
		(wqe->bytes_sent == 0 && wqe->total_length == 0))
			&& serial_less_32(wqe->remote_ep->send_next_psn,
					wqe->remote_ep->send_max_psn)) {
		sendmsg = rte_pktmbuf_alloc(qp->dev->tx_ddp_mempool);

		payload_length = RTE_MIN(mtu, wqe->total_length
				- wqe->bytes_sent);
		packet_length = RDMAP_UNTAGGED_ALLOC_SIZE(payload_length);
		new_rdmap = (struct rdmap_untagged_packet *)rte_pktmbuf_append(
					sendmsg, packet_length);
		new_rdmap->head.ddp_flags = (wqe->total_length
				- wqe->bytes_sent <= mtu)
			? DDP_V1_UNTAGGED_LAST_DF
			: DDP_V1_UNTAGGED_DF;
		if (wqe->opcode == usiw_wr_send_with_imm) {
			new_rdmap->head.rdmap_info = rdmap_opcode_send_with_imm | RDMAP_V1;
			new_rdmap->head.immediate = wqe->imm_data;
		} else {
			new_rdmap->head.rdmap_info = rdmap_opcode_send | RDMAP_V1;
			new_rdmap->head.immediate = 0;
		}
		new_rdmap->head.sink_stag = rte_cpu_to_be_32(0);
		new_rdmap->qn = rte_cpu_to_be_32(0);
		new_rdmap->msn = rte_cpu_to_be_32(wqe->msn);
		new_rdmap->mo = rte_cpu_to_be_32(wqe->bytes_sent);
		if (payload_length > 0) {
        		if (wqe->flags & usiw_send_inline) {
        			memcpy(PAYLOAD_OF(new_rdmap),
        					(char *)wqe->iov + wqe->bytes_sent,
        					payload_length);
        		} else {
        			memcpy_from_iov(PAYLOAD_OF(new_rdmap), payload_length,
        					wqe->iov, wqe->iov_count,
        					wqe->bytes_sent);
        		}
		}

		send_ddp_segment(qp, sendmsg, NULL, wqe, payload_length);
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> SEND transmit msn=%" PRIu32 " [%zu-%zu]\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				wqe->msn,
				wqe->bytes_sent,
				wqe->bytes_sent + payload_length);

		wqe->bytes_sent += payload_length;

		if(wqe->total_length == 0) {
			break;
		}
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
	size_t payload_length;
	uint16_t mtu = qp->shm_qp->mtu;
	void *payload;

	while (wqe->bytes_sent < wqe->total_length
			&& serial_less_32(wqe->remote_ep->send_next_psn,
					wqe->remote_ep->send_max_psn)) {
		sendmsg = rte_pktmbuf_alloc(qp->dev->tx_ddp_mempool);

		payload_length = RTE_MIN(mtu, wqe->total_length
				- wqe->bytes_sent);
		new_rdmap = (struct rdmap_tagged_packet *)rte_pktmbuf_prepend(
					sendmsg, sizeof(*new_rdmap));
		new_rdmap->head.ddp_flags = (wqe->total_length
				- wqe->bytes_sent <= mtu)
			? DDP_V1_TAGGED_LAST_DF
			: DDP_V1_TAGGED_DF;
		if (wqe->opcode == usiw_wr_write_with_imm) {
			new_rdmap->head.rdmap_info = rdmap_opcode_rdma_write_with_imm | RDMAP_V1;
			new_rdmap->head.immediate = wqe->imm_data;
		} else {
			new_rdmap->head.rdmap_info = rdmap_opcode_rdma_write | RDMAP_V1;
			new_rdmap->head.immediate = 0;
		}
		new_rdmap->head.sink_stag = rte_cpu_to_be_32(wqe->rkey);
		new_rdmap->offset = rte_cpu_to_be_64(wqe->remote_addr
				 + wqe->bytes_sent);
		payload = rte_pktmbuf_append(sendmsg, payload_length);
		if (wqe->flags & usiw_send_inline) {
			memcpy(payload, (char *)wqe->iov + wqe->bytes_sent,
					payload_length);
		} else {
			memcpy_from_iov(payload, payload_length,
					wqe->iov, wqe->iov_count,
					wqe->bytes_sent);
		}

		send_ddp_segment(qp, sendmsg, NULL, wqe, payload_length);
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> RDMA WRITE transmit bytes %zu through %zu\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				wqe->bytes_sent,
				wqe->bytes_sent + payload_length);

		wqe->bytes_sent += payload_length;
	}

	if (wqe->bytes_sent == wqe->total_length) {
		wqe->state = SEND_WQE_WAIT;
	}
} /* do_rdmap_write */


static void
do_rdmap_atomic(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	struct rdmap_atomicreq_packet *new_rdmap;
	struct rte_mbuf *sendmsg;
	unsigned int packet_length;

	if (wqe->state != SEND_WQE_TRANSFER) {
		return;
	}

	if (qp->ord_active >= qp->shm_qp->ord_max) {
		/* Cannot issue more than ord_max simultaneous RDMA READ
		 * and Atomic Requests. */
		return;
	} else if (wqe->remote_ep->send_next_psn
			== wqe->remote_ep->send_max_psn
			|| serial_greater_32(wqe->remote_ep->send_next_psn,
				wqe->remote_ep->send_max_psn)) {
		/* We have reached the maximum number of credits we are allowed
		 * to send. */
		return;
	}
	qp->ord_active++;

	sendmsg = rte_pktmbuf_alloc(qp->dev->tx_ddp_mempool);

	packet_length = sizeof(*new_rdmap);
	new_rdmap = (struct rdmap_atomicreq_packet *)rte_pktmbuf_append(
				sendmsg, packet_length);
	new_rdmap->untagged.head.ddp_flags = DDP_V1_UNTAGGED_LAST_DF;
	new_rdmap->untagged.head.rdmap_info
		= rdmap_opcode_atomic_request | RDMAP_V1;
	new_rdmap->untagged.head.sink_stag = rte_cpu_to_be_32(wqe->local_stag);
	new_rdmap->untagged.qn = rte_cpu_to_be_32(ddp_queue_read_request);
	new_rdmap->untagged.msn = rte_cpu_to_be_32(wqe->msn);
	new_rdmap->untagged.mo = rte_cpu_to_be_32(0);
	new_rdmap->opcode = rte_cpu_to_be_32(wqe->atomic_opcode);
	new_rdmap->req_id = rte_cpu_to_be_32(wqe->msn);
	new_rdmap->remote_stag = rte_cpu_to_be_32(wqe->rkey);
	new_rdmap->remote_offset =
		rte_cpu_to_be_64((uintptr_t)wqe->remote_addr);
	new_rdmap->add_swap_data = rte_cpu_to_be_64(wqe->atomic_add_swap);
	new_rdmap->add_swap_mask = rte_cpu_to_be_64(0);
	new_rdmap->compare_data = rte_cpu_to_be_64(wqe->atomic_compare);
	new_rdmap->compare_mask = rte_cpu_to_be_64(0);

	send_ddp_segment(qp, sendmsg, NULL, wqe, 0);
	RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> ATOMIC transmit msn=%" PRIu32 "\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id, wqe->msn);

	wqe->state = SEND_WQE_WAIT;
} /* do_rdmap_atomic */

static void
do_rdmap_read_request(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	struct rdmap_readreq_packet *new_rdmap;
	struct rte_mbuf *sendmsg;
	unsigned int packet_length;

	if (wqe->state != SEND_WQE_TRANSFER) {
		return;
	}

	if (qp->ord_active >= qp->shm_qp->ord_max) {
		/* Cannot issue more than ord_max simultaneous RDMA READ
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
	qp->ord_active++;

	sendmsg = rte_pktmbuf_alloc(qp->dev->tx_ddp_mempool);

	packet_length = sizeof(*new_rdmap);
	new_rdmap = (struct rdmap_readreq_packet *)rte_pktmbuf_append(
				sendmsg, packet_length);
	new_rdmap->untagged.head.ddp_flags = DDP_V1_UNTAGGED_LAST_DF;
	new_rdmap->untagged.head.rdmap_info
		= rdmap_opcode_rdma_read_request | RDMAP_V1;
	new_rdmap->untagged.head.sink_stag = rte_cpu_to_be_32(wqe->local_stag);
	new_rdmap->untagged.qn = rte_cpu_to_be_32(1);
	new_rdmap->untagged.msn = rte_cpu_to_be_32(wqe->msn);
	new_rdmap->untagged.mo = rte_cpu_to_be_32(0);
	new_rdmap->sink_offset
		= rte_cpu_to_be_64((uintptr_t)wqe->iov[0].iov_base);
	new_rdmap->read_msg_size = rte_cpu_to_be_32(wqe->iov[0].iov_len);
	new_rdmap->source_stag = rte_cpu_to_be_32(wqe->rkey);
	new_rdmap->source_offset = rte_cpu_to_be_64(wqe->remote_addr);

	send_ddp_segment(qp, sendmsg, NULL, wqe, 0);
	RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> RDMA READ transmit msn=%" PRIu32 "\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id, wqe->msn);

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
	struct rte_mbuf *sendmsg = rte_pktmbuf_alloc(qp->dev->tx_ddp_mempool);
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
	(void)send_ddp_segment(qp, sendmsg, NULL, NULL, 0);
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
			rte_memcpy(dest_iov_base + offset - prev, src + pos,
					cur);
			pos += cur;
			offset += cur;
		}
		prev += dest[y].iov_len;
	}
} /* memcpy_to_iov */


/** Pull all recv WQEs off of the ring for the given qp. */
static void
dequeue_recv_wqes(struct usiw_qp *qp)
{
	struct usiw_recv_wqe *wqe[qp->rq0.max_wr + 1];
	unsigned int i, ret;

	while ((ret = RING_DEQUEUE_BURST(qp->rq0.ring, (void **)wqe,
						qp->rq0.max_wr + 1)) > 0) {
		for (i = 0; i < ret; i++) {
			wqe[i]->remote_ep = &qp->remote_ep;
			wqe[i]->msn = qp->rq0.next_msn++;
			usiw_recv_wqe_queue_add_active(&qp->rq0, wqe[i]);
		}
	}
} /* dequeue_recv_wqes */


static void
process_send(struct usiw_qp *qp, struct packet_context *orig)
{
	struct usiw_recv_wqe *wqe;
	struct rdmap_untagged_packet *rdmap
		= (struct rdmap_untagged_packet *)orig->rdmap;
	uint32_t msn, expected_msn;
	size_t offset;
	size_t payload_length;
	int ret;

	if (!list_top(&qp->rq0.active_head, struct usiw_recv_wqe, active))
		dequeue_recv_wqes(qp);

	msn = rte_be_to_cpu_32(rdmap->msn);
	ret = usiw_recv_wqe_queue_lookup(&qp->rq0, msn, &wqe);
	assert(ret != -EINVAL);
	if (ret < 0) {
		if (list_top(&qp->rq0.active_head, struct usiw_recv_wqe, active)) {
			/* This is a duplicate of a previously received
			 * message --- should never happen since TRP will not
			 * give us a duplicate packet. */
			expected_msn = list_top(&qp->rq0.active_head, struct usiw_recv_wqe, active)->msn;
			RTE_LOG(INFO, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Received msn=%" PRIu32 " but expected msn=%" PRIu32 "\n",
					qp->shm_qp->dev_id, qp->shm_qp->qp_id,
					msn, expected_msn);
			do_rdmap_terminate(qp, orig,
					ddp_error_untagged_invalid_msn);
		} else {
			RTE_LOG(INFO, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Received SEND msn=%" PRIu32 " to empty receive queue\n",
					qp->dev->portid,
					qp->shm_qp->rx_queue, msn);
			assert(rte_ring_empty(qp->rq0.ring));
			do_rdmap_terminate(qp, orig,
					ddp_error_untagged_no_buffer);
		}
		return;
	} else {
	}

	offset = rte_be_to_cpu_32(rdmap->mo);
	payload_length = orig->ddp_seg_length - sizeof(struct rdmap_untagged_packet);
	if (offset + payload_length > wqe->total_request_size) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> DROP: offset=%zu + payload_length=%zu > wr_len=%zu\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				offset, payload_length, wqe->total_request_size);
		do_rdmap_terminate(qp, orig,
				ddp_error_untagged_message_too_long);
		return;
	}

	if (DDP_GET_L(rdmap->head.ddp_flags)) {
		if (wqe->input_size != 0) {
			RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> silently DROP duplicate last packet.\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id);
			return;
		}
		wqe->input_size = offset + payload_length;
	}

	memcpy_to_iov(wqe->iov, wqe->iov_count, PAYLOAD_OF(rdmap),
			payload_length, offset);
	wqe->recv_size += payload_length;
	assert(wqe->input_size == 0 || wqe->recv_size <= wqe->input_size);
	if (wqe->recv_size == wqe->input_size) {
		wqe->complete = true;
	}

	wqe->imm_data = rdmap->head.immediate;

	/* Post completion, but only if there are no holes in the LLP packet
	 * sequence. This ensures that even in the case of missing packets,
	 * we maintain the ordering between received Tagged and Untagged
	 * frames. Walk the queue starting at the head to make sure we post
	 * completions that we had previously deferred. */
	if (serial_less_32(orig->psn, wqe->remote_ep->recv_ack_psn)) {
		wqe = list_top(&qp->rq0.active_head, struct usiw_recv_wqe, active);
		while (wqe && wqe->complete) {
			rte_spinlock_lock(&qp->rq0.lock);
			post_recv_cqe(qp, wqe, IBV_WC_SUCCESS);
			rte_spinlock_unlock(&qp->rq0.lock);
			wqe = list_top(&qp->rq0.active_head, struct usiw_recv_wqe, active);
		}
	}
}	/* process_send */


/* This function implements the masked FetchAdd operation specified by iWARP.
 * This is optimized for the common case where the mask is 0. The implementation
 * follows the pseudocode specified in RFC 7306. */
static void
do_atomic_fetchadd(uint64_t orig, uint64_t *target,
		struct read_atomic_response_state *readresp)
{
	uint64_t val1, val2, sum;
	bool carry = false;
	int bitno, bit;

	if (!readresp->atomic.add_swap_mask) {
		*target = orig + readresp->atomic.add_swap;
		return;
	}

	*target = 0;
	for (bitno = 0; bitno < 64; bitno++) {
		bit = 1 << bitno;
		val1 = (orig & bit) >> bitno;
		val2 = (readresp->atomic.add_swap & bit) >> bitno;
		sum = (carry ? 1 : 0) + val1 + val2;
		carry = !!(sum & 2) && !(readresp->atomic.add_swap_mask & bit);
		sum &= 1;
		if (sum)
			*target |= bit;
	}
} /* do_atomic_fetchadd */


/* This function implements the masked CmpSwap operation specified by iWARP.
 * This is optimized for the common case where the mask is 0. The implementation
 * follows the pseudocode specified in RFC 7306. */
static void
do_atomic_cmpswap(uint64_t orig, uint64_t *target,
		struct read_atomic_response_state *readresp)
{
	uint64_t add_swap_mask = readresp->atomic.add_swap_mask;
	uint64_t compare_mask = readresp->atomic.compare_mask;

	if (!(compare_mask | add_swap_mask)) {
		if (*target == readresp->atomic.compare)
			*target = readresp->atomic.add_swap;
		return;
	}

	if (!((readresp->atomic.compare ^ orig) & compare_mask)) {
		*target = (orig & ~add_swap_mask)
			| (readresp->atomic.add_swap & add_swap_mask);
	}

} /* do_atomic_cmpswap */


static uint64_t
dispatch_atomic_op(struct usiw_qp *qp, struct read_atomic_response_state *readresp)
{
	uint64_t orig, *target;

	pthread_mutex_lock(qp->dev->driver->rdma_atomic_mutex);
	target = (uint64_t *)readresp->vaddr;
	orig = *target;
	switch (readresp->atomic.opcode) {
	case rdmap_atomic_fetchadd:
		do_atomic_fetchadd(orig, target, readresp);
		break;
	case rdmap_atomic_cmpswap:
		do_atomic_cmpswap(orig, target, readresp);
		break;
	}
	pthread_mutex_unlock(qp->dev->driver->rdma_atomic_mutex);
	return orig;
} /* dispatch_atomic_op */


static int
respond_atomic(struct usiw_qp *qp, struct read_atomic_response_state *readresp)
{
	struct rdmap_atomicresp_packet *new_rdmap;
	struct rte_mbuf *sendmsg;
	size_t dgram_length;
	uint64_t orig;

	if (likely(!readresp->atomic.done)) {
		orig = dispatch_atomic_op(qp, readresp);
		readresp->atomic.done = true;
	}

	if (serial_less_32(readresp->sink_ep->send_next_psn,
				readresp->sink_ep->send_max_psn)) {
		sendmsg = rte_pktmbuf_alloc(qp->dev->tx_ddp_mempool);

		dgram_length = sizeof(*new_rdmap);

		new_rdmap = (struct rdmap_atomicresp_packet *)rte_pktmbuf_append(
				sendmsg, dgram_length);
		new_rdmap->untagged.head.ddp_flags = DDP_V1_UNTAGGED_LAST_DF;
		new_rdmap->untagged.head.rdmap_info = RDMAP_V1
			| rdmap_opcode_atomic_response;
		new_rdmap->untagged.head.sink_stag
			= rte_cpu_to_be_32(readresp->sink_stag);
		new_rdmap->untagged.qn
			= rte_cpu_to_be_32(ddp_queue_atomic_response);
		new_rdmap->untagged.msn
			= rte_cpu_to_be_32(qp->readresp_head_msn++);
		new_rdmap->req_id = readresp->atomic.req_id;
		new_rdmap->orig_value = rte_cpu_to_be_64(orig);

		(void)send_ddp_segment(qp, sendmsg, readresp,
				NULL, 0);

		/* Signal that this is done */
		readresp->active = false;
		return 1;
	} else {
		return 0;
	}
} /* respond_atomic */


static int
respond_rdma_read(struct usiw_qp *qp, struct read_atomic_response_state *readresp)
{
	struct rdmap_tagged_packet *new_rdmap;
	struct rte_mbuf *sendmsg;
	size_t dgram_length;
	size_t payload_length;
	uint16_t mtu = qp->shm_qp->mtu;
	int count = 0;

	while (readresp->read.msg_size > 0
			&& serial_less_32(readresp->sink_ep->send_next_psn,
				readresp->sink_ep->send_max_psn)) {
		sendmsg = rte_pktmbuf_alloc(qp->dev->tx_ddp_mempool);

		payload_length = RTE_MIN(mtu, readresp->read.msg_size);
		dgram_length = RDMAP_TAGGED_ALLOC_SIZE(payload_length);

		new_rdmap = (struct rdmap_tagged_packet *)rte_pktmbuf_append(
				sendmsg, dgram_length);
		new_rdmap->head.ddp_flags = (readresp->read.msg_size <= mtu)
			? DDP_V1_TAGGED_LAST_DF : DDP_V1_TAGGED_DF;
		new_rdmap->head.rdmap_info = RDMAP_V1
			| rdmap_opcode_rdma_read_response;
		new_rdmap->head.sink_stag = readresp->sink_stag;
		new_rdmap->offset
			= rte_cpu_to_be_64(readresp->read.sink_offset);
		memcpy(PAYLOAD_OF(new_rdmap), readresp->vaddr,
				payload_length);

		(void)send_ddp_segment(qp, sendmsg, readresp,
				NULL, payload_length);
		readresp->vaddr += payload_length;
		readresp->read.msg_size -= payload_length;
		readresp->read.sink_offset += payload_length;
		count++;
	}

	if (readresp->read.msg_size == 0) {
		/* Signal that this is done */
		readresp->active = false;
		qp->readresp_head_msn++;
	}

	return count;
} /* respond_rdma_read */


static int
respond_next_read_atomic(struct usiw_qp *qp)
{
	struct read_atomic_response_state *readresp;
	unsigned long msn, end;
	int count;

	count = 0;
	for (msn = qp->readresp_head_msn, end = msn + qp->shm_qp->ird_max;
							msn != end; ++msn) {
		readresp = &qp->readresp_store[msn % qp->shm_qp->ird_max];
		if (!readresp->active) {
			break;
		}

		switch (readresp->type) {
		case atomic_response:
			count += respond_atomic(qp, readresp);
			break;
		case read_response:
			count += respond_rdma_read(qp, readresp);
			break;
		}
	}
	return count;
} /* respond_next_read_atomic */


static void
process_rdma_read_request(struct usiw_qp *qp, struct packet_context *orig)
{
	struct rdmap_readreq_packet *rdmap
		= (struct rdmap_readreq_packet *)orig->rdmap;
	struct read_atomic_response_state *readresp;
	uint32_t rkey;
	uint32_t msn;
	struct usiw_mr **candidate;
	struct usiw_mr *mr;

	msn = rte_be_to_cpu_32(rdmap->untagged.msn);
	if (msn < orig->src_ep->expected_read_msn
			|| msn >= qp->readresp_head_msn + qp->shm_qp->ird_max) {
		RTE_LOG(INFO, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> RDMA READ failure: expected MSN in range [%" PRIu32 ", %" PRIu32 "] received %" PRIu32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				orig->src_ep->expected_read_msn,
				qp->readresp_head_msn + qp->shm_qp->ird_max,
				msn);
		do_rdmap_terminate(qp, orig, ddp_error_untagged_invalid_msn);
		return;
	}
	if (msn == orig->src_ep->expected_read_msn)
		orig->src_ep->expected_read_msn++;

	rkey = rte_be_to_cpu_32(rdmap->source_stag);
	candidate = usiw_mr_lookup(qp->pd, rkey);
	if (!candidate) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> RDMA READ failure: invalid rkey %" PRIx32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				rkey);
		do_rdmap_terminate(qp, orig, rdmap_error_stag_invalid);
		return;
	}

	mr = *candidate;
	uintptr_t vaddr = (uintptr_t)rte_be_to_cpu_64(rdmap->source_offset);
	uint32_t rdma_length = rte_be_to_cpu_32(rdmap->read_msg_size);
	if (vaddr < (uintptr_t)mr->mr.addr || vaddr + rdma_length
			> (uintptr_t)mr->mr.addr + mr->mr.length) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> RDMA READ failure: source [%" PRIxPTR ", %" PRIxPTR
				"] outside of memory region [%" PRIxPTR ", %" PRIxPTR "]\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				vaddr, vaddr + rdma_length,
				(uintptr_t)mr->mr.addr,
				(uintptr_t)mr->mr.addr + mr->mr.length);
		do_rdmap_terminate(qp, orig,
				rdmap_error_base_or_bounds_violation);
		return;
	}

	readresp = &qp->readresp_store[msn % qp->shm_qp->ird_max];
	if (readresp->active) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> RDMA READ failure: duplicate MSN %" PRIu32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id, msn);
		do_rdmap_terminate(qp, orig,
				rdmap_error_remote_stream_catastrophic);
		return;
	}
	readresp->active = true;
	readresp->type = read_response;
	readresp->vaddr = (void *)vaddr;
	readresp->sink_stag = rdmap->untagged.head.sink_stag;
	readresp->sink_ep = orig->src_ep;
	readresp->read.msg_size = rdma_length;
	readresp->read.sink_offset = rte_be_to_cpu_64(rdmap->sink_offset);
}	/* process_rdma_read_request */


static void
process_atomic_request(struct usiw_qp *qp, struct packet_context *orig)
{
	struct rdmap_atomicreq_packet *rdmap
		= (struct rdmap_atomicreq_packet *)orig->rdmap;
	struct read_atomic_response_state *readresp;
	uint32_t rkey;
	uint32_t msn;
	struct usiw_mr **candidate;
	struct usiw_mr *mr;

	msn = rte_be_to_cpu_32(rdmap->untagged.msn);
	if (msn < orig->src_ep->expected_read_msn
			|| msn >= qp->readresp_head_msn + qp->shm_qp->ird_max) {
		RTE_LOG(INFO, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> ATOMIC failure: expected MSN in range [%" PRIu32 ", %" PRIu32 "] received %" PRIu32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				orig->src_ep->expected_read_msn,
				qp->readresp_head_msn + qp->shm_qp->ird_max,
				msn);
		do_rdmap_terminate(qp, orig, ddp_error_untagged_invalid_msn);
		return;
	}
	if (msn == orig->src_ep->expected_read_msn)
		orig->src_ep->expected_read_msn++;

	rkey = rte_be_to_cpu_32(rdmap->remote_stag);
	candidate = usiw_mr_lookup(qp->pd, rkey);
	if (!candidate) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> ATOMIC failure: invalid rkey %" PRIx32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				rkey);
		do_rdmap_terminate(qp, orig, rdmap_error_stag_invalid);
		return;
	}

	mr = *candidate;
	uintptr_t vaddr = (uintptr_t)rte_be_to_cpu_64(rdmap->remote_offset);
	size_t rdma_length = sizeof(uint64_t);
	if (vaddr < (uintptr_t)mr->mr.addr || vaddr + rdma_length
			> (uintptr_t)mr->mr.addr + mr->mr.length) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> ATOMIC failure: target [%" PRIxPTR ", %" PRIxPTR
				"] outside of memory region [%" PRIxPTR ", %" PRIxPTR "]\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				vaddr, vaddr + rdma_length,
				(uintptr_t)mr->mr.addr,
				(uintptr_t)mr->mr.addr + mr->mr.length);
		do_rdmap_terminate(qp, orig,
				rdmap_error_base_or_bounds_violation);
		return;
	} else if (vaddr & 7) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> ATOMIC failure: target %" PRIxPTR
				"] is not aligned on 8-byte boundary\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id, vaddr);
		do_rdmap_terminate(qp, orig,
				rdmap_error_remote_stream_catastrophic);
	}

	readresp = &qp->readresp_store[msn % qp->shm_qp->ird_max];
	if (readresp->active) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> ATOMIC failure: duplicate MSN %" PRIu32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id, msn);
		do_rdmap_terminate(qp, orig,
				rdmap_error_remote_stream_catastrophic);
		return;
	}
	readresp->active = true;
	readresp->type = atomic_response;
	readresp->vaddr = mr->mr.addr;
	readresp->atomic.opcode = rte_be_to_cpu_32(rdmap->opcode);
	readresp->atomic.req_id = rdmap->req_id;
	readresp->atomic.add_swap = rte_be_to_cpu_32(rdmap->add_swap_data);
	readresp->atomic.add_swap_mask
		= rte_be_to_cpu_32(rdmap->add_swap_mask);
	readresp->atomic.compare = rte_be_to_cpu_32(rdmap->compare_data);
	readresp->atomic.compare_mask = rte_be_to_cpu_32(rdmap->compare_mask);
	readresp->atomic.done = false;
	readresp->sink_stag = rdmap->untagged.head.sink_stag;
	readresp->sink_ep = orig->src_ep;
}	/* process_atomic_request */


/** Complete the requested WQE if and only if all completion ordering rules
 * have been met. */
static void
try_complete_wqe(struct usiw_qp *qp, struct usiw_send_wqe *wqe)
{
	/* We cannot post the completion until all previous WQEs have
	 * completed. */
	if (wqe == list_top(&qp->sq.active_head, struct usiw_send_wqe, active)) {
		rte_spinlock_lock(&qp->sq.lock);
		if (wqe->flags & usiw_send_signaled) {
			post_send_cqe(qp, wqe, IBV_WC_SUCCESS);
		} else {
			qp_free_send_wqe(qp, wqe, true);
		}
		rte_spinlock_unlock(&qp->sq.lock);
		if (wqe->opcode == usiw_wr_read
				|| wqe->opcode == usiw_wr_atomic) {
			assert(qp->ord_active > 0);
			qp->ord_active--;
		}
	}
} /* try_complete_wqe */


static struct usiw_send_wqe *
find_first_rdma_read_atomic(struct usiw_qp *qp)
{
	struct usiw_send_wqe *lptr, *next;
	list_for_each_safe(&qp->sq.active_head, lptr, next, active) {
		if (lptr->opcode == usiw_wr_read
				|| lptr->opcode == usiw_wr_atomic) {
			return lptr;
		}
	}
	return NULL;
}	/* find_first_rdma_read */


static void
process_rdma_read_response(struct usiw_qp *qp, struct packet_context *orig)
{
	struct rdmap_tagged_packet *rdmap;
	struct usiw_send_wqe *read_wqe;
	int ret;

	/* This ensures that at least one RDMA READ Request is active for this
	 * STag. We don't need to know exactly which one; this just ensures
	 * that we don't accept a random RDMA READ Response. */
	rdmap = (struct rdmap_tagged_packet *)orig->rdmap;
	ret = usiw_send_wqe_queue_lookup(&qp->sq,
			usiw_wr_read, rte_be_to_cpu_32(rdmap->head.sink_stag),
			&read_wqe);
	if (ret < 0 || !read_wqe || read_wqe->opcode != usiw_wr_read) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Unexpected RDMA READ response!\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id);
		do_rdmap_terminate(qp, orig, rdmap_error_opcode_unexpected);
		return;
	}

	/* If this was the last segment of an RDMA READ Response message, insert
	 * its PSN into the heap. Next time we receive a burst of packets, we
	 * will retrieve this PSN from the heap if we have received all prior
	 * packets and complete the corresponding WQE in the correct order. */
	if (DDP_GET_L(rdmap->head.ddp_flags)) {
		binheap_insert(qp->remote_ep.recv_rresp_last_psn, orig->psn);
	}
}	/* process_rdma_read_response */


static void
process_atomic_response(struct usiw_qp *qp, struct packet_context *orig)
{
	struct rdmap_atomicresp_packet *rdmap;
	struct usiw_send_wqe *wqe;
	uint16_t wqe_opcode;
	int ret;

	/* This ensures that at least one atomic request is active for this
	 * STag. We don't need to know exactly which one; this just ensures
	 * that we don't accept a random RDMA READ Response. */
	rdmap = (struct rdmap_atomicresp_packet *)orig->rdmap;
	ret = usiw_send_wqe_queue_lookup(&qp->sq, usiw_wr_atomic,
			rte_be_to_cpu_32(rdmap->req_id), &wqe);
	if (ret < 0 || !wqe || wqe->opcode != usiw_wr_atomic) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Unexpected atomic response!\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id);
		do_rdmap_terminate(qp, orig, rdmap_error_opcode_unexpected);
		return;
	} else if (!DDP_GET_L(rdmap->untagged.head.ddp_flags)) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Atomic response not single segment!\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id);
		do_rdmap_terminate(qp, orig,
				rdmap_error_remote_stream_catastrophic);
		return;
	}

	if (wqe->iov_count) {
		rte_memcpy(wqe->iov[0].iov_base, &rdmap->orig_value,
				sizeof(rdmap->orig_value));
	}

	binheap_insert(qp->remote_ep.recv_rresp_last_psn, orig->psn);
}	/* process_atomic_response */


static void
qp_shutdown(struct usiw_qp *qp)
{
	struct ibv_qp_attr qp_attr;
	struct ibv_modify_qp cmd;

	RTE_LOG(DEBUG, USER1, "Shutdown QP %u\n", qp->shm_qp->qp_id);

	pthread_mutex_lock(&qp->shm_qp->conn_event_lock);
	send_trp_fin(qp);

	atomic_store(&qp->shm_qp->conn_state, usiw_qp_error);
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_ERR;
	ibv_cmd_modify_qp(&qp->ib_qp, &qp_attr, IBV_QP_STATE,
			&cmd, sizeof(cmd));
	pthread_mutex_unlock(&qp->shm_qp->conn_event_lock);

	sq_flush(qp);
	rq_flush(qp);
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
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Received TERMINATE with error code %#" PRIxFAST16 " and no DDP header\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id,
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
			RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> TERMINATE sink_stag=%" PRIu32 " has no matching RDMA Read Request\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
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
				RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> TERMINATE sink_stag=%" PRIu32 " has no matching RDMA WRITE operation\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
						rte_be_to_cpu_32(t->head.sink_stag));
				return;
			}
			break;
		case rdmap_opcode_rdma_read_response:
			RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> TERMINATE for RDMA READ Response with sink_stag=%" PRIu32 ": error code %" PRIxFAST16 "\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
						rte_be_to_cpu_32(t->head.sink_stag),
						errcode);
			return;
		default:
			RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> TERMINATE sink_stag=%" PRIu32 " has tagged message error but invalid opcode %u\n",
					qp->shm_qp->dev_id, qp->shm_qp->qp_id,
					rte_be_to_cpu_32(t->head.sink_stag),
					RDMAP_GET_OPCODE(t->head.rdmap_info));
			return;
		}
		break;
	default:
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Received TERMINATE with unhandled error code %#" PRIxFAST16 "\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id,
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


static void
do_process_ack(struct usiw_qp *qp, struct usiw_send_wqe *wqe,
		struct pending_datagram_info *pending)
{
	wqe->bytes_acked += pending->ddp_length;
	assert(wqe->bytes_sent >= wqe->bytes_acked);

	if ((wqe->opcode == usiw_wr_send || wqe->opcode == usiw_wr_write || wqe->opcode == usiw_wr_send_with_imm)
			&& wqe->bytes_acked == wqe->total_length) {
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
			pending->psn = UINT32_MAX;
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
	while (count++ < ep->tx_pending_size && (sendmsg = *p) != NULL) {
		int ret, cstatus;
		pending = (struct pending_datagram_info *)(sendmsg + 1);
		if (now > pending->next_retransmit
				&& (ret = resend_ddp_segment(qp, sendmsg, ep)) < 0) {
			cstatus = IBV_WC_FATAL_ERR;
			switch (ret) {
			case -EIO:
				cstatus = IBV_WC_RETRY_EXC_ERR;
				RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> retransmit limit (%d) exceeded psn=%" PRIu32 "\n",
					qp->shm_qp->dev_id, qp->shm_qp->qp_id,
					RETRANSMIT_MAX,
					pending->psn);
				break;
			case -ENOMEM:
				RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> OOM on retransmit psn=%" PRIu32 "\n",
					qp->shm_qp->dev_id, qp->shm_qp->qp_id,
					pending->psn);
				break;
			default:
				RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> unknown error on retransmit psn=%" PRIu32 ": %s\n",
					qp->shm_qp->dev_id, qp->shm_qp->qp_id,
					pending->psn, rte_strerror(-ret));
			}
			if (pending->wqe) {
				rte_spinlock_lock(&qp->sq.lock);
				post_send_cqe(qp, pending->wqe, cstatus);
				rte_spinlock_unlock(&qp->sq.lock);
			} else if (pending->readresp) {
				struct rdmap_tagged_packet *rdmap;
				rdmap = rte_pktmbuf_mtod_offset(sendmsg, struct rdmap_tagged_packet *,
						sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)
						+ sizeof(struct udp_hdr) + sizeof(struct trp_hdr));
				RTE_LOG(NOTICE, USER1, "was read response; L=%d bytes left=%" PRIu32 "\n",
						DDP_GET_L(rdmap->head.ddp_flags),
						pending->readresp->read.msg_size);
			}
			RTE_LOG(DEBUG, USER1, "Shutdown QP %u\n", qp->shm_qp->qp_id);
			atomic_store(&qp->shm_qp->conn_state, usiw_qp_error);
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
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> received DDP tagged message with invalid stag %" PRIx32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				rkey);
		do_rdmap_terminate(qp, orig, ddp_error_tagged_stag_invalid);
		return;
	}

	mr = *candidate;
	vaddr = (uintptr_t)rte_be_to_cpu_64(rdmap->offset);
	rdma_length = orig->ddp_seg_length - sizeof(*rdmap);
	if (vaddr < (uintptr_t)mr->mr.addr || vaddr + rdma_length
			> (uintptr_t)mr->mr.addr + mr->mr.length) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> received DDP tagged message with destination [%" PRIxPTR ", %" PRIxPTR "] outside of memory region [%" PRIxPTR ", %" PRIxPTR "]\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				vaddr, vaddr + rdma_length,
				(uintptr_t)mr->mr.addr,
				(uintptr_t)mr->mr.addr + mr->mr.length);
		do_rdmap_terminate(qp, orig,
				ddp_error_tagged_base_or_bounds_violation);
		return;
	}

	rte_memcpy((void *)vaddr, PAYLOAD_OF(rdmap), rdma_length);
	RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Wrote %" PRIu32 " bytes to tagged buffer with stag=%" PRIx32 " at %" PRIx64 "\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id,
			rdma_length, rkey, vaddr);

	opcode = RDMAP_GET_OPCODE(orig->rdmap->rdmap_info);
	switch (opcode) {
	case rdmap_opcode_rdma_write:
		break;
	case rdmap_opcode_rdma_read_response:
		process_rdma_read_response(qp, orig);
		break;
	case rdmap_opcode_rdma_write_with_imm:
	default:
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> received DDP tagged message with invalid opcode %" PRIx8 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				opcode);
		do_rdmap_terminate(qp, orig, rdmap_error_opcode_unexpected);
	}
} /* ddp_place_tagged_data */


static void
process_data_packet(struct usiw_qp *qp, struct rte_mbuf *mbuf)
{
	struct packet_context ctx;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct trp_hdr *trp_hdr;
	uint16_t trp_opcode;

#ifdef DEBUG_PACKET_HEADERS
	RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Begin processing received packet:\n",
		qp->shm_qp->dev_id, qp->shm_qp->qp_id);
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
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Drop packet with bad UDP/IP checksum\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id);
		return;
	}

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*eth_hdr));
	if (ipv4_hdr->next_proto_id != IP_HDR_PROTO_UDP) {
		RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Drop packet with IPv4 next header %" PRIu8 " not UDP\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id,
			ipv4_hdr->next_proto_id);
	}
	if (ipv4_hdr->dst_addr != qp->dev->ipv4_addr) {
		RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Drop packet with IPv4 dst addr %" PRIx32 "; expected %" PRIx32 "\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id,
			rte_be_to_cpu_32(ipv4_hdr->dst_addr),
			rte_be_to_cpu_32(qp->dev->ipv4_addr));
	}

	udp_hdr = (struct udp_hdr *)rte_pktmbuf_adj(mbuf, sizeof(*ipv4_hdr));
	if (udp_hdr->dst_port != qp->shm_qp->local_udp_port) {
		RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Drop packet with UDP dst port %" PRIu16 "; expected %" PRIu16 "\n",
			qp->shm_qp->dev_id, qp->shm_qp->qp_id,
			rte_be_to_cpu_16(udp_hdr->dst_port),
			rte_be_to_cpu_16(qp->shm_qp->local_udp_port));
	}

	ctx.src_ep = &qp->remote_ep;
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
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> receive SACK [%" PRIu32 ", %" PRIu32 "); send_ack_psn %" PRIu32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				rte_be_to_cpu_32(trp_hdr->psn),
				rte_be_to_cpu_32(trp_hdr->ack_psn),
				ctx.src_ep->send_last_acked_psn);
		qp->stats.recv_sack_count++;
		process_trp_sack(ctx.src_ep, rte_be_to_cpu_32(trp_hdr->psn),
				rte_be_to_cpu_32(trp_hdr->ack_psn));
		return;
	case trp_fin:
		/* This is a finalize packet */
		qp_shutdown(qp);
		return;
	default:
		RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> receive unexpected opcode %" PRIu16 "; dropping\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
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
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> got ACK psn %" PRIu32 "; now last_acked_psn %" PRIu32 " send_next_psn %" PRIu32 " send_max_psn %" PRIu32 "\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
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
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> receive psn %" PRIu32 "; next expected psn %" PRIu32 "\n",
				qp->shm_qp->dev_id, qp->shm_qp->qp_id,
				ctx.psn,
				ctx.src_ep->recv_ack_psn);
		qp->stats.recv_psn_gap_count++;
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
				RTE_LOG(NOTICE, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> got out of range psn %" PRIu32 "; next expected %" PRIu32 " sack range: [%" PRIu32 ",%" PRIu32 "]\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
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
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> got retransmission psn %" PRIu32 "; expected psn %" PRIu32 "\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
						ctx.psn, ctx.src_ep->recv_ack_psn);
		qp->stats.recv_retransmit_count++;
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
		return ddp_place_tagged_data(qp, &ctx); //TODO
	} else {
		switch (RDMAP_GET_OPCODE(ctx.rdmap->rdmap_info)) {
			case rdmap_opcode_send_with_imm:
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
			case rdmap_opcode_atomic_request:
				process_atomic_request(qp, &ctx);
				break;
			case rdmap_opcode_atomic_response:
				process_atomic_response(qp, &ctx);
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
	case usiw_wr_send_with_imm:
		do_rdmap_send((struct usiw_qp *)qp, wqe);
		break;
	case usiw_wr_write:
	case usiw_wr_write_with_imm:
		do_rdmap_write((struct usiw_qp *)qp, wqe);
		break;
	case usiw_wr_read:
		do_rdmap_read_request((struct usiw_qp *)qp, wqe);
		break;
	case usiw_wr_atomic:
		do_rdmap_atomic(qp, wqe);
		break;
	}
} /* progress_send_wqe */


static int
process_receive_queue(struct usiw_qp *qp, void *prefetch_addr, uint64_t *now)
{
	struct rte_mbuf *rxmbuf[qp->shm_qp->rx_burst_size];
	uint16_t rx_count, pkt;

	/* Get burst of RX packets */
	if (qp->dev->flags & port_fdir) {
		rx_count = rte_eth_rx_burst(qp->dev->portid,
				qp->shm_qp->rx_queue,
				rxmbuf, qp->shm_qp->rx_burst_size);
	} else if (qp->remote_ep.rx_queue) {
		rx_count = RING_DEQUEUE_BURST(qp->remote_ep.rx_queue,
				(void **)rxmbuf, qp->shm_qp->rx_burst_size);
	} else {
		rx_count = 0;
	}
	qp->stats.base.recv_count_histo[rx_count]++;
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
	struct usiw_send_wqe *send_wqe, *next;
	uint64_t now;
	uint32_t psn;
	int scount, ret;

	/* Receive loop fills in now for us */
	process_receive_queue(qp, list_top(&qp->sq.active_head, struct usiw_send_wqe, active), &now);

	/* Call any timers only once per millisecond */
	sweep_unacked_packets(qp, now);

	/* Process RDMA READ Response last segments. */
	while (!binheap_empty(qp->remote_ep.recv_rresp_last_psn)) {
		binheap_peek(qp->remote_ep.recv_rresp_last_psn, &psn);
		if (psn < qp->remote_ep.recv_ack_psn) {
			/* We have received all prior packets, so since we have
			 * received the RDMA READ Response segment with L=1, we
			 * are guaranteed to have placed all data corresponding
			 * to this RDMA READ Response, and can complete the
			 * corresponding WQE. The heap ensures that we process
			 * the segments in the correct order, and
			 * try_complete_wqe() ensures that we do not complete an
			 * RDMA READ request out of order. */
			send_wqe = find_first_rdma_read_atomic(qp);
			if (!(WARN_ONCE(!send_wqe,
					"No RDMA READ request pending\n"))) {
				send_wqe->state = SEND_WQE_COMPLETE;
				try_complete_wqe(qp, send_wqe);
			}
			binheap_pop(qp->remote_ep.recv_rresp_last_psn);
		} else {
			break;
		}
	}

	scount = 0;

	list_for_each_safe(&qp->sq.active_head, send_wqe, next, active) {
		if (list_next(&qp->sq.active_head, send_wqe, active)) {
			rte_prefetch0(list_next(&qp->sq.active_head, send_wqe, active));
		}
		assert(send_wqe->state != SEND_WQE_INIT);
		progress_send_wqe(qp, send_wqe);
		if (send_wqe->state == SEND_WQE_TRANSFER) {
			scount++;
		}
	}
	if (scount == 0) {
		ret = rte_ring_dequeue(qp->sq.ring, (void **)&send_wqe);
		if (ret == 0) {
			assert(send_wqe->state == SEND_WQE_INIT);
			send_wqe->state = SEND_WQE_TRANSFER;
			switch (send_wqe->opcode) {
				case usiw_wr_send_with_imm:
				case usiw_wr_send:
					send_wqe->msn = send_wqe->remote_ep
							->next_send_msn++;
					break;
				case usiw_wr_read:
				case usiw_wr_atomic:
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

	scount += respond_next_read_atomic(qp);

	if (qp->remote_ep.trp_flags & trp_ack_update) {
		if (unlikely(qp->remote_ep.trp_flags & trp_recv_missing)) {
			send_trp_sack(qp);
		} else {
			send_trp_ack(qp);
		}
	}

	flush_tx_queue(qp);
} /* progress_qp */


void
urdma_do_destroy_cq(struct usiw_cq *cq)
{
	rte_free(cq->cqe_ring);
	rte_free(cq->free_ring);
	free(cq);
} /* urdma_do_destroy_cq */


void
usiw_do_destroy_qp(struct usiw_qp *qp)
{
	struct urdmad_sock_qp_msg msg;

	if (getenv("URDMA_DEBUG")) {
		fprintf(stderr, "<dev=%" PRIx16" qp=%" PRIx16 "> recv_psn_gap_count %" PRIuMAX "\n",
				qp->dev->portid, qp->shm_qp->qp_id,
				qp->stats.recv_psn_gap_count);
		fprintf(stderr, "<dev=%" PRIx16" qp=%" PRIx16 "> recv_retransmit_count %" PRIuMAX "\n",
				qp->dev->portid, qp->shm_qp->qp_id,
				qp->stats.recv_retransmit_count);
		fprintf(stderr, "<dev=%" PRIx16" qp=%" PRIx16 "> recv_sack_count %" PRIuMAX "\n",
				qp->dev->portid, qp->shm_qp->qp_id,
				qp->stats.recv_sack_count);
	}

	if (atomic_fetch_sub(&qp->recv_cq->refcnt, 1) == 1) {
		urdma_do_destroy_cq(qp->recv_cq);
	}
	if (qp->send_cq != qp->recv_cq) {
		if (atomic_fetch_sub(&qp->send_cq->refcnt, 1) == 1) {
			urdma_do_destroy_cq(qp->send_cq);
		}
	}

	usiw_recv_wqe_queue_destroy(&qp->rq0);
	usiw_send_wqe_queue_destroy(&qp->sq);
	free(qp->remote_ep.recv_rresp_last_psn);
	free(qp->readresp_store);

	memset(&msg, 0, sizeof(msg));
	msg.hdr.opcode = rte_cpu_to_be_32(urdma_sock_destroy_qp_req);
	msg.hdr.dev_id = rte_cpu_to_be_16(qp->dev->portid);
	msg.hdr.qp_id = rte_cpu_to_be_16(qp->shm_qp->qp_id);
	msg.ptr = rte_cpu_to_be_64((uintptr_t)qp->shm_qp);
	send(qp->dev->urdmad_fd, &msg, sizeof(msg), 0);
	free(qp->stats.base.recv_count_histo);
	free(qp->txq);
	free(qp);
} /* usiw_do_destroy_qp */


static void
start_qp(struct usiw_qp *qp)
{
	unsigned int cur_state;
	const char* urdma_qp_state_description[] = {"UNBOUND", "CONNECTED", "RUNNING", "SHUTDOWN", "ERROR"};

	RTE_LOG(DEBUG, USER1, "Start QP\n");


	pthread_mutex_lock(&qp->shm_qp->conn_event_lock);
	qp->readresp_store = calloc(qp->shm_qp->ird_max,
			sizeof(*qp->readresp_store));
	if (!qp->readresp_store) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Set up readresp_store failed: %s\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
						strerror(errno));
		goto err;
	}

	/* FIXME: Get this from the peer */
	qp->remote_ep.send_max_psn = qp->shm_qp->tx_desc_count / 2;
	qp->remote_ep.tx_pending_size = qp->shm_qp->tx_desc_count / 2;
	qp->remote_ep.tx_pending = calloc(qp->remote_ep.tx_pending_size,
			sizeof(*qp->remote_ep.tx_pending));
	if (!qp->remote_ep.tx_pending) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Set up tx_pending failed: %s\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
						strerror(errno));
		goto free_readresp_store;
	}
	qp->remote_ep.tx_head = qp->remote_ep.tx_pending;

	qp->remote_ep.recv_rresp_last_psn = binheap_new(qp->shm_qp->ord_max);
	if (!qp->remote_ep.recv_rresp_last_psn) {
		goto free_tx_pending;
	}

	RTE_LOG(DEBUG, USER1, "Initializing the QP TXQ to contain %u structs of size %u\n", qp->shm_qp->tx_burst_size, sizeof(*qp->txq));
	qp->txq = calloc(qp->shm_qp->tx_burst_size, sizeof(*qp->txq));
	if (!qp->txq) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Set up txq failed: %s\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
						strerror(errno));
		goto free_recv_rresp_last_psn;
	}
	qp->txq_end = qp->txq;

	qp->stats.base.recv_max_burst_size = qp->shm_qp->rx_burst_size;
	qp->stats.base.recv_count_histo = calloc(qp->stats.base.recv_max_burst_size + 1,
			sizeof(*qp->stats.base.recv_count_histo));
	if (!qp->stats.base.recv_count_histo) {
		RTE_LOG(DEBUG, USER1, "<dev=%" PRIx16 " qp=%" PRIx16 "> Set up recv_count_histo failed: %s\n",
						qp->shm_qp->dev_id, qp->shm_qp->qp_id,
						strerror(errno));
		goto free_txq;
	}

	cur_state = usiw_qp_connected;
	atomic_compare_exchange_strong(&qp->shm_qp->conn_state, &cur_state,
				       usiw_qp_running);
	atomic_fetch_sub(&qp->ctx->qp_init_count, 1);
	RTE_LOG(DEBUG, USER1, "Moving QP %u from %s to %s\n", qp->shm_qp->qp_id, urdma_qp_state_description[cur_state], urdma_qp_state_description[qp->shm_qp->conn_state]);

	goto unlock;

free_txq:
	free(qp->txq);
free_recv_rresp_last_psn:
	free(qp->remote_ep.recv_rresp_last_psn);
free_tx_pending:
	free(qp->remote_ep.tx_pending);
free_readresp_store:
	free(qp->readresp_store);
err:
	atomic_store(&qp->shm_qp->conn_state, usiw_qp_error);
unlock:
	pthread_mutex_unlock(&qp->shm_qp->conn_event_lock);
	return;
} /* start_qp */


int
kni_loop(void *arg)
{
	struct usiw_context_handle *h, *h_next;
	struct usiw_context *ctx;
	struct usiw_driver *driver;
	struct usiw_qp *qp, *qp_next;
	void *ctxs_to_add[NEW_CTX_MAX];
	unsigned int i, count;

	driver = arg;
	sem_wait(&driver->go);
	while (1) {
		count = RING_DEQUEUE_BURST(driver->new_ctxs, ctxs_to_add,
					     NEW_CTX_MAX);
		for (i = 0; i < count; ++i) {
			h = (struct usiw_context_handle *)ctxs_to_add[i];
			list_add_tail(&driver->ctxs, &h->driver_entry);
		}

		list_for_each_safe(&driver->ctxs, h, h_next, driver_entry) {
			ctx = (void *)atomic_load(&h->ctxp);
			if (unlikely(!ctx)) {
				list_del(&h->driver_entry);
				free(h);
				continue;
			}
			list_for_each_safe(&ctx->qp_active, qp, qp_next, ctx_entry) {
				switch (atomic_load(&qp->shm_qp->conn_state)) {
				case usiw_qp_connected:
					/* start_qp() transitions to
					 * usiw_qp_running */
					RTE_LOG(DEBUG, USER1, "kni_loop: start QP %d\n", qp->shm_qp->qp_id);
					start_qp(qp);
					if (atomic_load(&qp->shm_qp->conn_state)
							== usiw_qp_error) {
						break;
					}
					/* fall-through */
				case usiw_qp_running:
					//RTE_LOG(DEBUG, USER1, "kni_loop: progress QP %d\n", qp->shm_qp->qp_id);
					progress_qp(qp);
					break;
				case usiw_qp_shutdown:
					RTE_LOG(DEBUG, USER1, "kni_loop: shutdown QP %d\n", qp->shm_qp->qp_id);
					qp_shutdown(qp);
					/* qp_shutdown() transitions to
					 * usiw_qp_error */
					/* fall-through */
				case usiw_qp_error:
					RTE_LOG(DEBUG, USER1, "kni_loop: error in QP %d\n", qp->shm_qp->qp_id);
					list_del(&qp->ctx_entry);
					if (atomic_fetch_sub(&qp->refcnt,
								1) == 1) {
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
