/* udp_pingpong/main.c */

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

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_eth_ctrl.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_udp.h>

#include "util.h"

#define IP_HDR_PROTO_UDP 17

#define RX_DESC_COUNT 512
#define TX_DESC_COUNT 512

#define BASE_UDP_PORT 10000

static struct app_options {
	unsigned long long packet_count;
	unsigned long packet_size;
	unsigned long burst_size;
	unsigned int lcore_count;
	bool large_first_burst;
	bool checksum_offload;
	FILE *output_file;
} options = {
	.packet_count = 1000000,
	.packet_size = ETHER_MIN_LEN,
	.burst_size = 8,
	.lcore_count = 1,
	.output_file = NULL,
	.large_first_burst = true,
	.checksum_offload = true,
};

struct port {
	struct rte_mempool *mpool;
	int portid;
	uint32_t ipv4_addr;
	int ipv4_prefix_len;
	uint16_t tx_queue_count;
	uint16_t rx_queue_count;
	uint16_t arp_rx_queue;
};

static void
setup_filter_fdir(struct port *iface)
{
	struct rte_eth_fdir_filter_info filter_info;
	struct rte_eth_fdir_filter fdirf;
	unsigned int lcore_id;
	uint16_t udp_port;
	int retval;

	memset(&filter_info, 0, sizeof(filter_info));
	filter_info.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
	filter_info.info.input_set_conf.flow_type
				= RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
	filter_info.info.input_set_conf.inset_size = 2;
	filter_info.info.input_set_conf.field[0]
				= RTE_ETH_INPUT_SET_L3_DST_IP4;
	filter_info.info.input_set_conf.field[1]
				= RTE_ETH_INPUT_SET_L4_UDP_DST_PORT;
	filter_info.info.input_set_conf.op = RTE_ETH_INPUT_SET_SELECT;
	retval = rte_eth_dev_filter_ctrl(iface->portid, RTE_ETH_FILTER_FDIR,
			RTE_ETH_FILTER_SET, &filter_info);
	if (retval != 0) {
		rte_exit(EXIT_FAILURE, "Could not set fdir filter info: %s\n",
				strerror(-retval));
	}

	memset(&fdirf, 0, sizeof(fdirf));
	fdirf.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
	fdirf.input.flow.udp4_flow.ip.dst_ip = iface->ipv4_addr;
	fdirf.action.behavior = RTE_ETH_FDIR_ACCEPT;
	fdirf.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		udp_port = BASE_UDP_PORT + rte_lcore_index(lcore_id);
		fdirf.soft_id = lcore_id;
		fdirf.action.rx_queue = rte_lcore_index(lcore_id);
		fdirf.input.flow.udp4_flow.dst_port
			= rte_cpu_to_be_16(udp_port);
		fprintf(stderr, "--- assign lcore %u to rx queue %d and IP address %" PRIx32 ", UDP port %" PRIu16 "\n",
				lcore_id, fdirf.action.rx_queue,
				rte_be_to_cpu_32(iface->ipv4_addr), udp_port);
		retval = rte_eth_dev_filter_ctrl(iface->portid, RTE_ETH_FILTER_FDIR,
				RTE_ETH_FILTER_ADD, &fdirf);
		if (retval != 0) {
			rte_exit(EXIT_FAILURE, "Could not add fdir UDP filter: %s\n",
					strerror(-retval));
		}
	}
} /* setup_filter_fdir */

static void
setup_filter(struct port *iface)
{
	int retval;

	fprintf(stderr, "Enabling ethertype filter\n");
	struct rte_eth_ethertype_filter etypef = {
		.mac_addr = { .addr_bytes = { 0, 0, 0, 0, 0, 0, } },
		.ether_type = ETHER_TYPE_ARP,
		.flags = 0,
		.queue = iface->arp_rx_queue,
	};
	retval = rte_eth_dev_filter_ctrl(iface->portid,
			RTE_ETH_FILTER_ETHERTYPE,
			RTE_ETH_FILTER_ADD, &etypef);
	if (retval != 0) {
		rte_exit(EXIT_FAILURE, "Error enabling ethertype ARP filter: %s\n",
				strerror(-retval));
	}

	fprintf(stderr, "Enabling flow director filters\n");
	setup_filter_fdir(iface);
} /* setup_filter */

static int
port_init(struct port *iface, unsigned int port,
		struct rte_mempool *mbuf_pool,
		const char *ipv4_addr_string)
{

	static const uint32_t required_rx_offloads
		= DEV_RX_OFFLOAD_UDP_CKSUM|DEV_RX_OFFLOAD_IPV4_CKSUM;
	static const uint32_t required_tx_offloads
		= DEV_TX_OFFLOAD_UDP_CKSUM|DEV_TX_OFFLOAD_IPV4_CKSUM;

	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_conf port_conf;
	uint16_t rx_rings = options.lcore_count;
	uint16_t tx_rings = options.lcore_count;
	int retval;
	uint16_t q;

	memset(&port_conf, 0, sizeof(port_conf));
	port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
	port_conf.intr_conf.rxq = 1;
	if (options.lcore_count > 1
			&& rte_eth_dev_filter_supported(iface->portid,
				RTE_ETH_FILTER_FDIR) == 0) {
		/* Enable flow director to be set up later; this consumes
		 * resources on the NIC and causes other fields above
		 * (including the masks) to be processed */
		port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
		port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
		port_conf.fdir_conf.mask.ipv4_mask.src_ip = IPv4(0, 0, 0, 0);
		port_conf.fdir_conf.mask.ipv4_mask.dst_ip
						= IPv4(255, 255, 255, 255);
		port_conf.fdir_conf.mask.src_port_mask = 0;
		port_conf.fdir_conf.mask.dst_port_mask = UINT16_MAX;
		iface->arp_rx_queue = rte_lcore_index(rte_get_master_lcore());
	} else {
		/* Must support flow director in order to use more than one
		 * lcore */
		port_conf.fdir_conf.mode = RTE_FDIR_MODE_NONE;
		options.lcore_count = 1;
		rx_rings = 1;
		tx_rings = 1;
		iface->arp_rx_queue = 0;
	};

	if (port >= rte_eth_dev_count())
		return -1;

	iface->portid = port;
	rte_eth_dev_info_get(iface->portid, &dev_info);
	port_dump_info(stderr, &dev_info);
	fprintf(stderr, "\n");
	if ((dev_info.tx_offload_capa & required_tx_offloads)
			!= (required_tx_offloads)) {
		fprintf(stderr, "Port %u does not support checksum offload; disabling\n",
				port);
		options.checksum_offload = false;
	}
	if ((dev_info.rx_offload_capa & required_rx_offloads)
			== (required_rx_offloads)) {
		port_conf.rxmode.hw_ip_checksum = 1;
	}
	if (rx_rings > dev_info.max_rx_queues) {
		rx_rings = dev_info.max_rx_queues;
	}
	if (tx_rings > dev_info.max_tx_queues) {
		tx_rings = dev_info.max_tx_queues;
	}

	parse_ipv4_address(ipv4_addr_string,
			&iface->ipv4_addr,
			&iface->ipv4_prefix_len);
	iface->mpool = mbuf_pool;
	iface->rx_queue_count = rx_rings;
	iface->tx_queue_count = tx_rings;
	fprintf(stderr, "Port %u listening on %u.%u.%u.%u/%d\n", port,
			iface->ipv4_addr & 0xff,
			(iface->ipv4_addr >> 8) & 0xff,
			(iface->ipv4_addr >> 16) & 0xff,
			(iface->ipv4_addr >> 24) & 0xff,
			iface->ipv4_prefix_len);


	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	rte_eth_promiscuous_disable(port);

	/* Allocate and set up RX queues per lcore (plus one for control
	 * messages such as ARP requests). */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_DESC_COUNT,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per lcore. */
	for (q = 0; q < tx_rings; q++) {
		memcpy(&txconf, &dev_info.default_txconf, sizeof(txconf));
		txconf.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS
				| ETH_TXQ_FLAGS_NOVLANOFFL
				| ETH_TXQ_FLAGS_NOXSUMSCTP
				| ETH_TXQ_FLAGS_NOXSUMTCP;
		if (!options.checksum_offload) {
			txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMUDP;
		}
		retval = rte_eth_tx_queue_setup(port, q, TX_DESC_COUNT,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	if (options.lcore_count > 1) {
		setup_filter(iface);
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	fprintf(stderr, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	return 0;
}

/** Flips the fields of the Ethernet header and returns the Ethertype in
 * little-endian. */
static uint_fast16_t
flip_ether_header(struct port *port, struct rte_mbuf *mbuf)
{
	struct ether_hdr *ether = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	ether_addr_copy(&ether->s_addr, &ether->d_addr);
	rte_eth_macaddr_get(port->portid, &ether->s_addr);

	return rte_be_to_cpu_16(ether->ether_type);
} /* flip_ether_header */

static bool
make_arp_response(struct port *port, struct rte_mbuf *mbuf)
{
	struct arp_hdr *arp;
	uint32_t tmp;
	uint16_t ether_type;

	ether_type = flip_ether_header(port, mbuf);
	if (ether_type != ETHER_TYPE_ARP) {
		return false;
	}

	arp = rte_pktmbuf_mtod_offset(mbuf, struct arp_hdr *, sizeof(struct ether_hdr));
	if (rte_be_to_cpu_16(arp->arp_op) != ARP_OP_REQUEST) {
		return false;
	}

	arp->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

	fprintf(stderr, "lcore %u respond to ARP from %" PRIx32 "\n",
			rte_lcore_id(),
			rte_be_to_cpu_32(arp->arp_data.arp_sip));
	tmp = arp->arp_data.arp_tip;
	arp->arp_data.arp_tip = arp->arp_data.arp_sip;
	arp->arp_data.arp_sip = tmp;

	ether_addr_copy(&arp->arp_data.arp_sha, &arp->arp_data.arp_tha);
	rte_eth_macaddr_get(port->portid, &arp->arp_data.arp_sha);


	return true;
} /* make_arp_response */

static void
lookup_ether_addr(struct port *port, uint32_t ipv4_addr,
		struct ether_addr *dst_ether_addr)
{
	static const unsigned int max_retry_count = 5;
	static const struct ether_addr ether_bcast = {
		.addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
	};
	struct ether_addr self_ether_addr;
	struct rte_mbuf *mbuf;
	struct ether_hdr *ether;
	struct arp_hdr *arp;
	uint64_t deadline;
	uint16_t arp_tx_queue;
	uint16_t packet_count;
	unsigned int retry_count;
	unsigned int x;

	retry_count = 0;

send:
	mbuf = rte_pktmbuf_alloc(port->mpool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Could not get ARP mbuf: %s\n",
				rte_strerror(rte_errno));
	}
	if (!(arp = (struct arp_hdr *)rte_pktmbuf_append(mbuf, sizeof(*arp)))) {
		rte_exit(EXIT_FAILURE, "Not enough room in empty mbuf for ARP request: %s\n",
				rte_strerror(rte_errno));
	}
	arp->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp->arp_hln = ETHER_ADDR_LEN;
	arp->arp_pln = 4;
	arp->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);

	rte_eth_macaddr_get(port->portid, &self_ether_addr);
	ether_addr_copy(&self_ether_addr, &arp->arp_data.arp_sha);
	arp->arp_data.arp_sip = port->ipv4_addr;
	memset(&arp->arp_data.arp_tha, 0,
			sizeof(arp->arp_data.arp_tha));
	arp->arp_data.arp_tip = ipv4_addr;

	if (!(ether = (struct ether_hdr *)rte_pktmbuf_prepend(mbuf,
					sizeof(*ether)))) {
		rte_exit(EXIT_FAILURE, "Not enough headroom for Ethernet header: %s\n",
				rte_strerror(rte_errno));
	}
	ether_addr_copy(&ether_bcast, &ether->d_addr);
	rte_eth_macaddr_get(port->portid, &ether->s_addr);
	ether->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
	mbuf->l2_len = sizeof(*ether);

	assert(rte_lcore_id() != LCORE_ID_ANY);
	arp_tx_queue = rte_lcore_index(rte_lcore_id());
	if (rte_eth_tx_burst(port->portid, arp_tx_queue, &mbuf, 1) != 1) {
		rte_exit(EXIT_FAILURE, "Could not send ARP on idle link: %s\n",
				rte_strerror(rte_errno));
	}
	deadline = rte_get_timer_cycles() + rte_get_timer_hz();

wait:
	do {
		do {
			packet_count = 0;
			for (x = 0; x < 1000 && packet_count < 1; ++x) {
				packet_count = rte_eth_rx_burst(port->portid,
					port->arp_rx_queue, &mbuf, 1);
			}
			if (packet_count < 1) {
				if (rte_get_timer_cycles() >= deadline) {
					if (retry_count++ < max_retry_count) {
						/* Retransmit the ARP */
						fprintf(stderr, "Retransmit ARP (retry #%d)\n",
								retry_count);
						goto send;
					} else {
						rte_exit(EXIT_FAILURE, "No ARP reply received; retry count exceeded\n");
					}
				}
			}
		} while (packet_count < 1);
		ether = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	} while (rte_be_to_cpu_16(ether->ether_type) != ETHER_TYPE_ARP
			|| (!is_same_ether_addr(&self_ether_addr, &ether->d_addr)
				&& !is_broadcast_ether_addr(&ether->d_addr)));

	arp = rte_pktmbuf_mtod_offset(mbuf, struct arp_hdr *, sizeof(*ether));
	if (arp->arp_data.arp_sip != ipv4_addr) {
		fprintf(stderr, "Got ARP from non-interesting IPv4 address %" PRIx32 "\n",
				rte_be_to_cpu_32(ipv4_addr));
		goto wait;
	}

	ether_addr_copy(&arp->arp_data.arp_sha, dst_ether_addr);

	char etherbuf[20];
	ether_format_addr(etherbuf, 20, dst_ether_addr);
	etherbuf[19] = '\0';
	fprintf(stderr, "Got ARP Response; dest addr=%s\n", etherbuf);
}

static void
fill_udp_checksum(struct rte_mbuf *mbuf, struct ipv4_hdr *ip,
						struct udp_hdr *udp)
{
	udp->dgram_cksum = 0;
	if (options.checksum_offload) {
		mbuf->l2_len = sizeof(struct ether_hdr);
		mbuf->l3_len = sizeof(struct ipv4_hdr);
		mbuf->ol_flags |= PKT_TX_IPV4|PKT_TX_UDP_CKSUM;
		udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, mbuf->ol_flags);
	} else {
		udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
	}
}

static int
fill_ping_request(struct port *port, struct rte_mbuf *mbuf,
		const struct ether_addr *dest_ether_addr,
		uint32_t dest_ipv4_addr,
		uint_least16_t dest_udp_port)
{
	struct udp_hdr *udp;
	struct ipv4_hdr *ip;
	struct ether_hdr *ether;
	void *payload;

	if (!(payload = rte_pktmbuf_append(mbuf, options.packet_size))) {
		return -ENOBUFS;
	}
	ether = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ip = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
			sizeof(*ether));
	udp = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *,
			sizeof(*ether) + sizeof(*ip));

	ether_addr_copy(dest_ether_addr, &ether->d_addr);
	rte_eth_macaddr_get(port->portid, &ether->s_addr);
	ether->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = rte_cpu_to_be_16(options.packet_size
			- sizeof(*ether));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = IP_HDR_PROTO_UDP;
	ip->src_addr = port->ipv4_addr;
	ip->dst_addr = dest_ipv4_addr;

	/* Compute IP header checksum --- only depends on IP header contents,
	 * but checksum MUST be set to zero first */
	ip->hdr_checksum = 0;
	if (options.checksum_offload) {
		mbuf->ol_flags |= PKT_TX_IPV4|PKT_TX_IP_CKSUM;
	} else {
		ip->hdr_checksum = rte_ipv4_cksum(ip);
	}

	udp->src_port = dest_udp_port;
	udp->dst_port = dest_udp_port;
	udp->dgram_len = rte_cpu_to_be_16(options.packet_size
			- (sizeof(*ether) + sizeof(*ip)));

	fill_udp_checksum(mbuf, ip, udp);
	return 0;
}

static bool
flip_packet_headers_udp(struct port *port, struct rte_mbuf *mbuf)
{
	struct ipv4_hdr *ip;
	struct udp_hdr *udp;
	uint32_t tmp;
	uint16_t ether_type;

	if (mbuf->ol_flags & (PKT_RX_L4_CKSUM_BAD|PKT_RX_IP_CKSUM_BAD)) {
		RTE_LOG(NOTICE, USER1, "Drop packet with bad UDP/IP checksum\n");
		return false;
	}

	ether_type = flip_ether_header(port, mbuf);
	if (ether_type != ETHER_TYPE_IPv4) {
		return false;
	}

	ip = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
			sizeof(struct ether_hdr));
	if (ip->next_proto_id != IP_HDR_PROTO_UDP) {
		return false;
	}
	tmp = ip->dst_addr;
	ip->dst_addr = ip->src_addr;
	ip->src_addr = tmp;

	udp = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *,
			sizeof(struct ether_hdr) + sizeof(*ip));
	tmp = udp->dst_port;
	udp->dst_port = udp->src_port;
	udp->src_port = tmp;

	return true;
}

static void
recompute_udp_checksum(struct rte_mbuf *mbuf)
{
	struct ipv4_hdr *ip;
	struct udp_hdr *udp;

	ip = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *,
			sizeof(struct ether_hdr));
	udp = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *,
			sizeof(struct ether_hdr) + sizeof(*ip));

	fill_udp_checksum(mbuf, ip, udp);
}

struct stats {
	uint64_t latency;
		/**< Per-packet unidirectional latency, in cycles.  It is
		 * measured by inserting a cycle counter timestamp into an
		 * outgoing packet and then calculating the difference from the
		 * current cycle counter when the response is received.  The
		 * final value is the MEAN across all threads (note that the
		 * master lcore will receive the sum and itself divide by the
		 * number of workers). */
	uint64_t start_time;
		/**< Per-thread start cycle counter.  The final value is the
		 * MIN across all threads. */
	uint64_t end_time;
		/**< Per-thread end cycle counter. The final value is the MAX
		 * across all threads. */
	uint64_t elapsed_cycles;
		/**< Total cycles elapsed across all threads. The final value
		 * is the SUM across all threads. */
	uint64_t poll_cycles;
		/**< Total Cycles spent in recv poll loop. The final value is
		 * the SUM across all threads. */
	uintmax_t max_poll_cycles;
		/**< The maximum number of cycles spent in the recv poll
		 * loop. The final value is the MAX across all threads. */
	unsigned long long message_count;
		/**< Messages actually sent. The final value is the SUM across
		 * all threads. */
	uintmax_t *recv_count_histo;
		/**< The number of times that rte_eth_recv_burst returned each
		 * number of messages. The final value for each bucket is the
		 * SUM across all threads. */
	unsigned long first_burst_size;
		/**< The number of messages sent by the client in the first
		 * burst.  This will be greater that or equal to the input
		 * burst_size, since we try to keep sending messages until we
		 * receive the first response.  The final value is the MAX
		 * across all threads. */
};


static int
print_stats(FILE *fptr, const struct stats *stats)
{
	uint64_t elapsed_cycles;
	double timer_hz, physical_time, cpu_time, poll_time, latency;
	unsigned int x;
	int ret;

	elapsed_cycles = stats->end_time - stats->start_time;
	timer_hz = rte_get_timer_hz();
	physical_time = elapsed_cycles / timer_hz;
	cpu_time = stats->elapsed_cycles / timer_hz;
	poll_time = stats->poll_cycles / timer_hz;
	latency = 1e6 * stats->latency / timer_hz;

	flockfile(fptr);
	errno = 0;
	ret = fprintf(fptr, "{\n  \"requested_packet_count\": %llu,\n",
			options.packet_count);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"packet_size\": %lu,\n", options.packet_size);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"burst_size\": %lu,\n", options.burst_size);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"checksum_offload\": %s,\n",
			options.checksum_offload ? "true" : "false");
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"slave_lcore_count\": %u,\n",
			options.lcore_count - 1);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"packet_count\": %llu,\n",
			stats->message_count);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"physical_time\": %.9f,\n", physical_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"cpu_time\": %.9f,\n", cpu_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"recv_poll_time\": %.9f,\n", poll_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"max_recv_poll_time\": %.9f,\n",
			stats->max_poll_cycles / timer_hz);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"message_rate\": %f,\n",
			stats->message_count / physical_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"throughput\": %f,\n",
			8 * options.packet_size * stats->message_count
			/ (physical_time * 1000000));
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"throughput_unit\": \"Mbps\",\n");
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"latency\": %.9f,\n", latency);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"latency_unit\": \"microsecond\",\n");
	if (ret < 0)
		return ret;
	if (stats->first_burst_size) {
		ret = fprintf(fptr, "  \"first_burst_size\": %lu,\n",
				stats->first_burst_size);
		if (ret < 0)
			return ret;
	}
	ret = fprintf(fptr, "  \"recv_count_per_burst_histo\": [");
	if (ret < 0)
		return ret;

	for (x = 0; x < options.burst_size; ++x) {
		ret = fprintf(fptr, "%" PRIuMAX ", ",
				stats->recv_count_histo[x]);
		if (ret < 0)
			return ret;
	}
	ret = fprintf(fptr, "%" PRIuMAX "]\n}\n",
			stats->recv_count_histo[options.burst_size]);
	if (ret < 0)
		return ret;

	ret = fflush(fptr);
	if (ret == EOF) {
		return -1;
	}
	funlockfile(fptr);

	return 0;
} /* print_stats */

/** Awaits a single ARP Request and replies to it. */
static void
await_single_arp(struct port *port)
{
	struct rte_epoll_event event;
	struct rte_mbuf *mbuf;
	unsigned int recv_count;
	uint16_t tx_queue, rx_queue;
	bool do_wait;
	int ret, x;

	rx_queue = rte_lcore_index(rte_lcore_id());
	tx_queue = rte_lcore_index(rte_lcore_id());
	do_wait = true;

	fprintf(stderr, "lcore %u (master) awaiting initial ARP request on rx queue %" PRIu16 "\n",
			rte_lcore_id(), rx_queue);
	while (1) {
		do {
			recv_count = 0;
			for (x = 0; x < 100 && recv_count == 0; ++x) {
				recv_count = rte_eth_rx_burst(port->portid,
						rx_queue, &mbuf, 1);
			}
			if (recv_count == 0 && do_wait) {
				ret = rte_eth_dev_rx_intr_enable(port->portid,
						rx_queue);
				if (ret != 0) {
					fprintf(stderr, "WARNING: Cannot enable interrupts: %s\n",
							strerror(-ret));
					do_wait = false;
					continue;
				}
				ret = rte_epoll_wait(RTE_EPOLL_PER_THREAD, &event, 1,
						1000);
				if (ret < 0) {
					fprintf(stderr, "WARNING: Error while waiting for event: %s\n",
							strerror(-ret));
					do_wait = false;
				}
				rte_eth_dev_rx_intr_disable(port->portid,
						rx_queue);
			}
		} while (recv_count == 0);
		if (make_arp_response(port, mbuf)) {
			ret = rte_eth_tx_burst(port->portid, tx_queue, &mbuf, 1);
			if (ret != 1) {
				rte_exit(EXIT_FAILURE, "Could not send ARP reply on idle link\n");
			}
			break;
			fprintf(stderr, "lcore %u sent ARP Response\n",
					rte_lcore_id());
		}
	}
} /* await_single_arp */

struct lcore_param {
	struct port *port;
		/**< Reference to the Ethernet device port to use. */
	struct stats *final_stats;
		/**< Reference to the final statistics filled in by each
		 * thread.  Accesses to this must be protected by lock. */
	struct ether_addr dest_ether_addr;
		/**< The destination Ethernet address, if we are a client.
		 * Unspecified if we are a server. */
	uint32_t dest_ipv4_addr;
		/**< If we are a client, the destination IPv4 address.  If we
		 * are a server, this is set to all zeroes. */
	rte_spinlock_t lock;
		/**< Protects final_stats.  Locked only after each lcore has
		 * completed its main loop. */
};

static int
do_master_lcore_work(struct stats *stats)
{
	rte_eal_mp_wait_lcore();

	/* Print the stats. */
	stats->latency /= rte_lcore_count() - 1;
	if (print_stats(options.output_file
					? options.output_file : stdout,
					stats) != 0) {
		rte_exit(EXIT_FAILURE, "Error dumping statistics: %s\n",
				strerror(errno));
	}

	/* Close the stats output file */
	if (options.output_file) {
		if (fclose(options.output_file) == EOF) {
			rte_exit(EXIT_FAILURE, "Error detected closing JSON stream: %s\n",
					strerror(errno));
		}
	}

	return EXIT_SUCCESS;
}

static uint_fast16_t
wait_recv_bulk(struct lcore_param *arg, struct stats *stats,
		uint_fast16_t data_rx_queue, struct rte_mbuf **mbuf,
		uint64_t *poll_cycles)
{
	uint_fast16_t recv_count;
	uint64_t poll_start, poll_end;

	poll_start = rte_get_timer_cycles();
	do {
		recv_count = rte_eth_rx_burst(arg->port->portid,
				data_rx_queue,
				mbuf, options.burst_size);
	} while (recv_count == 0);
	rte_prefetch0(rte_pktmbuf_mtod(mbuf[0], void *));
	stats->recv_count_histo[recv_count]++;
	if (poll_cycles) {
		poll_end = rte_get_timer_cycles();
		*poll_cycles = poll_end - poll_start;
	}

	return recv_count;
} /* wait_recv_bulk */

static void
handle_burst(struct lcore_param *arg, struct rte_mbuf **mbuf,
		unsigned int *recv_count,
		unsigned int timestamp_offset,
		struct stats *stats,
		uint64_t *roundtrip_count,
		int remaining_send,
		int *remaining_recv)
{
	uint_fast16_t x;
	uint64_t *pkt_timestamp;

	x = 0;
	while (x < *recv_count) {
		if (x + 1 < *recv_count) {
			rte_prefetch0(rte_pktmbuf_mtod(mbuf[x + 1], void *));
		}
		assert(mbuf[x]->data_len >= options.packet_size);
		pkt_timestamp = rte_pktmbuf_mtod_offset(mbuf[x],
				uint64_t *, timestamp_offset);
		if (*pkt_timestamp != 0) {
			stats->latency += rte_get_timer_cycles()
					- *pkt_timestamp;
			*pkt_timestamp = 0;
			recompute_udp_checksum(mbuf[x]);
			(*roundtrip_count)++;
		}

		if (!flip_packet_headers_udp(arg->port, mbuf[x])) {
			--(*recv_count);
			rte_pktmbuf_free(mbuf[x]);
			mbuf[x] = mbuf[*recv_count];
		} else {
			if (!((remaining_send - x) & 255)) {
				*pkt_timestamp = rte_get_timer_cycles();
				recompute_udp_checksum(mbuf[x]);
			}
			x++;
		}
	}
	*remaining_recv -= *recv_count;
} /* handle_burst */

static uint16_t
transmit_burst(struct lcore_param *arg, uint_fast16_t data_tx_queue,
		struct rte_mbuf **mbuf, unsigned int recv_count,
		int *remaining_send)
{
	unsigned int x;
	uint16_t ret;

	if ((int)recv_count > *remaining_send) {
		for (x = *remaining_send; x < recv_count; ++x) {
			rte_pktmbuf_free(mbuf[x]);
		}
		recv_count = *remaining_send;
	}
	ret = rte_eth_tx_burst(arg->port->portid, data_tx_queue,
			mbuf, recv_count);
	*remaining_send -= ret;
	return recv_count - ret;
} /* transmit_burst */

static int
do_lcore_work(void *rawarg)
{
	struct lcore_param *arg;
	struct port *port;
	struct stats stats;
	struct rte_mbuf *mbuf[options.burst_size];
	uint64_t roundtrip_count;
	uint64_t poll_cycles;
	uint64_t start_time, end_time;
	uint16_t data_tx_queue, data_rx_queue;
	uint16_t dest_udp_port;
	unsigned int unsent_count, recv_count;
	unsigned int timestamp_offset;
	unsigned int x;
	int remaining_send, remaining_recv;

	assert(rte_lcore_id() != LCORE_ID_ANY);
	arg = rawarg;
	port = arg->port;
	data_rx_queue = port->rx_queue_count > 1
		? rte_lcore_index(rte_lcore_id()) : 0;
	data_tx_queue = port->tx_queue_count > 1
		? rte_lcore_index(rte_lcore_id()) : 0;
	dest_udp_port
		= rte_cpu_to_be_16(BASE_UDP_PORT
				+ rte_lcore_index(rte_lcore_id()));

	timestamp_offset = RTE_ALIGN_CEIL(sizeof(struct ether_hdr)
			+ sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr),
			sizeof(uint64_t));
	if (!arg->dest_ipv4_addr) {
		timestamp_offset += sizeof(uint64_t);
	}
	assert(timestamp_offset + sizeof(uint64_t)
			<= options.packet_size);

	stats.recv_count_histo = calloc(options.burst_size + 1,
			sizeof(*stats.recv_count_histo));
	remaining_send = options.packet_count;
	remaining_recv = options.packet_count;
	stats.latency = 0;
	stats.first_burst_size = 0;
	roundtrip_count = 0;
	if (arg->dest_ipv4_addr) {
		start_time = rte_get_timer_cycles();
		do {
			for (x = 0; x < options.burst_size; ++x) {
				mbuf[x] = rte_pktmbuf_alloc(port->mpool);
				if (!mbuf[x]) {
					break;
				}
				if (fill_ping_request(port, mbuf[x],
							&arg->dest_ether_addr,
							arg->dest_ipv4_addr,
							dest_udp_port) < 0) {
					fprintf(stderr, "Not enough space in packet buffer\n");
					return EXIT_FAILURE;
				}
			}
			unsent_count = transmit_burst(arg, data_tx_queue, mbuf,
					options.burst_size, &remaining_send);
			stats.first_burst_size
					+= options.burst_size - unsent_count;

			recv_count = rte_eth_rx_burst(arg->port->portid,
					data_rx_queue,
					mbuf, options.burst_size);
		} while (options.large_first_burst && unsent_count == 0
				&& recv_count == 0);

		if (recv_count > 0) {
			stats.recv_count_histo[recv_count]++;

			handle_burst(arg, mbuf, &recv_count, timestamp_offset,
					&stats, &roundtrip_count,
					remaining_send, &remaining_recv);
			assert((int)recv_count <= remaining_send);
			unsent_count += transmit_burst(arg, data_tx_queue, mbuf,
					recv_count, &remaining_send);
		}
		for (x = 0; x < unsent_count; ++x) {
			rte_pktmbuf_free(mbuf[options.burst_size
						- unsent_count]);
		}
	} else {
		recv_count = wait_recv_bulk(arg, &stats, data_rx_queue,
				mbuf, NULL);
		start_time = rte_get_timer_cycles();

		handle_burst(arg, mbuf, &recv_count, timestamp_offset, &stats,
				&roundtrip_count, remaining_send,
				&remaining_recv);
		assert((int)recv_count <= remaining_send);
		unsent_count = transmit_burst(arg, data_tx_queue, mbuf, recv_count,
				&remaining_send);
		if (unsent_count > 0) {
			fprintf(stderr, "%u messages not sent due to full tx ring\n",
					unsent_count);
		}
	}

	fprintf(stderr, "lcore %u sent first burst to %" PRIx32 " port %" PRIu16 "\n",
			rte_lcore_id(),
			rte_be_to_cpu_32(arg->dest_ipv4_addr),
			rte_be_to_cpu_16(dest_udp_port));

	stats.poll_cycles = 0;
	stats.max_poll_cycles = 0;
	fprintf(stderr, "lcore %u awaiting first burst on rx queue %" PRIu16 "\n",
			rte_lcore_id(), data_rx_queue);
	while (remaining_send > 0 || remaining_recv > 0) {
		recv_count = wait_recv_bulk(arg, &stats, data_rx_queue,
				mbuf, &poll_cycles);
		stats.poll_cycles += poll_cycles;
		if (poll_cycles > stats.max_poll_cycles) {
			stats.max_poll_cycles = poll_cycles;
		}

		handle_burst(arg, mbuf, &recv_count, timestamp_offset, &stats,
				&roundtrip_count, remaining_send,
				&remaining_recv);
		unsent_count = transmit_burst(arg, data_tx_queue, mbuf, recv_count,
				&remaining_send);
		if (unsent_count > 0) {
			fprintf(stderr, "%u messages not sent due to full tx ring\n",
					unsent_count);
		}
	}

	end_time = rte_get_timer_cycles();
	stats.elapsed_cycles = end_time - start_time;
	stats.message_count = options.packet_count - remaining_send;
	stats.latency = (roundtrip_count == 0) ? 0.0
		: (stats.latency / (2 * roundtrip_count));

	rte_spinlock_lock(&arg->lock);
	arg->final_stats->latency += stats.latency;
	if (start_time < arg->final_stats->start_time) {
		arg->final_stats->start_time = start_time;
	}
	if (end_time > arg->final_stats->end_time) {
		arg->final_stats->end_time = end_time;
	}
	arg->final_stats->elapsed_cycles += stats.elapsed_cycles;
	arg->final_stats->poll_cycles += stats.poll_cycles;
	arg->final_stats->message_count += stats.message_count;
	for (x = 0; x <= options.burst_size; ++x) {
		arg->final_stats->recv_count_histo[x]
					+= stats.recv_count_histo[x];
	}
	if (stats.max_poll_cycles > arg->final_stats->max_poll_cycles) {
		arg->final_stats->max_poll_cycles
					= stats.max_poll_cycles;
	}
	if (stats.first_burst_size > arg->final_stats->first_burst_size) {
		arg->final_stats->first_burst_size = stats.first_burst_size;
	}
	rte_spinlock_unlock(&arg->lock);

	free(stats.recv_count_histo);
	return EXIT_SUCCESS;
}

static struct option longopts[] = {
	{ .name = "packet-count", .has_arg = required_argument,
		.flag = NULL, .val = 'c' },
	{ .name = "packet-size", .has_arg = required_argument,
		.flag = NULL, .val = 's' },
	{ .name = "burst-size", .has_arg = required_argument,
		.flag = NULL, .val = 'b' },
	{ .name = "output", .has_arg = required_argument,
		.flag = NULL, .val = 'o' },
	{ .name = "disable-large-first-burst", .has_arg = no_argument,
		.flag = NULL, .val = 'F' },
	{ .name = "disable-checksum-offload", .has_arg = no_argument,
		.flag = NULL, .val = 'K' },
	{ .name = "help", .has_arg = no_argument, .flag = NULL, .val = 'h' },
	{ 0 },
};

static void
usage(int status)
{
	rte_exit(status, "Usage: udp_pingpong [<eal_options>] -- [<options>] <iface_ip> ... [<server_ip>]\n");
} /* usage */

/** Intended to be equivalent to the shell command
 * "mkdir -p $(dirname ${path})". */
static int
make_parent_dir(const char *path)
{
	struct stat st;
	char *pathcopy;
	char *dir;
	int ret;

	pathcopy = alloca(strlen(path) + 1);
	strcpy(pathcopy, path);
	dir = dirname(pathcopy);
	if (strcmp(dir, "/") == 0) {
		errno = ENOENT;
		return -1;
	} else if ((ret = stat(dir, &st)) < 0 && errno == ENOENT) {
		/* Recur to ensure parent directory exists */
		ret = make_parent_dir(dir);
		if (ret == 0) {
			/* If parent directory exists or was created, create
			 * this directory. */
			return mkdir(dir, 0770);
		} else {
			return ret;
		}
	} else if (ret < 0) {
		return ret;
	} else if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return -1;
	} else {
		/* Exists and is a directory */
		return 0;
	}
} /* make_parent_dir */

static unsigned int
parse_options(int argc, char *argv[])
{
	char *endch;
	int ch;

	while ((ch = getopt_long(argc, argv,
					"c:" /* --packet-count */
					"s:" /* --packet-size */
					"b:" /* --burst-size */
					"F" /* --disable-large-first-burst */
					"K" /* --disable-checksum-offload */
					"o:" /* --output */
					"h" /* --help */
					, longopts, NULL)) != -1) {
		switch (ch) {
		case 'c':
			errno = 0;
			options.packet_count = strtoull(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0' || !options.packet_count) {
				rte_exit(EXIT_FAILURE,
						"Invalid packet count \"%s\"\n",
						optarg);
			}
			break;
		case 's':
			errno = 0;
			options.packet_size = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0'
					|| options.packet_size < ETHER_MIN_LEN
					|| options.packet_size
					> ETHER_MAX_LEN - ETHER_CRC_LEN) {
				rte_exit(EXIT_FAILURE,
						"Invalid packet size \"%s\"\n",
						optarg);
			}
			break;
		case 'b':
			errno = 0;
			options.burst_size = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0'
					|| !options.burst_size
					|| options.burst_size
					> RX_DESC_COUNT) {
				rte_exit(EXIT_FAILURE,
						"Invalid burst size \"%s\"\n",
						optarg);
			}
			break;
		case 'F':
			options.large_first_burst = false;
			break;
		case 'K':
			options.checksum_offload = false;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 'o':
			if (options.output_file) {
				rte_exit(EXIT_FAILURE,
					"Only a single output file may be specified.\n");
			}
			if (make_parent_dir(optarg) < 0) {
				rte_exit(EXIT_FAILURE,
					"Could not create parent directory for %s: %s\n",
					optarg, strerror(errno));
			}
			options.output_file = fopen(optarg, "w");
			if (!options.output_file) {
				rte_exit(EXIT_FAILURE,
					"Could not open %s for writing: %s\n",
					optarg, strerror(errno));
			}
			break;
		default:
			rte_exit(EXIT_FAILURE, "Unexpected option -%c\n", ch);
			break;
		}
	}

	return optind - 1;
} /* parse_options */


/** Calculate the sizes according to the following rules from the DPDK
 * documentation:
 *
 *  - mbuf_count should be a power of 2 minus 1
 *  - cache_size must be no greater than RTE_CONFIG_CACHE_MAX_SIZE (512 by
 *    default; TODO: make this work if the size differs)
 *  - cache_size must be no greater than mbuf_count / 1.5
 *  - Ideally, mbuf_count % cache_size == 0
 */
static void
get_mempool_sizes(unsigned int *mbuf_count, unsigned int *cache_size)
{
	if (*mbuf_count <= 16383) {
		*mbuf_count = 16383;
		*cache_size = 381;
	} else if (*mbuf_count <= 32767) {
		*mbuf_count = 32767;
		*cache_size = 217;
	} else if (*mbuf_count <= 65535) {
		*mbuf_count = 65535;
		*cache_size = 257;
	} else if (*mbuf_count <= 262143) {
		*mbuf_count = 262143;
		*cache_size = 219;
	} else if (*mbuf_count <= 1048575) {
		*mbuf_count = 1048575;
		*cache_size = 275;
	} else {
		/* Allocate 2 Mi objects at most for this simple
		 * benchmark---that already consumes 2 GiB of memory without
		 * accounting for bookkeeping overhead.
		 *
		 * TODO: Allow reasonably larger mempools, up to maybe 128 GiB
		 * of consumed memory */
		*mbuf_count = 2097151;
		*cache_size = 337;
	}
} /* mempool_cache_size */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct lcore_param param;
	struct stats final_stats;
	struct port *interfaces;
	struct rte_mempool *mbuf_pool;
	unsigned int mbuf_count, cache_size;
	int nb_ports, portid;
	int retval;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	ret = parse_options(argc, argv);

	argc -= ret;
	argv += ret;

	if (options.packet_count < options.burst_size) {
		fprintf(stderr, "ERROR: packet_count %llu < burst_size %lu\n",
				options.packet_count, options.burst_size);
		usage(EXIT_FAILURE);
	}

	nb_ports = rte_eth_dev_count();
	options.lcore_count = rte_lcore_count();

	if (argc < nb_ports) {
		fprintf(stderr, "Not enough arguments; need IP config for %d ports\n",
				nb_ports);
		usage(EXIT_FAILURE);
	}

	interfaces = calloc(nb_ports, sizeof(*interfaces));
	if (!interfaces) {
		rte_exit(EXIT_FAILURE, "Cannot allocate interface table: %s\n",
						strerror(errno));
	}

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_count = 4 * nb_ports * options.burst_size;
	get_mempool_sizes(&mbuf_count, &cache_size);
	/* TODO: optimize this for a multi-socket system: create a mbuf_pool
	 * per CPU socket */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", mbuf_count,
		cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
						rte_strerror(rte_errno));

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++) {
		if (port_init(&interfaces[portid], portid, mbuf_pool,
					argv[portid + 1]) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n",
					portid);
		}
	}

	param.port = &interfaces[0];
	rte_spinlock_init(&param.lock);
	param.final_stats = &final_stats;
	memset(&final_stats, 0, sizeof(final_stats));
	final_stats.start_time = UINT64_MAX;
	final_stats.recv_count_histo = calloc(options.burst_size,
			sizeof(*final_stats.recv_count_histo));
	if (!final_stats.recv_count_histo) {
		rte_exit(EXIT_FAILURE, "%s\n", strerror(errno));
	}

	if (argc >= nb_ports + 2) {
		if (parse_ipv4_address(argv[nb_ports + 1],
					&param.dest_ipv4_addr, NULL) != 0) {
			fprintf(stderr, "Could not parse client IP address %s\n",
					argv[nb_ports + 1]);
			usage(EXIT_FAILURE);
		}

		lookup_ether_addr(param.port, param.dest_ipv4_addr,
				&param.dest_ether_addr);
	} else {
		param.dest_ipv4_addr = IPv4(0, 0, 0, 0);
		await_single_arp(param.port);
	}

	if (rte_lcore_count() < 2) {
		rte_exit(EXIT_FAILURE, "This benchmark requires at least 2 lcores\n");
	}

	retval = rte_eal_mp_remote_launch(do_lcore_work, &param,
			SKIP_MASTER);
	if (retval != 0) {
		rte_exit(EXIT_FAILURE, "Could not launch main work task: %s\n",
				strerror(errno));
	}
	return do_master_lcore_work(&final_stats);
}
