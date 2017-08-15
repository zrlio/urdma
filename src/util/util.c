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
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

int
parse_ipv4_address(const char *str, uint32_t *address, int *prefix_len)
{
	char terminator[] = {'.', '.', '.', '/'};
	uint32_t tmp_address;
	char *endptr;
	int i;
	long v;

	if (!prefix_len) {
		terminator[3] = '\0';
	}

	tmp_address = 0;
	for (i = 0; i < 4; ++i) {
		errno = 0;
		v = strtol(str, &endptr, 10);
		if (errno != 0 || *endptr != terminator[i]
						|| v < 0 || v > 255) {
			return -EINVAL;
		}
		tmp_address = (tmp_address << 8) | (v & 0xff);
		str = endptr + 1;
	}

	if (!prefix_len) {
		*address = rte_cpu_to_be_32(tmp_address);
		return 0;
	}

	errno = 0;
	v = strtol(str, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || v < 8 || v > 32) {
		return -EINVAL;
	}

	*address = rte_cpu_to_be_32(tmp_address);
	*prefix_len = v;
	return 0;
} /* parse_ipv4_address */

struct flag_descr {
	uint32_t flag;
	const char *name;
};

static const struct flag_descr all_rx_capa[] = {
	{ .flag = DEV_RX_OFFLOAD_VLAN_STRIP, .name = "vlan_strip" },
	{ .flag = DEV_RX_OFFLOAD_IPV4_CKSUM, .name = "ipv4_cksum" },
	{ .flag = DEV_RX_OFFLOAD_UDP_CKSUM, .name = "udp_cksum" },
	{ .flag = DEV_RX_OFFLOAD_TCP_CKSUM, .name = "tcp_cksum" },
	{ .flag = DEV_RX_OFFLOAD_TCP_LRO, .name = "tcp_lro" },
	{ .flag = DEV_RX_OFFLOAD_QINQ_STRIP, .name = "qinq_strip" },
	{ .flag = 0, .name = NULL },
};

static const struct flag_descr all_tx_capa[] = {
	{ .flag = DEV_TX_OFFLOAD_VLAN_INSERT, .name = "vlan_insert" },
	{ .flag = DEV_TX_OFFLOAD_IPV4_CKSUM, .name = "ipv4_cksum" },
	{ .flag = DEV_TX_OFFLOAD_UDP_CKSUM, .name = "udp_cksum" },
	{ .flag = DEV_TX_OFFLOAD_TCP_CKSUM, .name = "tcp_cksum" },
	{ .flag = DEV_TX_OFFLOAD_SCTP_CKSUM, .name = "sctp_cksum" },
	{ .flag = DEV_TX_OFFLOAD_TCP_TSO, .name = "tcp_tso" },
	{ .flag = DEV_TX_OFFLOAD_UDP_TSO, .name = "udp_tso" },
	{ .flag = DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM, .name = "outer_ipv4_cksum" },
	{ .flag = DEV_TX_OFFLOAD_QINQ_INSERT, .name = "qinq_insert" },
	{ .flag = 0, .name = NULL },
};

static const struct flag_descr all_txq_flags[] = {
	{ .flag = ETH_TXQ_FLAGS_NOMULTSEGS, .name = "nomultsegs" },
	{ .flag = ETH_TXQ_FLAGS_NOREFCOUNT, .name = "norefcount" },
	{ .flag = ETH_TXQ_FLAGS_NOMULTMEMP, .name = "nomultmemp" },
	{ .flag = ETH_TXQ_FLAGS_NOVLANOFFL, .name = "novlanoffl" },
	{ .flag = ETH_TXQ_FLAGS_NOXSUMSCTP, .name = "noxsumsctp" },
	{ .flag = ETH_TXQ_FLAGS_NOXSUMUDP, .name = "noxsumudp" },
	{ .flag = ETH_TXQ_FLAGS_NOXSUMTCP, .name = "noxsumtcp" },
	{ .flag = 0, .name = NULL },
};

static const struct flag_descr all_speed_capa[] = {
	{ .flag = ETH_LINK_SPEED_FIXED, .name = "fixed" },
	{ .flag = ETH_LINK_SPEED_10M_HD, .name = "10M_HD" },
	{ .flag = ETH_LINK_SPEED_10M, .name = "10M" },
	{ .flag = ETH_LINK_SPEED_100M_HD, .name = "100M_HD" },
	{ .flag = ETH_LINK_SPEED_100M, .name = "100M" },
	{ .flag = ETH_LINK_SPEED_1G, .name = "1G" },
	{ .flag = ETH_LINK_SPEED_2_5G, .name = "2.5G" },
	{ .flag = ETH_LINK_SPEED_5G, .name = "5G" },
	{ .flag = ETH_LINK_SPEED_10G, .name = "10G" },
	{ .flag = ETH_LINK_SPEED_20G, .name = "20G" },
	{ .flag = ETH_LINK_SPEED_25G, .name = "25G" },
	{ .flag = ETH_LINK_SPEED_40G, .name = "40G" },
	{ .flag = ETH_LINK_SPEED_50G, .name = "50G" },
	{ .flag = ETH_LINK_SPEED_56G, .name = "56G" },
	{ .flag = ETH_LINK_SPEED_100G, .name = "100G" },
	{ .flag = 0, .name = NULL },
};

static void dump_flags(FILE *stream, const struct flag_descr *flags, uint32_t v)
{
	const struct flag_descr *ptr;
	const char *sep;

	fprintf(stream, "[");
	for (ptr = flags, sep = " "; ptr->flag != 0; ++ptr) {
		if (v & ptr->flag) {
			fprintf(stream, "%s\"%s\"", sep, ptr->name);
			sep = ", ";
		}
	}
	fprintf(stream, " ]");
} /* dump_flags */

void
thresh_dump_info(FILE *stream, struct rte_eth_thresh *thresh, int indent)
{
	fprintf(stream, "{\n%*c\"pthresh\": %" PRIu8 ",\n",
			2 * indent, ' ', thresh->pthresh);
	fprintf(stream, "%*c\"hthresh\": %" PRIu8 ",\n",
			2 * indent, ' ', thresh->hthresh);
	fprintf(stream, "%*c\"wthresh\": %" PRIu8 "\n",
			2 * indent, ' ', thresh->wthresh);
	fprintf(stream, "%*c}", 2 * indent - 2, ' ');
} /* thresh_dump_info */

void
txconf_dump_info(FILE *stream, struct rte_eth_txconf *conf, int indent)
{
	fprintf(stream, "{\n%*c\"tx_thresh\": ", 2 * indent, ' ');
	thresh_dump_info(stream, &conf->tx_thresh, indent + 1);
	fprintf(stream, ",\n%*c\"tx_rs_thresh\": %" PRIu16 ",\n",
			2 * indent, ' ', conf->tx_rs_thresh);
	fprintf(stream, "%*c\"tx_free_thresh\": %" PRIu16 ",\n",
			2 * indent, ' ', conf->tx_free_thresh);
	fprintf(stream, "%*c\"txq_flags\": ", 2 * indent, ' ');
	dump_flags(stream, all_txq_flags, conf->txq_flags);
	fprintf(stream, ",\n%*c\"tx_deferred_start\": %" PRIu8 "\n",
			2 * indent, ' ', conf->tx_deferred_start);
	fprintf(stream, "%*c}", 2 * indent - 2, ' ');
} /* rxconf_dump_info */

void
rxconf_dump_info(FILE *stream, struct rte_eth_rxconf *conf, int indent)
{
	fprintf(stream, "{\n%*c\"rx_thresh\": ", 2 * indent, ' ');
	thresh_dump_info(stream, &conf->rx_thresh, indent + 1);
	fprintf(stream, ",\n%*c\"rx_free_thresh\": %" PRIu16 ",\n",
			2 * indent, ' ', conf->rx_free_thresh);
	fprintf(stream, "%*c\"rx_drop_en\": %" PRIu8 ",\n",
			2 * indent, ' ', conf->rx_drop_en);
	fprintf(stream, "%*c\"rx_deferred_start\": %" PRIu8 "\n",
			2 * indent, ' ', conf->rx_deferred_start);
	fprintf(stream, "%*c}", 2 * indent - 2, ' ');
} /* rxconf_dump_info */

void
desc_lim_dump_info(FILE *stream, struct rte_eth_desc_lim *lim, int indent)
{
	fprintf(stream, "{\n%*c\"nb_max\": %" PRIu16 ",\n",
			2 * indent, ' ', lim->nb_max);
	fprintf(stream, "%*c\"nb_min\": %" PRIu16 ",\n",
			2 * indent, ' ', lim->nb_min);
	fprintf(stream, "%*c\"nb_align\": %" PRIu16 "\n",
			2 * indent, ' ', lim->nb_align);
	fprintf(stream, "%*c}", 2 * indent - 2, ' ');
} /* desc_lim_dump_info */

void
port_dump_info(FILE *stream, struct rte_eth_dev_info *info)
{
	fprintf(stream, "\"" PCI_PRI_FMT "\": {\n  \"driver_name\": %s,\n",
			info->pci_dev->addr.domain,
			info->pci_dev->addr.bus,
			info->pci_dev->addr.devid,
			info->pci_dev->addr.function,
			info->driver_name);
	fprintf(stream, "  \"if_index\": %u,\n",
			info->if_index);
	fprintf(stream, "  \"min_rx_bufsize\": %" PRIu32 ",\n",
			info->min_rx_bufsize);
	fprintf(stream, "  \"max_rx_pktlen\": %" PRIu32 ",\n",
			info->max_rx_pktlen);
	fprintf(stream, "  \"max_rx_queues\": %" PRIu16 ",\n",
			info->max_rx_queues);
	fprintf(stream, "  \"max_tx_queues\": %" PRIu16 ",\n",
			info->max_tx_queues);
	fprintf(stream, "  \"max_mac_addrs\": %" PRIu32 ",\n",
			info->max_mac_addrs);
	fprintf(stream, "  \"max_hash_mac_addrs\": %" PRIu32 ",\n",
			info->max_hash_mac_addrs);
	fprintf(stream, "  \"max_vfs\": %" PRIu16 ",\n", info->max_vfs);
	fprintf(stream, "  \"max_vmdq_pools\": %" PRIu32 ",\n",
			info->max_vmdq_pools);
	fprintf(stream, "  \"rx_offload_capa\": ");
	dump_flags(stream, all_rx_capa, info->rx_offload_capa);
	fprintf(stream, ",\n  \"tx_offload_capa\": ");
	dump_flags(stream, all_tx_capa, info->tx_offload_capa);
	fprintf(stream, ",\n  \"reta_size\": %" PRIu16 ",\n",
			info->reta_size);
	fprintf(stream, "  \"hash_key_size\": %" PRIu8 ",\n",
			info->hash_key_size);
	fprintf(stream, "  \"flow_type_rss_offloads\": %" PRIx64 ",\n",
			info->flow_type_rss_offloads);
	fprintf(stream, "  \"default_rxconf\": ");
	rxconf_dump_info(stream, &info->default_rxconf, 2);
	fprintf(stream, ",\n  \"default_txconf\": ");
	txconf_dump_info(stream, &info->default_txconf, 2);
	fprintf(stream, ",\n  \"vmdq_queue_base\": %" PRIu16 ",\n",
			info->vmdq_queue_base);
	fprintf(stream, "  \"vmdq_queue_num\": %" PRIu16 ",\n",
			info->vmdq_queue_num);
	fprintf(stream, "  \"vmdq_pool_base\": %" PRIu16 ",\n",
			info->vmdq_pool_base);
	fprintf(stream, "  \"rx_desc_lim\": ");
	desc_lim_dump_info(stream, &info->rx_desc_lim, 2);
	fprintf(stream, ",\n  \"tx_desc_lim\": ");
	desc_lim_dump_info(stream, &info->tx_desc_lim, 2);
	fprintf(stream, ",\n  \"speed_capa\": ");
	if (info->speed_capa == ETH_LINK_SPEED_AUTONEG) {
		fprintf(stderr, "\"autoneg\"");
	} else {
		dump_flags(stream, all_speed_capa, info->speed_capa);
	}
	fprintf(stream, "\n}");
} /* port_dump_info */
