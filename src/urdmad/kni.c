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

#include <assert.h>
#include <rte_config.h>
#include <rte_kni.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#ifndef AVOID_NET_IF_H
#include <net/if.h>
#endif

#include "config_file.h"
#include "interface.h"
#include "kni.h"

/** nl_errno is expected to be the negated errno value. */
static int
nlerr_to_syserr(int nl_errno)
{
	switch (-nl_errno) {
	case NLE_SUCCESS:
		return 0;
	case NLE_FAILURE:
	case NLE_DUMP_INTR:
		return -EIO;
	case NLE_INTR:
		return -EINTR;
	case NLE_BAD_SOCK:
		return -ENOTSOCK;
	case NLE_AGAIN:
		return -EAGAIN;
	case NLE_NOMEM:
		return -ENOMEM;
	case NLE_EXIST:
		return -EEXIST;
	case NLE_INVAL:
	case NLE_PARSE_ERR:
		return -EINVAL;
	case NLE_RANGE:
		return -ERANGE;
	case NLE_MSGSIZE:
		return -EMSGSIZE;
	case NLE_OPNOTSUPP:
		return -EOPNOTSUPP;
	case NLE_AF_NOSUPPORT:
	case NLE_AF_MISMATCH:
		return -EAFNOSUPPORT;
	case NLE_OBJ_NOTFOUND:
	case NLE_NOATTR:
		return -ENOENT;
	case NLE_BUSY:
		return -EBUSY;
	case NLE_PERM:
		return -EPERM;
	case NLE_NODEV:
		return -ENODEV;
	case NLE_NOACCESS:
		return -EACCES;
	case NLE_IMMUTABLE:
		return -EROFS;
	default:
		return -EPROTO;
	}
} /* nlerr_to_syserr */

static struct rtnl_addr *
get_addr(struct usiw_port *port, const char *ipv4_address_str)
{
	struct rtnl_addr *addr;
	struct nl_addr *laddr;
	void *ptr;
	int ret;

	addr = rtnl_addr_alloc();
	if (!addr) {
		errno = ENOMEM;
		return NULL;
	}

	ret = nl_addr_parse(ipv4_address_str, AF_INET, &laddr);
	if (ret < 0) {
		rtnl_addr_put(addr);
		errno = nlerr_to_syserr(ret);
		return NULL;
	}

	ptr = nl_addr_get_binary_addr(laddr);
	memcpy(&port->ipv4_addr, ptr, sizeof(port->ipv4_addr));
	port->ipv4_prefix_len = nl_addr_get_prefixlen(laddr);

	rtnl_addr_set_local(addr, laddr);

	/* TODO: do I need to do this?
	nl_addr_put(laddr);
	 */
	return addr;
} /* get_addr */

static int
port_set_mac_addr(uint8_t port_id, struct rtnl_link *link)
{
	struct ether_addr bin_addr;
	struct nl_addr *addr;

	rte_eth_macaddr_get(port_id, &bin_addr);
	addr = nl_addr_build(AF_UNSPEC, &bin_addr, sizeof(bin_addr));
	if (!addr) {
		return -ENOMEM;
	}
	rtnl_link_set_addr(link, addr);
	//nl_addr_put(addr);
	return 0;
} /* port_set_mac_addr */

int
usiw_set_ipv4_addr(struct usiw_driver *driver, struct usiw_port *port,
		struct usiw_port_config *config)
{
	struct rtnl_addr *addr;
	struct rtnl_link *link;
	struct nl_cache *link_cache;
	struct nl_sock *sock;
	int ifindex, ret;

	sock = driver->nl_sock;
	link_cache = driver->nl_link_cache;
	assert(sock != NULL);
	assert(link_cache != NULL);
	addr = get_addr(port, config->ipv4_address);

	link = rtnl_link_get_by_name(link_cache, port->kni_name);
	if (!link) {
		ret = -ENODEV;
		goto unref_addr;
	}
	ifindex = rtnl_link_get_ifindex(link);
	if (!ifindex) {
		ret = -ENODEV;
		goto unref_link;
	}

	rtnl_addr_set_ifindex(addr, ifindex);
	ret = rtnl_addr_add(sock, addr, 0);
	if (ret < 0) {
		ret = nlerr_to_syserr(ret);
	}

	port_set_mac_addr(port->portid, link);
	rtnl_link_set_flags(link, IFF_UP);
	ret = rtnl_link_change(sock, link, link, 0);
	if (ret != 0) {
		ret = nlerr_to_syserr(ret);
		goto unref_link;
	}

unref_link:
	rtnl_link_put(link);
unref_addr:
	rtnl_addr_put(addr);

	return ret;
} /* usiw_set_ipv4_addr */

static int
usiw_port_change_mtu(uint8_t port_id, unsigned int new_mtu)
{
	RTE_LOG(NOTICE, USER1, "got KNI request to change port %" PRIu8 " MTU to %u\n",
			port_id, new_mtu);
	return rte_eth_dev_set_mtu(port_id, new_mtu);
} /* usiw_port_change_mtu */

static const char *
link_speed_str(uint8_t portid, struct rte_eth_link *link_info)
{
	const char *speed_str;

	switch (link_info->link_speed) {
	case ETH_SPEED_NUM_100G:
		speed_str = "100 Gbps";
		break;
	case ETH_SPEED_NUM_56G:
		speed_str = "56 Gbps";
		break;
	case ETH_SPEED_NUM_50G:
		speed_str = "50 Gbps";
		break;
	case ETH_SPEED_NUM_40G:
		speed_str = "40 Gbps";
		break;
	case ETH_SPEED_NUM_25G:
		speed_str = "25 Gbps";
		break;
	case ETH_SPEED_NUM_20G:
		speed_str = "20 Gbps";
		break;
	case ETH_SPEED_NUM_10G:
		speed_str = "10 Gbps";
		break;
	case ETH_SPEED_NUM_5G:
		speed_str = "5 Gbps";
		break;
	case ETH_SPEED_NUM_2_5G:
		speed_str = "2.5 Gbps";
		break;
	case ETH_SPEED_NUM_1G:
		speed_str = "1 Gbps";
		break;
	case ETH_SPEED_NUM_100M:
		speed_str = "100 Mbps";
		break;
	case ETH_SPEED_NUM_10M:
		speed_str = "10 Mbps";
		break;
	default:
		speed_str = "unknown";
		break;
	}
	return speed_str;
} /* link_speed_str */

static int
usiw_port_change_state(uint8_t port_id, uint8_t if_up)
{
	struct rte_eth_link link_info;
	const char *speed_str;
	uint16_t mtu;
	int ret;

	if (!if_up) {
		RTE_LOG(NOTICE, USER1, "port %" PRIu8 " state change to down\n",
			port_id);
		return -EBUSY;
	}

	ret = rte_eth_dev_get_mtu(port_id, &mtu);
	assert(ret == 0);
	rte_eth_link_get_nowait(port_id, &link_info);
	if (link_info.link_status) {
		speed_str = link_speed_str(port_id, &link_info);
		RTE_LOG(NOTICE, USER1, "port %" PRIu8 " up mtu=%" PRIu16 " speed %s\n",
				port_id, mtu, speed_str);
	} else {
		RTE_LOG(NOTICE, USER1, "port %" PRIu8 " down\n", port_id);
	}
	return 0;
} /* usiw_port_change_mtu */

int
usiw_port_setup_kni(struct usiw_port *port)
{
	struct rte_kni_conf kni_conf;
	struct rte_kni_ops ops;
	int ret;

	snprintf(port->kni_name, RTE_KNI_NAMESIZE, "kni%u", port->portid);

	memset(&kni_conf, 0, sizeof(kni_conf));
	strcpy(kni_conf.name, port->kni_name);
	kni_conf.group_id = port->portid;
	kni_conf.mbuf_size = 2048;
	kni_conf.addr = port->dev_info.pci_dev->addr;
	kni_conf.id = port->dev_info.pci_dev->id;

	port->kni = rte_kni_alloc(port->rx_mempool, &kni_conf, NULL);
	if (!port->kni) {
		return -EINVAL;
	}

	ops.port_id = port->portid;
	ops.change_mtu = &usiw_port_change_mtu;
	ops.config_network_if = &usiw_port_change_state;
	ret = rte_kni_register_handlers(port->kni, &ops);
	if (ret) {
		ret = -EINVAL;
	}

	return ret;
} /* usiw_port_setup_kni */


/** Do setup that can be done prior to bringing up the interface. */
int
usiw_driver_setup_netlink(struct usiw_driver *driver)
{
	int ret;

	driver->nl_sock = nl_socket_alloc();
	if (!driver->nl_sock) {
		return -ENOMEM;
	}

	ret = nl_connect(driver->nl_sock, NETLINK_ROUTE);
	if (ret < 0) {
		nl_socket_free(driver->nl_sock);
		fprintf(stderr, "nl_connect failed: %s\n",
				nl_geterror(ret));
		return nlerr_to_syserr(ret);
	}

	ret = rtnl_link_alloc_cache(driver->nl_sock, AF_UNSPEC,
			&driver->nl_link_cache);
	if (ret < 0 || !driver->nl_link_cache) {
		nl_socket_free(driver->nl_sock);
		ret = nlerr_to_syserr(ret);
	}

	return ret;
} /* usiw_driver_setup_netlink */
