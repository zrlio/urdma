/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
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

#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_ethdev.h>
#include <rte_pci.h>

#ifdef HAVE_UINT16_T_PORT_ID
typedef uint16_t dpdk_port_id_type;
#else
typedef uint8_t dpdk_port_id_type;
#endif

#ifdef RTE_ETH_NAME_MAX_LEN
static const size_t pci_addr_namebuf_size = RTE_ETH_NAME_MAX_LEN;
#else
/* maximum size of buffer to hold "0000:00:00.0" */
static const size_t pci_addr_namebuf_size = 13;
#endif

#ifdef NDEBUG
#define NDEBUG_UNUSED __attribute__((unused))
#else
#define NDEBUG_UNUSED
#endif

#define DO_WARN_ONCE(cond, var, format, ...) ({ \
	static bool var = false; \
	if ((cond) && !var) { \
		var = true; \
		RTE_LOG(WARNING, USER1, format, ##__VA_ARGS__); \
	}; cond; })

#define PASTE(x, y) x##y

/** Prints the given warning message (like fprintf(stderr, format, ...)) if cond
 * is true, but only once per execution. */
#define WARN_ONCE(cond, format, ...) \
	DO_WARN_ONCE(cond, PASTE(xyzwarn_, __LINE__), format, ##__VA_ARGS__)

int
parse_ipv4_address(const char *str, uint32_t *address, int *prefix_len);

void
port_dump_info(FILE *stream, uint16_t port_id);

#ifndef HAVE_RTE_ETH_DEV_GET_NAME_BY_PORT
static inline int
rte_eth_dev_get_name_by_port(uint16_t port_id, char *name)
{
	struct rte_eth_dev_info info;
	int ret;
	if ((ret = rte_eth_dev_info_get(port_id, &info)))
		return ret;
	return rte_pci_device_name(&info->pci_dev->addr, name,
				   pci_addr_namebuf_size);
}
#endif

#ifdef HAVE_RTE_ETH_DEV_GET_PORT_BY_NAME
static inline int
lookup_ethdev_by_pci_addr(struct rte_pci_addr *addr)
{
	char namebuf[pci_addr_namebuf_size];
	dpdk_port_id_type port_id;
	int ret;

	rte_pci_device_name(addr, namebuf, pci_addr_namebuf_size);
	ret = rte_eth_dev_get_port_by_name(namebuf, &port_id);
	if (!ret)
		return port_id;
	else
		return ret;
}
#else
static inline int
lookup_ethdev_by_pci_addr(struct rte_pci_addr *addr)
{
	struct rte_eth_dev_info info;
	int x, count;

	count = rte_eth_dev_count();
	for (x = 0; x < count; ++x) {
		if (!rte_eth_dev_is_valid_port(x))
			continue;
		rte_eth_dev_info_get(x, &info);
		if (!rte_eal_compare_pci_addr(addr, &info.pci_dev->addr)) {
			return x;
		}
	}
	return -ENODEV;
}
#endif

#endif
