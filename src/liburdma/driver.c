/* driver.c */

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
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include <infiniband/driver.h>

#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include "config_file.h"
#include "interface.h"
#include "kni.h"
#include "urdma_kabi.h"
#include "util.h"

#define RX_DESC_COUNT_MAX 512
#define TX_DESC_COUNT_MAX 512

static struct usiw_driver *driver;

static struct ibv_device *
usiw_driver_init(int portid)
{
	struct usiw_device *dev;
	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		errno = ENOMEM;
		return NULL;
	}
	dev->vdev.sz = sizeof(struct verbs_device);
	dev->vdev.size_of_context = sizeof(struct usiw_context)
						- sizeof(struct verbs_context);
	dev->vdev.init_context = usiw_init_context;
	dev->vdev.uninit_context = usiw_uninit_context;

	dev->port = &driver->ports[portid];

	return &dev->vdev.device;
} /* usiw_driver_init */

static int
setup_base_filters(struct usiw_port *iface)
{
	struct rte_eth_fdir_filter_info filter_info;
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
		RTE_LOG(CRIT, USER1, "Could not set fdir filter info: %s\n",
				strerror(-retval));
	}
	return retval;
} /* setup_base_filters */


static int
usiw_port_init(struct usiw_port *iface)
{
	static const uint32_t rx_checksum_offloads
		= DEV_RX_OFFLOAD_UDP_CKSUM|DEV_RX_OFFLOAD_IPV4_CKSUM;
	static const uint32_t tx_checksum_offloads
		= DEV_TX_OFFLOAD_UDP_CKSUM|DEV_TX_OFFLOAD_IPV4_CKSUM;

	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_conf port_conf;
	int socket_id;
	int retval;
	uint16_t q;

	/* *** FIXME: *** LOTS of resource leaks on failure */

	socket_id = rte_eth_dev_socket_id(iface->portid);

	if (iface->portid >= rte_eth_dev_count())
		return -EINVAL;

	memset(&port_conf, 0, sizeof(port_conf));
	iface->flags = 0;
	port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
	if ((iface->dev_info.tx_offload_capa & tx_checksum_offloads)
			== tx_checksum_offloads) {
		iface->flags |= port_checksum_offload;
	}
	if ((iface->dev_info.rx_offload_capa & rx_checksum_offloads)
			== rx_checksum_offloads) {
		port_conf.rxmode.hw_ip_checksum = 1;
	}
	if (rte_eth_dev_filter_supported(iface->portid,
						RTE_ETH_FILTER_FDIR) == 0) {
		iface->flags |= port_fdir;
		port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
		port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
		port_conf.fdir_conf.mask.ipv4_mask.src_ip = IPv4(0, 0, 0, 0);
		port_conf.fdir_conf.mask.ipv4_mask.dst_ip
						= IPv4(255, 255, 255, 255);
		port_conf.fdir_conf.mask.src_port_mask = 0;
		port_conf.fdir_conf.mask.dst_port_mask = UINT16_MAX;
	} else {
		port_conf.fdir_conf.mode = RTE_FDIR_MODE_NONE;
	}
	iface->max_qp = DPDKV_MAX_QP;
	if (iface->max_qp > iface->dev_info.max_rx_queues) {
		iface->max_qp = iface->dev_info.max_rx_queues;
	}
	if (iface->max_qp > iface->dev_info.max_tx_queues) {
		iface->max_qp = iface->dev_info.max_tx_queues;
	}

	/* TODO: Do performance testing to determine optimal descriptor
	 * counts */
	/* FIXME: Retry mempool allocations with smaller amounts until it
	 * succeeds, and then base max_qp and rx/tx_desc_count based on that */
	iface->rx_desc_count = iface->dev_info.rx_desc_lim.nb_max;
	if (iface->rx_desc_count > RX_DESC_COUNT_MAX) {
		iface->rx_desc_count = RX_DESC_COUNT_MAX;
	}
	iface->tx_desc_count = iface->dev_info.tx_desc_lim.nb_max;
	if (iface->tx_desc_count > TX_DESC_COUNT_MAX) {
		iface->tx_desc_count = TX_DESC_COUNT_MAX;
	}

	snprintf(name, RTE_RING_NAMESIZE,
			"port_%u_qp_ring", iface->portid);
	iface->avail_qp = rte_ring_create(name, iface->max_qp,
			SOCKET_ID_ANY, 0);
	if (!iface->avail_qp) {
		rte_exit(EXIT_FAILURE, "Cannot allocate QP ring: %s\n",
				rte_strerror(rte_errno));
	}

	iface->qp = rte_calloc("urdma_qp", iface->max_qp + 1,
			sizeof(*iface->qp), 0);
	if (!iface->qp) {
		rte_exit(EXIT_FAILURE, "Cannot allocate QP array: %s\n",
				rte_strerror(rte_errno));
	}
	for (q = 0; q < iface->max_qp; ++q) {
		iface->qp[q + 1].tx_queue = q + 1;
		iface->qp[q + 1].rx_queue = q + 1;
		rte_ring_enqueue(iface->avail_qp, &iface->qp[q + 1]);
	}

	snprintf(name, RTE_MEMPOOL_NAMESIZE,
			"port_%u_rx_mempool", iface->portid);
	iface->rx_mempool = rte_pktmbuf_pool_create(name,
		2 * iface->max_qp * iface->rx_desc_count,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
	if (iface->rx_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create rx mempool with %u mbufs: %s\n",
				2 * iface->max_qp * iface->rx_desc_count,
				rte_strerror(rte_errno));

	snprintf(name, RTE_MEMPOOL_NAMESIZE,
			"port_%u_tx_mempool", iface->portid);
	iface->tx_ddp_mempool = rte_pktmbuf_pool_create(name,
		2 * iface->max_qp * iface->tx_desc_count,
		0, sizeof(struct pending_datagram_info),
		RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
	if (iface->tx_ddp_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create tx mempool with %u mbufs: %s\n",
				2 * iface->max_qp * iface->tx_desc_count,
				rte_strerror(rte_errno));

	/* FIXME: make these actually separate */
	iface->tx_hdr_mempool = iface->tx_ddp_mempool;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(iface->portid, iface->max_qp,
			iface->max_qp, &port_conf);
	if (retval != 0)
		return retval;

	rte_eth_promiscuous_disable(iface->portid);

	/* Set up control RX queue */
	retval = rte_eth_rx_queue_setup(iface->portid, 0, iface->rx_desc_count,
			socket_id, NULL, iface->rx_mempool);
	if (retval < 0)
		return retval;

	/* Data RX queue startup is deferred */
	memcpy(&rxconf, &iface->dev_info.default_rxconf, sizeof(rxconf));
	rxconf.rx_deferred_start = 1;
	for (q = 1; q < iface->max_qp; q++) {
		retval = rte_eth_rx_queue_setup(iface->portid, q,
				iface->rx_desc_count, socket_id, &rxconf,
				iface->rx_mempool);
		if (retval < 0)
			return retval;
	}

	/* Set up control TX queue */
	retval = rte_eth_tx_queue_setup(iface->portid, 0, iface->tx_desc_count,
			socket_id, NULL);
	if (retval < 0)
		return retval;

	/* Data TX queue requires checksum offload, and startup is deferred */
	memcpy(&txconf, &iface->dev_info.default_txconf, sizeof(txconf));
	txconf.txq_flags = ETH_TXQ_FLAGS_NOVLANOFFL
			| ETH_TXQ_FLAGS_NOXSUMSCTP
			| ETH_TXQ_FLAGS_NOXSUMTCP;
	if (!(iface->flags & port_checksum_offload)) {
		RTE_LOG(DEBUG, USER1, "Port %u does not support checksum offload; disabling\n",
				iface->portid);
		txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMUDP;
	}
	txconf.tx_deferred_start = 1;
	for (q = 1; q < iface->max_qp; q++) {
		retval = rte_eth_tx_queue_setup(iface->portid, q,
				iface->tx_desc_count, socket_id, &txconf);
		if (retval < 0)
			return retval;
	}

	if (iface->flags & port_fdir) {
		retval = setup_base_filters(iface);
		if (retval < 0) {
			return retval;
		}
	}

	retval = usiw_port_setup_kni(iface);
	if (retval < 0) {
		return retval;
	}

	return rte_eth_dev_start(iface->portid);
} /* usiw_port_init */


static void
free_arg_list(int argc, char **argv)
{
	for (int i = 0; i < argc; ++i) {
		free(argv[i]);
	}
	free(argv);
} /* free_arg_list */


static bool
do_config(int *eal_argc, char ***eal_argv, int *port_count,
					struct usiw_port_config **port_config)
{
	struct usiw_config config;
	bool result = false;
	int ret;

	ret = urdma__config_file_open(&config);
	if (ret < 0) {
		fprintf(stderr, "Could not read config file: %s\n",
				strerror(errno));
		goto out;
	}

	*port_count = urdma__config_file_get_ports(&config, port_config);
	if (!(*port_count)) {
		goto close_config;
	}

	/* Need to allocate argc + 2 elements for EAL args
	 * argc returned by urdma__config_file_get_eal_argc does not include
	 * process name
	 *
	 * argv array must contain:
	 * [0] "<procname>"
	 * [1..argc-1] "<argv>"
	 * [argc] NULL
	 */
	*eal_argc = urdma__config_file_get_eal_args(&config, NULL);
	*eal_argv = calloc(*eal_argc + 2, sizeof(**eal_argv));
	if (!(*eal_argv)) {
		goto free_ports;
	}

	if (urdma__config_file_get_eal_args(&config, *eal_argv) < 0) {
		fprintf(stderr, "Could not parse EAL arguments from config file: %s\n",
				strerror(errno));
		goto free_eal_args;
	}
	result = true;
	goto close_config;

free_eal_args:
	free_arg_list(*eal_argc, *eal_argv);
free_ports:
	free(*port_config);
close_config:
	urdma__config_file_close(&config);
out:
	return result;
} /* do_config */


static void
do_init_driver(void)
{
	struct usiw_port_config *port_config;
	char **eal_argv;
	int eal_argc;
	int portid, port_count;
	int retval;

	if (!do_config(&eal_argc, &eal_argv, &port_count, &port_config)) {
		return;
	}

	/* rte_eal_init does nothing and returns -1 if it was already called
	 * (although this behavior is not documented).  rte_eal_init also
	 * crashes the whole program if it fails for any other reason, so we
	 * can depend on a negative return code meaning that rte_eal_init was
	 * already called.  This means that a program can accept the default
	 * EAL configuration by not calling rte_eal_init() before calling into
	 * a verbs function, allowing us to work with unmodified verbs
	 * applications. */
	rte_eal_init(eal_argc, eal_argv);
	free_arg_list(eal_argc, eal_argv);

	if (rte_eth_dev_count() < port_count) {
		errno = ENODEV;
		goto err;
	}

	driver = calloc(1, sizeof(*driver)
			+ port_count * sizeof(struct usiw_port));
	if (!driver) {
		errno = ENOMEM;
		goto err;
	}
	driver->port_count = port_count;
	rte_kni_init(driver->port_count);

	driver->progress_lcore = 1;
	for (portid = 0; portid < driver->port_count; ++portid) {
		driver->ports[portid].portid = portid;
		driver->ports[portid].ctx = NULL;
		rte_eth_macaddr_get(portid,
				&driver->ports[portid].ether_addr);
		rte_eth_dev_info_get(portid, &driver->ports[portid].dev_info);

		retval = usiw_port_init(&driver->ports[portid]);
		if (retval < 0) {
			RTE_LOG(DEBUG, USER1, "Could not initialize port %u: %s\n",
					portid, strerror(-retval));
			errno = -retval;
			goto free_driver;
		}
	}
	rte_eal_remote_launch(kni_loop, driver, driver->progress_lcore);
	/* FIXME: cannot free driver beyond this point since it is being
	 * accessed by the kni_loop */
	retval = usiw_driver_setup_netlink(driver);
	if (retval < 0) {
		RTE_LOG(DEBUG, USER1, "Could not setup KNI context: %s\n",
					strerror(-retval));
		errno = -retval;
		driver = NULL;
		return;
	}
	for (portid = 0; portid < driver->port_count; portid++) {
		retval = usiw_set_ipv4_addr(driver, &driver->ports[portid],
				&port_config[portid]);
		if (retval < 0) {
			RTE_LOG(DEBUG, USER1, "Could not set port %u IPv4 address: %s\n",
					portid, strerror(-retval));
			errno = -retval;
			driver = NULL;
			return;
		}
	}
	return;

free_driver:
	free(driver);
err:
	free(port_config);
	driver = NULL;
} /* do_init_driver */


static struct verbs_device *
usiw_verbs_driver_init(const char *uverbs_sys_path, int abi_version)
{
	static pthread_once_t driver_init_once = PTHREAD_ONCE_INIT;
	static const char siw_node_desc[] = URDMA_NODE_DESC;
	struct ibv_device *ibdev;
	char siw_devpath[IBV_SYSFS_PATH_MAX];
	char node_desc[24];
	char value[16];
	int portid;

	pthread_once(&driver_init_once, &do_init_driver);
	if (!driver) {
		/* driver initialization failed */
		return NULL;
	}

	if (ibv_read_sysfs_file(uverbs_sys_path, "ibdev",
				value, sizeof value) < 0)
		return NULL;

	if (sscanf(value, URDMA_DEV_PREFIX "%d", &portid) < 1)
		return NULL;

	memset(siw_devpath, 0, IBV_SYSFS_PATH_MAX);

	snprintf(siw_devpath, IBV_SYSFS_PATH_MAX, "%s/class/infiniband/%s",
		 ibv_get_sysfs_path(), value);

	if (ibv_read_sysfs_file(siw_devpath, "node_desc",
				node_desc, sizeof node_desc) < 0)
		return NULL;

	/* Verify node description to ensure that we are talking to the right
	 * kernel driver */
	if (strncmp(siw_node_desc, node_desc, strlen(siw_node_desc)))
		return NULL;

	if (abi_version < URDMA_ABI_VERSION_MIN
			|| abi_version > URDMA_ABI_VERSION_MAX) {
		return NULL;
	}

	ibdev = usiw_driver_init(portid);
	return ibdev ? verbs_get_device(ibdev) : NULL;
} /* usiw_verbs_driver_init */


static __attribute__((constructor)) void
usiw_register_driver(void)
{
	/* We cannot access /proc/self/pagemap as non-root if we are not
	 * dumpable
	 *
	 * We do require CAP_NET_ADMIN but there should be minimal risk from
	 * making ourselves dumpable, compared to requiring root priviliges to
	 * run */
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
		perror("WARNING: set dumpable flag failed; DPDK may not initialize properly");
	}

	verbs_register_driver("urdma", &usiw_verbs_driver_init);
} /* usiw_register_driver */
