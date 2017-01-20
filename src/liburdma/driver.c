/* driver.c */

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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <unistd.h>

#include <infiniband/driver.h>

#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/errno.h>
#include <netlink/socket.h>
#include <netlink/utils.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>

#include "config_file.h"
#include "interface.h"
#include "urdma_kabi.h"
#include "util.h"

#define RX_DESC_COUNT_MAX 512
#define TX_DESC_COUNT_MAX 512

static struct usiw_driver *driver;

void
driver_add_context(struct usiw_context *ctx)
{
	LIST_INSERT_HEAD(&driver->ctxs, ctx, driver_entry);
} /* driver_add_context */

void
start_progress_thread(void)
{
	sem_post(&driver->go);
} /* start_progress_thread */


static int
setup_nl_sock(void)
{
	int rv;

	driver->sock = nl_socket_alloc();
	if (!driver->sock)
		return -1;
	if ((rv = nl_connect(driver->sock, NETLINK_ROUTE)))
		goto free_socket;

	rv = rtnl_link_alloc_cache(driver->sock,
			AF_UNSPEC, &driver->link_cache);
	if (rv)
		goto free_socket;
	rv = rtnl_addr_alloc_cache(driver->sock,
			&driver->addr_cache);
	if (rv)
		goto free_link_cache;

	return 0;

free_link_cache:
	nl_cache_free(driver->link_cache);
free_socket:
	nl_socket_free(driver->sock);

	return -1;
} /* setup_netlink */


static int
get_ipv4addr(int portid, uint32_t *result)
{
	char kni_name[RTE_KNI_NAMESIZE];
	struct rtnl_link *link;
	struct nl_cache *subset;
	struct rtnl_addr *hints, *addr;
	struct nl_addr *local;
	int ifindex;
	int rv = -1;

	if (!driver->sock) {
		if (setup_nl_sock()) {
			return -1;
		}
	}

	snprintf(kni_name, RTE_KNI_NAMESIZE, "kni%u", portid);
	link = rtnl_link_get_by_name(driver->link_cache, kni_name);
	if (!link) {
		return -1;
	}
	ifindex = rtnl_link_get_ifindex(link);
	rtnl_link_put(link);

	/* Create an address object with only the ifindex defined.  We can then
	 * use this partial object as a filter to only select address entries
	 * with this interface index, which effectively gets us every IP address
	 * assigned to this interface. */
	hints = rtnl_addr_alloc();
	if (!hints) {
		fprintf(stderr, "Could not allocate network address hints\n");
		return -1;
	}
	rtnl_addr_set_ifindex(hints, ifindex);
	rtnl_addr_set_family(hints, AF_INET);
	subset = nl_cache_subset(driver->addr_cache, (struct nl_object *)hints);
	rtnl_addr_put(hints);
	addr = (struct rtnl_addr *)nl_cache_get_first(subset);
	if (!addr) {
		goto free_hints;
	}

	local = rtnl_addr_get_local(addr);
	memcpy(result, nl_addr_get_binary_addr(local), sizeof(*result));
	rv = 0;

free_hints:
	nl_cache_put(subset);

	return rv;
} /* get_ipaddr */


static struct ibv_device *
usiw_driver_init(int portid)
{
	static const uint32_t tx_checksum_offloads
		= DEV_TX_OFFLOAD_UDP_CKSUM|DEV_TX_OFFLOAD_IPV4_CKSUM;

	struct usiw_device *dev;
	struct rte_eth_dev_info info;
	char name[RTE_MEMPOOL_NAMESIZE];

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

	dev->portid = portid;
	rte_eth_macaddr_get(dev->portid, &dev->ether_addr);
	if (get_ipv4addr(dev->portid, &dev->ipv4_addr)) {
		free(dev);
		errno = ENOENT;
		return NULL;
	}
	rte_eth_dev_info_get(dev->portid, &info);
	dev->rx_desc_count = info.rx_desc_lim.nb_max;
	if (dev->rx_desc_count > RX_DESC_COUNT_MAX) {
		dev->rx_desc_count = RX_DESC_COUNT_MAX;
	}

	if ((info.tx_offload_capa & tx_checksum_offloads)
						== tx_checksum_offloads) {
		dev->flags |= port_checksum_offload;
	}
	if (rte_eth_dev_filter_supported(dev->portid,
						RTE_ETH_FILTER_FDIR) == 0) {
		dev->flags |= port_fdir;
	}

	snprintf(name, RTE_MEMPOOL_NAMESIZE, "port_%u_rx_mempool", portid);
	dev->rx_mempool = rte_mempool_lookup(name);
	if (!dev->rx_mempool) {
		free(dev);
		errno = ENOENT;
		return NULL;
	}

	snprintf(name, RTE_MEMPOOL_NAMESIZE, "port_%u_tx_mempool", portid);
	dev->tx_ddp_mempool = dev->tx_hdr_mempool = rte_mempool_lookup(name);
	if (!dev->tx_ddp_mempool) {
		free(dev);
		errno = ENOENT;
		return NULL;
	}

	dev->urdmad_fd = driver->urdmad_fd;

	return &dev->vdev.device;
} /* usiw_driver_init */


static char *
get_argv0(void)
{
	enum { prctl_name_size = 16 };
	char name[prctl_name_size];

	if (prctl(PR_GET_NAME, (uintptr_t)name, 0, 0, 0) < 0) {
		return strdup("dummy");
	}
	return strdup(name);
} /* get_argv0 */


static int
open_socket(int family, int socktype, int proto)
{
	int ret, fd;

#if HAVE_DECL_SOCK_CLOEXEC
	/* Atomically set the FD_CLOEXEC flag when creating the socket */
	fd = socket(family, socktype | SOCK_CLOEXEC, proto);
	if (fd >= 0 || (errno != EINVAL && errno != EPROTOTYPE))
		return fd;
#endif

	/* The system doesn't support SOCK_CLOEXEC; set the flag using
	 * fcntl() and live with the small window for a race with fork+exec
	 * from another thread */
	fd = socket(family, socktype, proto);
	if (fd < 0)
		return fd;

	ret = fcntl(fd, F_GETFD);
	if (ret < 0)
		goto close_fd;
	ret = fcntl(fd, F_SETFD, ret | FD_CLOEXEC);
	if (ret < 0)
		goto close_fd;
	return fd;

close_fd:
	close(fd);
	return ret;
} /* open_socket */


static int
setup_socket(const char *sock_name)
{
	struct sockaddr_un addr;
	int fd, flags, ret;

	if (strlen(sock_name) >= sizeof(addr.sun_path) - 1) {
		fprintf(stderr, "Invalid socket path %s: too long\n",
				sock_name);
		errno = EINVAL;
		return -1;
	}

	fd = open_socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		fprintf(stderr, "Could not create socket: %s\n",
				strerror(errno));
		return fd;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path));
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Could not connect to %s: %s\n",
				addr.sun_path, strerror(errno));
		goto err;
	}

	return fd;

err:
	close(fd);
	return -1;
} /* setup_socket */


static void
free_arg_list(int argc, char **argv)
{
	for (int i = 0; i < argc; ++i) {
		free(argv[i]);
	}
	free(argv);
} /* free_arg_list */


/** Parses the config file and fills in sock_name with the name of the socket to
 * use, and eal_argv with the user-requested argument, in addition to the
 * required arguments "--proc-type=secondary" and "-c".  (*eal_argv)[*eal_argc -
 * 1] is left NULL and must be filled in by the caller with the coremask to use,
 * which is determined by the socket identified by *sock_name. */
static bool
do_config(char **sock_name, int *eal_argc, char ***eal_argv)
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

	*sock_name = urdma__config_file_get_sock_name(&config);
	if (!*sock_name) {
		fprintf(stderr, "Could not parse socket name from config file: %s\n",
				strerror(errno));
		goto close_config;
	}

	/* Need to allocate argc + 4 elements for EAL args
	 * argc returned by urdma__config_file_get_eal_argc does not include
	 * process name
	 *
	 * argv array must contain:
	 * [0] "<procname>"
	 * [1..argc-1] "<argv>"
	 * [argc] "--proc-type=secondary"
	 * [argc+1] "-c"
	 * [argc+2] "<coremask>"
	 * [argc+3] NULL
	 */
	*eal_argc = urdma__config_file_get_eal_args(&config, NULL);
	*eal_argv = calloc(*eal_argc + 4, sizeof(**eal_argv));
	if (!(*eal_argv)) {
		goto free_sock_name;
	}

	if (urdma__config_file_get_eal_args(&config, *eal_argv) < 0) {
		fprintf(stderr, "Could not parse EAL arguments from config file: %s\n",
				strerror(errno));
		goto free_eal_args;
	}
	if (!((*eal_argv)[*eal_argc] = strdup("--proc-type=secondary"))) {
		goto free_eal_args;
	}
	(*eal_argc)++;
	if (!((*eal_argv)[*eal_argc] = strdup("-c"))) {
		goto free_eal_args;
	}
	*eal_argc += 2;
	result = true;
	goto close_config;

free_eal_args:
	free_arg_list(*eal_argc, *eal_argv);
free_sock_name:
	free(*sock_name);
close_config:
	urdma__config_file_close(&config);
out:
	return result;
} /* do_config */


static int
do_hello(void)
{
	struct urdmad_sock_hello_req req;
	struct urdmad_sock_hello_resp resp;
	int i;
	ssize_t ret;

	memset(&req, 0, sizeof(req));
	req.hdr.opcode = rte_cpu_to_be_32(urdma_sock_hello_req);
	req.req_lcore_count = rte_cpu_to_be_32(2);
	ret = send(driver->urdmad_fd, &req, sizeof(req), 0);
	if (ret != sizeof(req)) {
		return -1;
	}
	ret = recv(driver->urdmad_fd, &resp, sizeof(resp), 0);
	if (ret != sizeof(resp)) {
		return -1;
	}

	for (i = 0; i < RTE_DIM(resp.lcore_mask); i++) {
		driver->lcore_mask[i] = rte_be_to_cpu_32(resp.lcore_mask[i]);
	}

	return 0;
} /* do_hello */


/** Formats the coremask as a hexadecimal string.  Array size is the number of
 * uint32_t elements in coremask. */
static char *
format_coremask(uint32_t *coremask, size_t array_size)
{
	static const size_t width = 2 * sizeof(*coremask);
	char *p, *result;
	int i;

	/* "0xabcdabcdabcdabcd" */
	p = result = malloc(width * array_size + 3);
	if (!result) {
		return NULL;
	}
	*(p++) = '0';
	*(p++) = 'x';
	for (i = array_size - 1; i >= 0; i--) {
		snprintf(p, width + 1, "%0*" PRIx32, (int)width, coremask[i]);
		p += width;
	}
	*p = '\0';

	return result;
} /* format_coremask */


static void
do_init_driver(void)
{
	char **eal_argv;
	char **argv_copy;
	char *sock_name;
	char *p;
	int eal_argc, ret;

	if (!do_config(&sock_name, &eal_argc, &eal_argv)) {
		return;
	}

	driver = calloc(1, sizeof(*driver));
	if (!driver)
		goto err;
	LIST_INIT(&driver->ctxs);

	driver->urdmad_fd = setup_socket(sock_name);
	if (driver->urdmad_fd < 0)
		goto err;
	free(sock_name);
	if (do_hello() < 0) {
		fprintf(stderr, "Could not setup socket: %s\n",
				strerror(errno));
		goto err;
	}
	eal_argv[eal_argc - 1] = format_coremask(driver->lcore_mask,
						 RTE_DIM(driver->lcore_mask));

	/* rte_eal_init does nothing and returns -1 if it was already called
	 * (although this behavior is not documented).  rte_eal_init also
	 * crashes the whole program if it fails for any other reason, so we
	 * can depend on a negative return code meaning that rte_eal_init was
	 * already called.  This means that a program can accept the default
	 * EAL configuration by not calling rte_eal_init() before calling into
	 * a verbs function, allowing us to work with unmodified verbs
	 * applications.
	 *
	 * Additionally, rte_eal_init mutates the argument list.  In particular,
	 * it sets eal_argv[eal_argc - 1] = eal_argv[0], trying to be helpful if
	 * an application wishes to parse its own argument list.  To be
	 * completely safe, we make a copy of the argument list, and free all
	 * elements of the copy before freeing the argument list itself. */
	argv_copy = malloc(eal_argc * sizeof(*eal_argv));
	if (argv_copy) {
		memcpy(argv_copy, eal_argv, eal_argc * sizeof(*eal_argv));
	}
	rte_eal_init(eal_argc, eal_argv);
	if (argv_copy) {
		free_arg_list(eal_argc, argv_copy);
	}
	free(eal_argv);

	if (sem_init(&driver->go, 0, 0))
		goto close_fd;
	ret = rte_eal_remote_launch(kni_loop, driver,
			rte_get_next_lcore(rte_get_master_lcore(), 1, 1));
	if (ret) {
		goto destroy_sem;
	}
	return;

destroy_sem:
	sem_destroy(&driver->go);
close_fd:
	close(driver->urdmad_fd);
err:
	free(driver);
	driver = NULL;
}


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
