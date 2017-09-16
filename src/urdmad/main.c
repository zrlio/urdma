/* src/urdmad/main.c */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Author: Patrick MacArthur <patrick@patrickmacarthur.net>
 *
 * Copyright (c) 2016-2017, University of New Hampshire
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_kni.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "config_file.h"
#include "interface.h"
#include "list.h"
#include "kni.h"
#include "util.h"
#include "urdmad_private.h"
#include "urdma_kabi.h"

/* ixgbe and e1000 drivers require space for a VLAN tag in the receive mbufs;
 * in the case of ixgbe this is twice the space of the VLAN header */
static const size_t urdma_vlan_space = 8;

static struct usiw_driver *driver;

static unsigned int core_avail;
static uint32_t core_mask[RTE_MAX_LCORE / 32];

static const unsigned int core_mask_shift = 5;
static const uint32_t core_mask_mask = 31;

static void init_core_mask(void)
{
	struct rte_config *config;
	unsigned int i;

	config = rte_eal_get_configuration();
	for (i = 0; i < RTE_MAX_LCORE; ++i) {
		if (!lcore_config[i].detected) {
			return;
		} else if (config->lcore_role[i] == ROLE_OFF) {
			core_mask[i >> core_mask_shift]
						|= 1 << (i & core_mask_mask);
			core_avail++;
		}
	}
	RTE_LOG(INFO, USER1, "%u cores available\n", core_avail);
} /* init_core_mask */


/** Allocates an array that can be used with reserve_cores().  The caller must
 * call free() when done with this array. */
static uint32_t *alloc_lcore_mask(void)
{
	return malloc(RTE_MAX_LCORE / sizeof(uint32_t));
} /* alloc_lcore_mask */


/** Reserve count lcores for the given process.  Expects out_mask to be a
 * zero-initialized bitmask that can hold RTE_MAX_LCORE bits; i.e., an array
 * with at least (RTE_MAX_LCORE / 32) uint32_t elements.  This can be done with
 * the alloc_lcore_mask() function. */
static bool reserve_cores(unsigned int count, uint32_t *out_mask)
{
	uint32_t bit;
	unsigned int i, j;

	RTE_LOG(DEBUG, USER1, "requesting %u cores; %u cores available\n",
			count, core_avail);
	if (count > core_avail) {
		return false;
	}

	for (i = 0, j = 0; i < count; ++i) {
		while (!core_mask[j]) {
			j++;
			assert(j < RTE_MAX_LCORE / 32);
		}
		bit = 1 << rte_bsf32(core_mask[j]);
		core_mask[j] &= ~bit;
		out_mask[j] |= bit;
	}

	core_avail -= count;
	return true;
} /* reserve_cores */


/** Returns count lcores from the given process.  Expects in_mask to be a
 * bitmask that can hold RTE_MAX_LCORE bits; i.e., an array with at least
 * (RTE_MAX_LCORE / 32) uint32_t elements, where each lcore being returned is
 * set to 1. */
static void return_lcores(uint32_t *in_mask)
{
	uint32_t tmp, bit;
	unsigned int i;

	for (i = 0; i < RTE_MAX_LCORE / (8 * sizeof(*in_mask)); ++i) {
		tmp = in_mask[i];
		while (tmp) {
			core_avail++;
			bit = 1 << rte_bsf32(tmp);
			tmp &= ~bit;
			core_mask[i] |= bit;
		}
	}
} /* return_lcores */


static void
return_qp(struct usiw_port *dev, struct urdmad_qp *qp)
{
	enum { mbuf_count = 4 };
	struct rte_eth_fdir_filter fdirf;
	struct rte_mbuf *mbuf[mbuf_count];
	int ret, count;

	LIST_REMOVE(qp, urdmad__entry);
	LIST_INSERT_HEAD(&dev->avail_qp, qp, urdmad__entry);

	if (dev->flags & port_fdir) {
		memset(&fdirf, 0, sizeof(fdirf));
		fdirf.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
		fdirf.input.flow.udp4_flow.ip.dst_ip = dev->ipv4_addr;
		fdirf.action.behavior = RTE_ETH_FDIR_ACCEPT;
		fdirf.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;
		fdirf.soft_id = qp->rx_queue;
		fdirf.action.rx_queue = qp->rx_queue;
		fdirf.input.flow.udp4_flow.dst_port = qp->local_udp_port;
		ret = rte_eth_dev_filter_ctrl(dev->portid,
				RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_DELETE,
				&fdirf);

		if (ret) {
			RTE_LOG(DEBUG, USER1, "Could not delete fdir filter for qp %" PRIu32 ": %s\n",
					qp->qp_id, rte_strerror(-ret));
		}

		/* Drain the queue of any outstanding messages. */
		count = 0;
		do {
			ret = rte_eth_rx_burst(dev->portid, qp->rx_queue,
					mbuf, mbuf_count);
			count += ret;
		} while (ret > 0);
		if (count > 0) {
			RTE_LOG(INFO, USER1, "Drained %d packets from qp %" PRIu32 "\n",
					count, qp->qp_id);
		}

		ret = rte_eth_dev_rx_queue_stop(dev->portid, qp->rx_queue);
		if (ret < 0 && ret != -ENOTSUP) {
			RTE_LOG(INFO, USER1, "Disable RX queue %u failed: %s\n",
					qp->rx_queue, rte_strerror(-ret));
		}

		ret = rte_eth_dev_tx_queue_stop(dev->portid, qp->tx_queue);
		if (ret < 0 && ret != -ENOTSUP) {
			RTE_LOG(INFO, USER1, "Disable RX queue %u failed: %s\n",
					qp->tx_queue, rte_strerror(-ret));
		}
	}
} /* return_qp */


static void
handle_qp_connected_event(struct urdma_qp_connected_event *event, size_t count)
{
	struct urdma_qp_rtr_event rtr_event;
	struct rte_eth_fdir_filter fdirf;
	struct rte_eth_rxq_info rxq_info;
	struct rte_eth_txq_info txq_info;
	struct usiw_port *dev;
	struct urdmad_qp *qp;
	ssize_t ret;

	if (WARN_ONCE(count < sizeof(*event),
			"Read only %zd/%zu bytes\n", count, sizeof(*event))) {
		return;
	}

	RTE_LOG(DEBUG, USER1, "Got connection event for device %" PRIu16 " queue pair %" PRIu32 "/%" PRIu16 "\n",
			event->urdmad_dev_id, event->kmod_qp_id,
			event->urdmad_qp_id);

	dev = &driver->ports[event->urdmad_dev_id];
	qp = &dev->qp[event->urdmad_qp_id];

	rte_spinlock_lock(&qp->conn_event_lock);
	assert(event->src_port != 0);
	assert(event->src_ipv4 == dev->ipv4_addr);
	assert(event->rxq == qp->rx_queue);
	assert(event->txq == qp->tx_queue);
	qp->local_udp_port = event->src_port;
	qp->local_ipv4_addr = event->src_ipv4;
	qp->remote_udp_port = event->dst_port;
	qp->remote_ipv4_addr = event->dst_ipv4;
	qp->ord_max = event->ord_max;
	qp->ird_max = event->ird_max;
	switch (dev->mtu) {
	case 9000:
		qp->mtu = 8192;
		break;
	default:
		qp->mtu = 1024;
	}
	ret = rte_eth_rx_queue_info_get(event->urdmad_dev_id,
			event->urdmad_qp_id, &rxq_info);
	if (ret < 0) {
		qp->rx_desc_count = dev->rx_desc_count;
	} else {
		qp->rx_desc_count = rxq_info.nb_desc;
	}
	ret = rte_eth_tx_queue_info_get(event->urdmad_dev_id,
			event->urdmad_qp_id, &txq_info);
	if (ret < 0) {
		qp->tx_desc_count = dev->tx_desc_count;
	} else {
		qp->tx_desc_count = txq_info.nb_desc;
	}
	qp->rx_burst_size = dev->rx_burst_size;
	if (qp->rx_burst_size > qp->rx_desc_count + 1) {
		qp->rx_burst_size = qp->rx_desc_count + 1;
	}
	qp->tx_burst_size = dev->tx_burst_size;
	if (qp->tx_burst_size > dev->tx_desc_count) {
		qp->tx_burst_size = dev->tx_desc_count;
	}
	memcpy(&qp->remote_ether_addr, event->dst_ether, ETHER_ADDR_LEN);
	if (dev->flags & port_fdir) {
		memset(&fdirf, 0, sizeof(fdirf));
		fdirf.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
		fdirf.input.flow.udp4_flow.ip.dst_ip = dev->ipv4_addr;
		fdirf.action.behavior = RTE_ETH_FDIR_ACCEPT;
		fdirf.action.report_status = RTE_ETH_FDIR_NO_REPORT_STATUS;
		fdirf.soft_id = event->rxq;
		fdirf.action.rx_queue = event->rxq;
		fdirf.input.flow.udp4_flow.dst_port = event->src_port;
		RTE_LOG(DEBUG, USER1, "fdir: assign rx queue %d: IP address %" PRIx32 ", UDP port %" PRIu16 "\n",
					fdirf.action.rx_queue,
					rte_be_to_cpu_32(dev->ipv4_addr),
					rte_be_to_cpu_16(event->src_port));
		ret = rte_eth_dev_filter_ctrl(dev->portid, RTE_ETH_FILTER_FDIR,
				RTE_ETH_FILTER_ADD, &fdirf);
		if (ret != 0) {
			RTE_LOG(CRIT, USER1, "Could not add fdir UDP filter: %s\n",
					rte_strerror(-ret));
			rte_spinlock_unlock(&qp->conn_event_lock);
			return;
		}

		/* Start the queues now that we have bound to an interface */
		ret = rte_eth_dev_rx_queue_start(event->urdmad_dev_id, event->rxq);
		if (ret < 0 && ret != -ENOTSUP) {
			RTE_LOG(DEBUG, USER1, "Enable RX queue %u failed: %s\n",
					event->rxq, rte_strerror(-ret));
			rte_spinlock_unlock(&qp->conn_event_lock);
			return;
		}

		ret = rte_eth_dev_tx_queue_start(event->urdmad_dev_id, event->txq);
		if (ret < 0 && ret != -ENOTSUP) {
			RTE_LOG(DEBUG, USER1, "Enable RX queue %u failed: %s\n",
					event->txq, rte_strerror(-ret));
			rte_spinlock_unlock(&qp->conn_event_lock);
			return;
		}
#if 0
	} else {
		char name[RTE_RING_NAMESIZE];
		snprintf(name, RTE_RING_NAMESIZE, "qp%u_rxring",
				qp->qp_id);
		qp->remote_ep.rx_queue = rte_ring_create(name,
				qp->dev->rx_desc_count, rte_socket_id(),
				RING_F_SP_ENQ|RING_F_SC_DEQ);
		if (!qp->rx_queue) {
			RTE_LOG(DEBUG, USER1, "Set up rx ring failed: %s\n",
						rte_strerror(ret));
			atomic_store(&qp->shm_qp->conn_state, usiw_qp_error);
			rte_spinlock_unlock(&qp->shm_qp->conn_event_lock);
			return;
		}
#endif
	}

	atomic_store(&qp->conn_state, usiw_qp_connected);
	rte_spinlock_unlock(&qp->conn_event_lock);

	rtr_event.event_type = SIW_EVENT_QP_RTR;
	rtr_event.kmod_qp_id = event->kmod_qp_id;
	ret = write(driver->chardev.fd, &rtr_event, sizeof(rtr_event));
	if (WARN_ONCE(ret < 0, "Error writing event file: %s\n",
							strerror(errno))) {
		return;
	} else if (WARN_ONCE((size_t)ret < sizeof(rtr_event),
			"Wrote only %zd/%zu bytes\n", ret, sizeof(rtr_event))) {
		return;
	}
	RTE_LOG(DEBUG, USER1, "Post RTR event for queue pair %" PRIu32 "; tx_queue=%" PRIu16 " rx_queue=%" PRIu16 "\n",
			event->kmod_qp_id, event->txq, event->rxq);
}	/* handle_qp_connected_event */


static void
chardev_data_ready(struct urdma_fd *fd)
{
	struct urdma_qp_connected_event event;
	struct pollfd pollfd;
	ssize_t ret;

	ret = read(fd->fd, &event, sizeof(event));
	if (ret < 0 && errno == EAGAIN) {
		return;
	}
	if (WARN_ONCE(ret < 0, "Error reading event file: %s\n",
							strerror(errno))) {
		return;
	}

	if (WARN_ONCE(event.event_type != SIW_EVENT_QP_CONNECTED,
			"Received unexpected event_type %d from kernel\n",
			event.event_type)) {
		return;
	}

	handle_qp_connected_event(&event, ret);
} /* chardev_data_ready */


static int
send_create_qp_resp(struct urdma_process *process, struct urdmad_qp *qp)
{
	struct urdmad_sock_qp_msg msg;
	int ret;

	msg.hdr.opcode = rte_cpu_to_be_32(urdma_sock_create_qp_resp);
	msg.hdr.dev_id = rte_cpu_to_be_16(qp->dev_id);
	msg.hdr.qp_id = rte_cpu_to_be_16(qp->qp_id);
	msg.ptr = rte_cpu_to_be_64((uintptr_t)qp);
	ret = send(process->fd.fd, &msg, sizeof(msg), 0);
	if (ret < 0) {
		return ret;
	} else if (ret == sizeof(msg)) {
		return 0;
	} else {
		errno = EMSGSIZE;
		return -1;
	}
} /* send_create_qp_resp */


static int
handle_hello(struct urdma_process *process, struct urdmad_sock_hello_req *req)
{
	struct urdmad_sock_hello_resp *resp;
	ssize_t ret;
	size_t resp_size;
	int i;

	if (!reserve_cores(rte_cpu_to_be_32(req->req_lcore_count),
				process->core_mask))
		return -1;

	resp_size = sizeof(*resp) + driver->port_count * sizeof(*resp->max_qp);
	resp = alloca(resp_size);
	memset(resp, 0, resp_size);
	resp->hdr.opcode = rte_cpu_to_be_32(urdma_sock_hello_resp);
	resp->max_lcore = rte_cpu_to_be_16(RTE_MAX_LCORE);
	resp->device_count = rte_cpu_to_be_16(driver->port_count);
	for (i = 0; i < RTE_DIM(resp->lcore_mask); i++) {
		resp->lcore_mask[i] = rte_cpu_to_be_32(process->core_mask[i]);
	}
	for (i = 0; i < driver->port_count; ++i) {
		resp->max_qp[i] = rte_cpu_to_be_16(driver->ports[i].max_qp);
	}
	ret = send(process->fd.fd, resp, resp_size, 0);
	if (ret < 0) {
		return ret;
	} else if (ret == resp_size) {
		return 0;
	} else {
		errno = EMSGSIZE;
		return -1;
	}

	return 0;
} /* handle_hello */


static void
process_data_ready(struct urdma_fd *process_fd)
{
	struct urdma_process *process
		= container_of(process_fd, struct urdma_process, fd);
	struct usiw_port *port;
	union urdmad_sock_any_msg msg;
	struct urdmad_qp *qp, **prev;
	uint16_t dev_id, qp_id;
	ssize_t ret;

	ret = recv(process->fd.fd, &msg, sizeof(msg), 0);
	if (ret < sizeof(struct urdmad_sock_msg)) {
		RTE_LOG(DEBUG, USER1, "EOF or error on fd %d\n", process->fd.fd);
		LIST_FOR_EACH(qp, &process->owned_qps, urdmad__entry, prev) {
			RTE_LOG(DEBUG, USER1, "Return QP %" PRIu16 " to pool\n",
					qp->qp_id);
			return_qp(&driver->ports[qp->dev_id], qp);
		}
		return_lcores(process->core_mask);
		goto err;
	}

	switch (rte_be_to_cpu_32(msg.hdr.opcode)) {
	case urdma_sock_create_qp_req:
		dev_id = rte_be_to_cpu_16(msg.hdr.dev_id);
		if (dev_id > driver->port_count) {
			goto err;
		}
		port = &driver->ports[dev_id];
		qp = port->avail_qp.lh_first;
		LIST_REMOVE(qp, urdmad__entry);
		RTE_LOG(DEBUG, USER1, "CREATE QP dev_id=%" PRIu16 " on fd %d => qp_id=%" PRIu16 "\n",
				dev_id, process->fd.fd, qp->qp_id);
		LIST_INSERT_HEAD(&process->owned_qps, qp, urdmad__entry);
		ret = send_create_qp_resp(process, qp);
		if (ret < 0) {
			goto err;
		}
		break;
	case urdma_sock_destroy_qp_req:
		dev_id = rte_be_to_cpu_16(msg.hdr.dev_id);
		qp_id = rte_be_to_cpu_16(msg.hdr.qp_id);
		RTE_LOG(DEBUG, USER1, "DESTROY QP qp_id=%" PRIu16 " dev_id=%" PRIu16 " on fd %d\n",
				qp_id, dev_id, process->fd.fd);
		if (dev_id > driver->port_count
				|| qp_id > driver->ports[dev_id].max_qp) {
			goto err;
		}
		port = &driver->ports[dev_id];
		qp = &port->qp[qp_id];
		return_qp(port, qp);
		break;
	case urdma_sock_hello_req:
		fprintf(stderr, "HELLO on fd %d\n", process->fd.fd);
		if (handle_hello(process, &msg.hello_req) < 0) {
			goto err;
		}
		break;
	default:
		RTE_LOG(DEBUG, USER1, "Unknown opcode %" PRIu32 " on fd %d\n",
				rte_be_to_cpu_32(msg.hdr.opcode),
				process->fd.fd);
		goto err;
	}

	return;

err:
	LIST_REMOVE(process, entry);
	close(process->fd.fd);
	free(process);
} /* process_data_ready */


static int
epoll_add(int epoll_fd, struct urdma_fd *fd, int events)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = events;
	event.data.ptr = fd;
	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd->fd, &event);
} /* epoll_add */


static void
listen_data_ready(struct urdma_fd *listen_fd)
{
	struct urdma_process *proc;

	proc = malloc(sizeof(*proc));
	if (!proc) {
		return;
	}

	proc->fd.fd = accept4(listen_fd->fd, NULL, NULL,
			SOCK_NONBLOCK|SOCK_CLOEXEC);
	if (proc->fd.fd < 0) {
		return;
	}
	proc->fd.data_ready = &process_data_ready;
	if (epoll_add(driver->epoll_fd, &proc->fd, EPOLLIN) < 0) {
		rte_exit(EXIT_FAILURE, "Could not add socket to epoll set: %s\n",
				strerror(errno));
	}
	LIST_INIT(&proc->owned_qps);
	/* This assumes that core_mask is an array member, not a pointer to an
	 * array */
	memset(proc->core_mask, 0, sizeof(proc->core_mask));
	LIST_INSERT_HEAD(&driver->processes, proc, entry);
} /* listen_data_ready */


static void
timer_data_ready(struct urdma_fd *fd)
{
	struct rte_eth_stats stats;
	unsigned int i;
	uint64_t event_count;
	int ret;

	errno = EMSGSIZE;
	ret = read(fd->fd, &event_count, sizeof(event_count));
	if (ret < sizeof(event_count)) {
		rte_exit(EXIT_FAILURE, "Error disarming timer: %s\n", strerror(errno));
	}

	for (i = 0; i < driver->port_count; i++) {
		ret = rte_eth_stats_get(driver->ports[i].portid, &stats);
		if (ret) {
			continue;
		}

		if (stats.imissed || stats.ierrors || stats.oerrors
							|| stats.rx_nombuf) {
			RTE_LOG(NOTICE, USER1,
				"port %u imissed=%" PRIu64 " ierrors=%" PRIu64 " oerrors=%" PRIu64 " rx_nombuf=%" PRIu64 "\n",
				driver->ports[i].portid, stats.imissed,
				stats.ierrors, stats.oerrors, stats.rx_nombuf);
		}
		rte_eth_stats_reset(driver->ports[i].portid);
	}
} /* timer_data_ready */


static void
do_poll(int timeout)
{
	struct epoll_event event;
	struct urdma_fd *fd;
	int ret;

	if (timeout) {
		ret = epoll_wait(driver->epoll_fd, &event, 1, timeout);
		if (ret > 0) {
			fd = event.data.ptr;
			fd->data_ready(fd);
		} else if (WARN_ONCE(ret < 0,
				"Error polling event file for reading: %s\n",
							strerror(errno))) {
			return;
		}
	}
} /* do_poll */


static int
kni_process_burst(struct usiw_port *port,
		struct rte_mbuf **rxmbuf, int count)
{

	/* TODO: Forward these to the appropriate process */
#if 0
	struct usiw_qp *qp;
	int i, j;
	if (port->ctx && !(port->flags & port_fdir)) {
		for (i = j = 0; i < count; i++) {
			while (i + j < count
					&& (qp = find_matching_qp(port->ctx,
							rxmbuf[i + j]))) {
				/* This implies that qp->ep_default != NULL */
				rte_ring_enqueue(qp->ep_default->rx_queue,
						rxmbuf[i + j]);
				j++;
			}
			if (i + j < count) {
				rxmbuf[i] = rxmbuf[i + j];
			}
		}

		count -= j;
	}
#endif
#ifdef DEBUG_PACKET_HEADERS
	int i;
	RTE_LOG(DEBUG, USER1, "port %d: receive %d packets\n",
			port->portid, count);
	for (i = 0; i < count; ++i)
		rte_pktmbuf_dump(stderr, rxmbuf[i], 128);
#endif
	return rte_kni_tx_burst(port->kni, rxmbuf, count);
} /* kni_process_burst */


static void
do_xchg_packets(struct usiw_port *port)
{
	struct rte_mbuf *rxmbuf[port->rx_burst_size];
	unsigned int rcount, scount;

	rcount = rte_kni_rx_burst(port->kni,
			rxmbuf, port->rx_burst_size);
	if (rcount) {
#ifdef DEBUG_PACKET_HEADERS
		int i;
		RTE_LOG(DEBUG, USER1, "port %d: send %d packets\n",
				port->portid, rcount);
		for (i = 0; i < rcount; ++i)
			rte_pktmbuf_dump(stderr, rxmbuf[i], 128);
#endif
		scount = rte_eth_tx_burst(port->portid, 0,
			rxmbuf, rcount);
		if (scount < rcount) {
			RTE_LOG(WARNING, USER1, "rte_eth_tx_burst only %d of %d packets\n",
					scount, rcount);
			for (; scount < rcount; scount++) {
				rte_pktmbuf_free(rxmbuf[scount]);
			}
		}
	}

	rcount = rte_eth_rx_burst(port->portid, 0,
				rxmbuf, port->rx_burst_size);
	if (rcount) {
		scount = kni_process_burst(port, rxmbuf, rcount);
		if (scount < rcount) {
			RTE_LOG(WARNING, USER1, "rte_kni_tx_burst only %d of %d packets\n",
					scount, rcount);
			for (; scount < rcount; scount++) {
				rte_pktmbuf_free(rxmbuf[scount]);
			}
		}
	}
} /* do_xchng_packets */


static int
event_loop(void *arg)
{
	struct usiw_driver *driver = arg;
	struct usiw_port *port;
	int portid, ret;

	while (1) {
		do_poll(1);
		for (portid = 0; portid < driver->port_count; ++portid) {
			port = &driver->ports[portid];
			ret = rte_kni_handle_request(port->kni);
			if (ret) {
				break;
			}

			do_xchg_packets(port);
		}
	}

	return EXIT_FAILURE;
}


static void
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
		RTE_LOG(WARNING, USER1, "Could not set fdir filter info on port %" PRIu16 ": %s\n",
				iface->portid, strerror(-retval));
	}
} /* setup_base_filters */


static void
usiw_port_init(struct usiw_port *iface, struct usiw_port_config *port_config)
{
	static const uint32_t rx_checksum_offloads
		= DEV_RX_OFFLOAD_UDP_CKSUM|DEV_RX_OFFLOAD_IPV4_CKSUM;
	static const uint32_t tx_checksum_offloads
		= DEV_TX_OFFLOAD_UDP_CKSUM|DEV_TX_OFFLOAD_IPV4_CKSUM;

	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_conf port_conf;
	size_t mbuf_size;
	int socket_id;
	int retval;
	uint16_t q;

	socket_id = rte_eth_dev_socket_id(iface->portid);

	assert(iface->portid < rte_eth_dev_count());

	memset(&port_conf, 0, sizeof(port_conf));
	iface->flags = 0;
	port_conf.rxmode.max_rx_pkt_len
			= port_config->mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;
	port_conf.rxmode.jumbo_frame = !!(port_config->mtu > 1500);
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
		RTE_LOG(NOTICE, USER1,
			"port %" PRIu16 " does not support Flow Director\n",
			iface->portid);
		port_conf.fdir_conf.mode = RTE_FDIR_MODE_NONE;
	}

	/* Calculate max_qp.  We map queue pairs 1:1 with hardware queues for
	 * now, with 1 reserved for urdmad ARP/CM usage.  Note that at least
	 * i40e reserves queues for VMDq and makes them unavailable for general
	 * use, so we must subtract those queues from the available queues. */
	if (iface->dev_info.max_vmdq_pools > 0
			&& iface->dev_info.vmdq_queue_base > 0) {
		RTE_LOG(INFO, USER1,
			"port %" PRIu16 " reserves %" PRIu16 " queues for VMDq\n",
			iface->portid, iface->dev_info.vmdq_queue_num);
		iface->dev_info.max_rx_queues -= iface->dev_info.vmdq_queue_num;
		iface->dev_info.max_tx_queues -= iface->dev_info.vmdq_queue_num;
	}
	iface->max_qp = port_config->max_qp > 0 ? port_config->max_qp
		: RTE_MIN(iface->dev_info.max_rx_queues,
					iface->dev_info.max_tx_queues);
	if (iface->max_qp >= iface->dev_info.max_rx_queues) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured max_qp %" PRIu16 " > max_rx_queues %" PRIu16 "\n",
			 iface->portid, iface->max_qp,
			 iface->dev_info.max_rx_queues - 1);
	}
	if (iface->max_qp >= iface->dev_info.max_tx_queues) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured max_qp %" PRIu16 " > max_tx_queues %" PRIu16 "\n",
			 iface->portid, iface->max_qp,
			 iface->dev_info.max_tx_queues - 1);
	}
	fprintf(stderr, "port %" PRIu16 " max_qp %" PRIu16 "\n",
			iface->portid, iface->max_qp);

	/* TODO: Auto-tuning of rx_desc_count and tx_desc_count */
	if (port_config->rx_desc_count == UINT_MAX) {
		iface->rx_desc_count = iface->dev_info.rx_desc_lim.nb_min;
	} else if (port_config->rx_desc_count > iface->dev_info.rx_desc_lim.nb_max) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured rx_desc_count %" PRIu16 " > rx_desc_lim.nb_max %" PRIu16 "\n",
			 iface->portid, iface->rx_desc_count,
			 iface->dev_info.rx_desc_lim.nb_max);
	} else if (port_config->rx_desc_count < iface->dev_info.rx_desc_lim.nb_min) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured rx_desc_count %" PRIu16 " < rx_desc_lim.nb_min %" PRIu16 "\n",
			 iface->portid, iface->rx_desc_count,
			 iface->dev_info.rx_desc_lim.nb_min);
	} else if (port_config->rx_desc_count % iface->dev_info.rx_desc_lim.nb_align) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured rx_desc_count %" PRIu16 " does not match alignment %" PRIu16 "\n",
			 iface->portid, iface->rx_desc_count,
			 iface->dev_info.rx_desc_lim.nb_align);
	} else {
		iface->rx_desc_count = port_config->rx_desc_count;
	}
	if (port_config->tx_desc_count == UINT_MAX) {
		iface->tx_desc_count = iface->dev_info.tx_desc_lim.nb_min;
	} else if (port_config->tx_desc_count > iface->dev_info.tx_desc_lim.nb_max) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured tx_desc_count %" PRIu16 " > tx_desc_lim.nb_max %" PRIu16 "\n",
			 iface->portid, iface->tx_desc_count,
			 iface->dev_info.tx_desc_lim.nb_max);
	} else if (port_config->tx_desc_count < iface->dev_info.tx_desc_lim.nb_min) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured tx_desc_count %" PRIu16 " < tx_desc_lim.nb_min %" PRIu16 "\n",
			 iface->portid, iface->tx_desc_count,
			 iface->dev_info.tx_desc_lim.nb_min);
	} else if (port_config->tx_desc_count % iface->dev_info.tx_desc_lim.nb_align) {
		rte_exit(EXIT_FAILURE,
			 "port %" PRIu16 " configured tx_desc_count %" PRIu16 " does not match alignment %" PRIu16 "\n",
			 iface->portid, iface->tx_desc_count,
			 iface->dev_info.tx_desc_lim.nb_align);
	} else {
		iface->tx_desc_count = port_config->tx_desc_count;
	}
	iface->rx_burst_size = port_config->rx_burst_size;
	iface->tx_burst_size = port_config->tx_burst_size;
	fprintf(stderr,
		"port %" PRIu16 " tx_desc_count %" PRIu16 " rx_desc_count %" PRIu16 " rx_burst_size %" PRIu16 " tx_burst_size %" PRIu16 "\n",
		iface->portid, iface->tx_desc_count,
		iface->rx_desc_count, iface->rx_burst_size,
		iface->tx_burst_size);

	LIST_INIT(&iface->avail_qp);

	iface->qp = rte_calloc("urdma_qp", iface->max_qp + 1,
			sizeof(*iface->qp), 0);
	if (!iface->qp) {
		rte_exit(EXIT_FAILURE, "Cannot allocate QP array: %s\n",
				rte_strerror(rte_errno));
	}
	for (q = 1; q <= iface->max_qp; ++q) {
		iface->qp[q].qp_id = q;
		iface->qp[q].tx_queue = q;
		iface->qp[q].rx_queue = q;
		atomic_init(&iface->qp[q].conn_state, 0);
		rte_spinlock_init(&iface->qp[q].conn_event_lock);
		LIST_INSERT_HEAD(&iface->avail_qp, &iface->qp[q],
				urdmad__entry);
	}

	/* We must allocate an mbuf large enough to hold the maximum possible
	 * received packet. Note that the 64-byte headroom does *not* count for
	 * incoming packets. Note that the MTU as set by urdma and DPDK does
	 * *not* include the Ethernet header, CRC, or VLAN tag, but the drivers
	 * require space for these in the receive buffer. */
	mbuf_size = RTE_PKTMBUF_HEADROOM + port_config->mtu
		+ ETHER_HDR_LEN + ETHER_CRC_LEN + urdma_vlan_space;

	snprintf(name, RTE_MEMPOOL_NAMESIZE,
			"port_%u_rx_mempool", iface->portid);
	RTE_LOG(DEBUG, USER1, "create rx mempool for port %" PRIu16 " with %u mbufs of size %zu\n",
				iface->portid,
				2 * iface->max_qp * iface->rx_desc_count,
				mbuf_size);
	iface->rx_mempool = rte_pktmbuf_pool_create(name,
		2 * iface->max_qp * iface->rx_desc_count,
		0, 0, mbuf_size, socket_id);
	if (iface->rx_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create rx mempool for port %" PRIu16 " with %u mbufs: %s\n",
				iface->portid,
				2 * iface->max_qp * iface->rx_desc_count,
				rte_strerror(rte_errno));

	snprintf(name, RTE_MEMPOOL_NAMESIZE,
			"port_%u_tx_mempool", iface->portid);
	RTE_LOG(DEBUG, USER1, "create tx mempool for port %" PRIu16 " with %u mbufs of size %zu plus %u bytes private data\n",
				iface->portid,
				2 * iface->max_qp * iface->rx_desc_count,
				mbuf_size, PENDING_DATAGRAM_INFO_SIZE);
	iface->tx_ddp_mempool = rte_pktmbuf_pool_create(name,
		2 * iface->max_qp * iface->tx_desc_count,
		0, PENDING_DATAGRAM_INFO_SIZE, mbuf_size, socket_id);
	if (iface->tx_ddp_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create tx mempool for port %" PRIu16 " with %u mbufs: %s\n",
				iface->portid,
				2 * iface->max_qp * iface->tx_desc_count,
				rte_strerror(rte_errno));

	/* FIXME: make these actually separate */
	iface->tx_hdr_mempool = iface->tx_ddp_mempool;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(iface->portid, iface->max_qp + 1,
			iface->max_qp + 1, &port_conf);
	if (retval != 0) {
		rte_exit(EXIT_FAILURE,
			"Cannot configure port %" PRIu16 " with max_qp %" PRIu16 ": %s\n",
			iface->portid, iface->max_qp,
			rte_strerror(-retval));
	}

	rte_eth_promiscuous_disable(iface->portid);

	/* Set up control RX queue */
	retval = rte_eth_rx_queue_setup(iface->portid, 0, iface->rx_desc_count,
			socket_id, NULL, iface->rx_mempool);
	if (retval < 0)
		rte_exit(EXIT_FAILURE,
			"Cannot setup port %" PRIu16 " rx queue 0: %s\n",
			iface->portid, rte_strerror(-retval));

	/* Data RX queue startup is deferred */
	memcpy(&rxconf, &iface->dev_info.default_rxconf, sizeof(rxconf));
	rxconf.rx_deferred_start = 1;
	for (q = 1; q <= iface->max_qp; q++) {
		retval = rte_eth_rx_queue_setup(iface->portid, q,
				iface->rx_desc_count, socket_id, &rxconf,
				iface->rx_mempool);
		if (retval < 0) {
			rte_exit(EXIT_FAILURE,
				"Cannot setup port %" PRIu16 " rx queue %" PRIu16 ": %s\n",
				iface->portid, q, rte_strerror(-retval));
		}
	}

	/* Set up control TX queue */
	retval = rte_eth_tx_queue_setup(iface->portid, 0, iface->tx_desc_count,
			socket_id, NULL);
	if (retval < 0)
		rte_exit(EXIT_FAILURE,
			"Cannot setup port %" PRIu16 " tx queue 0: %s\n",
			iface->portid, rte_strerror(-retval));

	/* Data TX queue requires checksum offload, and startup is deferred */
	memcpy(&txconf, &iface->dev_info.default_txconf, sizeof(txconf));
	txconf.txq_flags &= ~(ETH_TXQ_FLAGS_NOMULTSEGS|ETH_TXQ_FLAGS_NOREFCOUNT
				|ETH_TXQ_FLAGS_NOMULTMEMP);
	if (iface->flags & port_checksum_offload) {
		txconf.txq_flags &= ~ETH_TXQ_FLAGS_NOXSUMUDP;
	}
	txconf.tx_deferred_start = 1;
	for (q = 1; q <= iface->max_qp; q++) {
		retval = rte_eth_tx_queue_setup(iface->portid, q,
				iface->tx_desc_count, socket_id, &txconf);
		if (retval < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot setup port %" PRIu16 " tx queue %" PRIu16 ": %s\n",
				iface->portid, q, rte_strerror(-retval));
	}

	if (iface->flags & port_fdir) {
		setup_base_filters(iface);
	}

	retval = usiw_port_setup_kni(iface);
	if (retval < 0) {
		rte_exit(EXIT_FAILURE, "Could not set port %u KNI interface: %s\n",
				iface->portid, strerror(-retval));
	}

	retval = rte_eth_dev_set_mtu(iface->portid, port_config->mtu);
	if (retval < 0) {
		rte_exit(EXIT_FAILURE, "Could not set port %u MTU to %u: %s\n",
				iface->portid, port_config->mtu,
				strerror(-retval));
	}
	iface->mtu = port_config->mtu;

	retval = rte_eth_dev_start(iface->portid);
	if (retval < 0)
		rte_exit(EXIT_FAILURE, "Could not start port %u: %s\n",
				iface->portid, strerror(-retval));
} /* usiw_port_init */


static void
setup_socket(const char *path)
{
	struct sockaddr_un addr;
	int flags, ret;

	if (strlen(path) >= sizeof(addr.sun_path) - 1) {
		rte_exit(EXIT_FAILURE, "Invalid socket path %s: too long\n",
				path);
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));

	if (unlink(path) < 0 && errno != ENOENT) {
		rte_exit(EXIT_FAILURE, "Could not unlink previous socket %s: %s\n",
				path, strerror(errno));
	}

	driver->listen.fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (driver->listen.fd < 0) {
		rte_exit(EXIT_FAILURE, "Could not open socket %s: %s\n",
				path, strerror(errno));
	}

	flags = fcntl(driver->listen.fd, F_GETFL);
	if (flags == -1 || fcntl(driver->listen.fd, F_SETFL,
						flags | O_NONBLOCK)) {
		rte_exit(EXIT_FAILURE, "Could not make socket non-blocking: %s\n",
				strerror(errno));
	}

	if (bind(driver->listen.fd, (struct sockaddr *)&addr,
				sizeof(addr)) < 0) {
		rte_exit(EXIT_FAILURE, "Could not bind socket %s: %s\n",
				path, strerror(errno));
	}

	LIST_INIT(&driver->processes);
	if (listen(driver->listen.fd, 16) < 0) {
		rte_exit(EXIT_FAILURE, "Could not listen on socket %s: %s\n",
				path, strerror(errno));
	}

	driver->listen.data_ready = &listen_data_ready;
	if (epoll_add(driver->epoll_fd, &driver->listen, EPOLLIN) < 0) {
		rte_exit(EXIT_FAILURE, "Could not add socket to epoll set: %s\n",
				strerror(errno));
	}
} /* setup_socket */


static void
setup_timer(int interval_ms)
{
	struct itimerspec tv;
	int ret;

	driver->timer.fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (driver->timer.fd < 0) {
		rte_exit(EXIT_FAILURE, "Could not open timer fd: %s\n",
				strerror(errno));
	}

	tv.it_interval.tv_sec = interval_ms / 1000;
	tv.it_interval.tv_nsec = (interval_ms % 1000) * 1000000;
	memcpy(&tv.it_value, &tv.it_interval, sizeof(tv.it_value));

	if (timerfd_settime(driver->timer.fd, 0, &tv, NULL) < 0) {
		rte_exit(EXIT_FAILURE, "Could not arm timer fd %d: %s\n",
				driver->timer.fd, strerror(errno));
	}

	driver->timer.data_ready = &timer_data_ready;
	if (epoll_add(driver->epoll_fd, &driver->timer, EPOLLIN) < 0) {
		rte_exit(EXIT_FAILURE, "Could not add timer fd %d to epoll set: %s\n",
				driver->timer.fd, strerror(errno));
	}
} /* setup_timer */



static int
lookup_ethdev_by_pci_addr(struct rte_pci_addr *addr)
{
	struct rte_eth_dev_info info;
	int x, count;

	count = rte_eth_dev_count();
	for (x = 0; x < count; ++x) {
		rte_eth_dev_info_get(x, &info);
		if (!rte_eal_compare_pci_addr(addr, &info.pci_dev->addr)) {
			return x;
		}
	}
	return -ENODEV;
} /* lookup_ethdev_by_pci_addr */


static void
do_init_driver(void)
{
	struct usiw_port_config *port_config;
	struct usiw_config config;
	char *sock_name;
	int i, portid, port_count, timer_ms;
	int retval;

	retval = urdma__config_file_open(&config);
	if (retval < 0) {
		rte_exit(EXIT_FAILURE, "Could not open config file: %s\n",
				strerror(errno));
	}

	port_count = rte_eth_dev_count();

	retval = urdma__config_file_get_ports(&config, &port_config);
	if (retval <= 0) {
		rte_exit(EXIT_FAILURE, "Could not parse config file: %s\n",
				strerror(errno));
	} else if (port_count < retval) {
		rte_exit(EXIT_FAILURE, "Configuration expects %d devices but found only %d\n",
				retval, port_count);
	}
	port_count = retval;

	sock_name = urdma__config_file_get_sock_name(&config);
	if (!sock_name) {
		rte_exit(EXIT_FAILURE, "sock_name not found in configuration\n");
	}

	timer_ms = urdma__config_file_get_timer_interval(&config);
	if (!timer_ms) {
		timer_ms = 5000;
	}

	urdma__config_file_close(&config);

	driver = calloc(1, sizeof(*driver)
			+ port_count * sizeof(struct usiw_port));
	if (!driver) {
		rte_exit(EXIT_FAILURE, "Could not allocate main driver structure: %s\n",
				strerror(errno));
	}
	driver->port_count = port_count;
	driver->epoll_fd = epoll_create(EPOLL_CLOEXEC);
	if (driver->epoll_fd < 0) {
		rte_exit(EXIT_FAILURE, "Could not open epoll fd: %s\n",
				strerror(errno));
	}
	setup_timer(timer_ms);
	setup_socket(sock_name);
	free(sock_name);
	driver->chardev.data_ready = &chardev_data_ready;
	driver->chardev.fd = open("/dev/urdma", O_RDWR|O_NONBLOCK);
	if (driver->chardev.fd < 0) {
		rte_exit(EXIT_FAILURE, "Could not open urdma char device: %s\n",
				strerror(errno));
	}
	if (epoll_add(driver->epoll_fd, &driver->chardev, EPOLLIN) < 0) {
		rte_exit(EXIT_FAILURE, "Could not add urdma char device to epoll set: %s\n",
				strerror(errno));
	}
	rte_kni_init(driver->port_count);

	driver->progress_lcore = 1;
	for (i = 0; i < driver->port_count; ++i) {
		switch (port_config[i].id_type) {
		case urdma_port_id_index:
			portid = i;
			break;
		case urdma_port_id_pci:
			portid = lookup_ethdev_by_pci_addr(
						&port_config[i].pci_address);
			if (portid < 0) {
				rte_exit(EXIT_FAILURE, "No DPDK ethdev with PCI address " PCI_PRI_FMT "\n",
					port_config[i].pci_address.domain,
					port_config[i].pci_address.bus,
					port_config[i].pci_address.devid,
					port_config[i].pci_address.function);
			}
			RTE_LOG(DEBUG, USER1, "Resolve PCI address " PCI_PRI_FMT " to portid %d\n",
					port_config[i].pci_address.domain,
					port_config[i].pci_address.bus,
					port_config[i].pci_address.devid,
					port_config[i].pci_address.function,
					portid);
			break;
		default:
			abort();
		}
		driver->ports[i].portid = portid;
		rte_eth_macaddr_get(portid,
				&driver->ports[i].ether_addr);
		rte_eth_dev_info_get(portid, &driver->ports[i].dev_info);

		usiw_port_init(&driver->ports[i], &port_config[i]);
	}
	rte_eal_remote_launch(event_loop, driver, driver->progress_lcore);
	/* FIXME: cannot free driver beyond this point since it is being
	 * accessed by the event_loop */
	retval = usiw_driver_setup_netlink(driver);
	if (retval < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup KNI context: %s\n",
					strerror(-retval));
	}
	for (i = 0; i < driver->port_count; i++) {
		retval = usiw_set_ipv4_addr(driver, &driver->ports[i],
				&port_config[i]);
		if (retval < 0) {
			rte_exit(EXIT_FAILURE, "Could not set port %u IPv4 address: %s\n",
					portid, strerror(-retval));
		}
	}
	free(port_config);
} /* do_init_driver */


static void usage(const char *argv0)
{
	printf("  %-20s%s\n", "--systemd",
			"Assume we are running from systemd");
	printf("%22cDump log messages to stderr but not syslog\n", ' ');
	fflush(stdout);
} /* usage */


int
main(int argc, char *argv[])
{
	char **arg;

	rte_set_application_usage_hook(&usage);

	/* We cannot access /proc/self/pagemap as non-root if we are not
	 * dumpable
	 *
	 * We do require CAP_NET_ADMIN but there should be minimal risk from
	 * making ourselves dumpable, compared to requiring root priviliges to
	 * run */
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
		perror("WARNING: set dumpable flag failed; DPDK may not initialize properly");
	}

	/* Scan command line for --systemd option. We can't use getopt_long()
	 * because we must know about this argument *before* we call
	 * rte_eal_init(), which consumes most command line arguments. */
	for (arg = argv; *arg != NULL; ++arg) {
		if (!strcmp(*arg, "--systemd")) {
			/* If we are running under systemd, stderr is
			 * automatically logged to the systemd journal and thus
			 * also logging to syslog (which DPDK does by default)
			 * results in duplicate log messages. By preserving
			 * stderr, we ensure that any error messages printed by
			 * a library (such as glibc heap corruption dumps) make
			 * it to the journal. */
			rte_openlog_stream(stderr);
			break;
		}
	}

	/* rte_eal_init does nothing and returns -1 if it was already called
	 * (although this behavior is not documented).  rte_eal_init also
	 * crashes the whole program if it fails for any other reason, so we
	 * can depend on a negative return code meaning that rte_eal_init was
	 * already called.  This means that a program can accept the default
	 * EAL configuration by not calling rte_eal_init() before calling into
	 * a verbs function, allowing us to work with unmodified verbs
	 * applications. */
	rte_eal_init(argc, argv);

	init_core_mask();

	do_init_driver();

	pause();
} /* main */
