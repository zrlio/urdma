/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2008-2016, IBM Corporation
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

#ifndef _SIW_H
#define _SIW_H

#include <linux/idr.h>
#include <rdma/ib_verbs.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/module.h>

#include "usiw_kabi.h"
#include "backports.h"
#include "iwarp.h"

#define SIW_MAX_QP		(1024 * 100)
#define SIW_MAX_ORD		128
#define SIW_MAX_IRD		128
#define SIW_MAX_CQ		(1024 * 100)
#define SIW_MAX_PD		SIW_MAX_QP
#define SIW_MAX_CONTEXT		(SIW_MAX_PD * 10)

#define ETHER_ADDR_LEN		6

struct siw_devinfo {
	unsigned		version;

	/* close match to ib_device_attr where appropriate */
	u32			vendor_id;
	u32			vendor_part_id;
	u32			sw_version;
	int			max_qp;
	int			max_ord; /* max. outbound read queue depth */
	int			max_ird; /* max. inbound read queue depth */

	enum ib_device_cap_flags	cap_flags;
	int			max_cq;
	int			max_pd;
	/* end ib_device_attr */
};


struct siw_dev {
	struct ib_device	ofa_dev;
	struct list_head	list;
	struct net_device	*netdev;
	struct siw_devinfo	attrs;
	int			is_registered; /* Registered with OFA core */

	/* physical port state (only one port per device) */
	enum ib_port_state	state;

	/* object management */
	struct list_head	cep_list;
	spinlock_t		idr_lock;
	struct idr		qp_idr;
	struct idr		cq_idr;
	struct idr		pd_idr;

	/* active objects statistics */
	atomic_t		num_qp;
	atomic_t		num_cq;
	atomic_t		num_pd;
	atomic_t		num_cep;
	atomic_t		num_ctx;

	struct dentry		*debugfs;
};

struct siw_objhdr {
	u32			id;	/* for idr based object lookup */
	struct kref		ref;
	struct siw_dev		*sdev;
};

struct siw_event_file {
	struct siw_ucontext	*ctx;
	spinlock_t		lock;
	struct list_head	established_list;
	struct list_head	rtr_wait_list;
	wait_queue_head_t	wait_head;
};

struct siw_ucontext {
	struct ib_ucontext	ib_ucontext;
	struct siw_dev		*sdev;
	struct siw_event_file	*event_file;
};

struct siw_pd {
	struct siw_objhdr	hdr;
	struct ib_pd		ofa_pd;
};

struct siw_cq {
	struct ib_cq		ofa_cq;
	struct siw_objhdr	hdr;
};

enum siw_qp_state {
	SIW_QP_STATE_IDLE	= 0,
	SIW_QP_STATE_RTR	= 1,
	SIW_QP_STATE_RTS	= 2,
	SIW_QP_STATE_CLOSING	= 3,
	SIW_QP_STATE_TERMINATE	= 4,
	SIW_QP_STATE_ERROR	= 5,
	SIW_QP_STATE_MORIBUND	= 6, /* destroy called but still referenced */
	SIW_QP_STATE_UNDEF	= 7,
	SIW_QP_STATE_COUNT	= 8
};

enum siw_qp_flags {
	SIW_RDMA_BIND_ENABLED	= (1 << 0),
	SIW_RDMA_WRITE_ENABLED	= (1 << 1),
	SIW_RDMA_READ_ENABLED	= (1 << 2),
	/*
	 * QP currently being destroyed
	 */
	SIW_QP_IN_DESTROY	= (1 << 8)
};

enum siw_qp_attr_mask {
	SIW_QP_ATTR_STATE		= (1 << 0),
	SIW_QP_ATTR_ACCESS_FLAGS	= (1 << 1),
	SIW_QP_ATTR_LLP_HANDLE		= (1 << 2),
	SIW_QP_ATTR_ORD			= (1 << 3),
	SIW_QP_ATTR_IRD			= (1 << 4),
};

struct siw_sk_upcalls {
	void	(*sk_state_change)(struct sock *sk);
	void	(*sk_data_ready)(struct sock *sk, int bytes);
	void	(*sk_write_space)(struct sock *sk);
	void	(*sk_error_report)(struct sock *sk);
};

struct siw_qp_attrs {
	enum siw_qp_state	state;
	u32			orq_size;
	u32			irq_size;
	enum siw_qp_flags	flags;

	struct socket		*llp_stream_handle;
};

struct siw_qp {
	struct ib_qp		ofa_qp;
	struct siw_objhdr	hdr;

	struct siw_cep		*cep;
	struct rw_semaphore	state_lock;

	struct siw_pd		*pd;
	struct siw_cq		*scq;
	struct siw_cq		*rcq;

	struct siw_qp_attrs	attrs;
};

#define QP_ID(qp)		((qp)->hdr.id)
#define OBJ_ID(obj)		((obj)->hdr.id)


/* QP general functions */
int siw_qp_modify(struct siw_qp *, struct siw_qp_attrs *,
		  enum siw_qp_attr_mask);

void siw_qp_llp_close(struct siw_qp *);
void siw_qp_cm_drop(struct siw_qp *, int);


struct ib_qp *siw_get_ofaqp(struct ib_device *, int);
void siw_qp_get_ref(struct ib_qp *);
void siw_qp_put_ref(struct ib_qp *);

enum siw_qp_state siw_map_ibstate(enum ib_qp_state);


/* RDMA core event dipatching */
void siw_qp_event(struct siw_qp *, enum ib_event_type);
void siw_cq_event(struct siw_cq *, enum ib_event_type);
void siw_port_event(struct siw_dev *, u8, enum ib_event_type);


extern struct dma_map_ops usiw_dma_generic_ops;
extern struct ib_dma_mapping_ops siw_dma_mapping_ops;

#endif
