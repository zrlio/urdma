/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Patrick MacArthur <pam@zurich.ibm.com>
 *          Fredy Neeser <nfd@zurich.ibm.com>
 *
 * Copyright (c) 2008-2016, IBM Corporation
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

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "urdma.h"
#include "obj.h"
#include "cm.h"


static char siw_qp_state_to_string[SIW_QP_STATE_COUNT][sizeof "TERMINATE"] = {
	[SIW_QP_STATE_IDLE]		= "IDLE",
	[SIW_QP_STATE_RTR]		= "RTR",
	[SIW_QP_STATE_RTS]		= "RTS",
	[SIW_QP_STATE_CLOSING]		= "CLOSING",
	[SIW_QP_STATE_TERMINATE]	= "TERMINATE",
	[SIW_QP_STATE_ERROR]		= "ERROR",
	[SIW_QP_STATE_MORIBUND]		= "MORIBUND",
	[SIW_QP_STATE_UNDEF]		= "UNDEF"
};


void siw_qp_llp_close(struct siw_qp *qp)
{
	pr_debug(DBG_CM "(QP%d): Enter: SIW QP state = %s, cep=0x%p\n",
		QP_ID(qp), siw_qp_state_to_string[qp->attrs.state],
		qp->cep);

	down_write(&qp->state_lock);

	pr_debug(DBG_CM "(QP%d): state locked\n", QP_ID(qp));

	qp->attrs.llp_stream_handle = NULL;

	switch (qp->attrs.state) {

	case SIW_QP_STATE_RTS:
	case SIW_QP_STATE_RTR:
	case SIW_QP_STATE_IDLE:
	case SIW_QP_STATE_TERMINATE:

		qp->attrs.state = SIW_QP_STATE_ERROR;

		break;
	/*
	 * SIW_QP_STATE_CLOSING:
	 *
	 * This is a forced close. shall the QP be moved to
	 * ERROR or IDLE ?
	 */
	case SIW_QP_STATE_CLOSING:
		qp->attrs.state = SIW_QP_STATE_IDLE;

		break;

	default:
		pr_debug(DBG_CM " No state transition needed: %d\n",
			qp->attrs.state);
		break;
	}

	/*
	 * dereference closing CEP
	 */
	if (qp->cep) {
		siw_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);
	pr_debug(DBG_CM "(QP%d): Exit: SIW QP state = %s, cep=0x%p\n",
		QP_ID(qp), siw_qp_state_to_string[qp->attrs.state],
		qp->cep);
}


static void
notify_established(struct siw_ucontext *ctx, struct siw_qp *qp)
{
	struct urdma_chardev_data *file
		= dev_get_drvdata(ctx->sdev->ofa_dev.dma_device);

	if (!file) {
		siw_qp_rtr_fail(qp->cep);
	} else {
		siw_cep_get(qp->cep);
		list_add_tail(&qp->cep->established_entry,
				&file->established_list);
		wake_up(&file->wait_head);
	}
}


static inline struct siw_ucontext *siw_ctx_ofa2siw(struct ib_ucontext *ofa_ctx)
{
	return container_of(ofa_ctx, struct siw_ucontext, ib_ucontext);
}


int
siw_qp_modify(struct siw_qp *qp, struct siw_qp_attrs *attrs,
	      enum siw_qp_attr_mask mask)
	__must_hold(qp->state_lock)
{
	/* Minimum attributes required for INIT/RTR to RTS transition */
	static const enum siw_qp_attr_mask init_to_rts_mask
		= SIW_QP_ATTR_LLP_HANDLE|SIW_QP_ATTR_ORD|SIW_QP_ATTR_IRD;

	int	drop_conn = 0, rv = 0;

	if (!mask)
		return 0;

	pr_debug(DBG_CM "(QP%d)\n", QP_ID(qp));

	if (mask != SIW_QP_ATTR_STATE) {
		/*
		 * changes of qp attributes (maybe state, too)
		 */
		if (mask & SIW_QP_ATTR_ACCESS_FLAGS) {

			if (attrs->flags & SIW_RDMA_BIND_ENABLED)
				qp->attrs.flags |= SIW_RDMA_BIND_ENABLED;
			else
				qp->attrs.flags &= ~SIW_RDMA_BIND_ENABLED;

			if (attrs->flags & SIW_RDMA_WRITE_ENABLED)
				qp->attrs.flags |= SIW_RDMA_WRITE_ENABLED;
			else
				qp->attrs.flags &= ~SIW_RDMA_WRITE_ENABLED;

			if (attrs->flags & SIW_RDMA_READ_ENABLED)
				qp->attrs.flags |= SIW_RDMA_READ_ENABLED;
			else
				qp->attrs.flags &= ~SIW_RDMA_READ_ENABLED;

		}
		/*
		 * TODO: what else ??
		 */
	}
	if (!(mask & SIW_QP_ATTR_STATE))
		return 0;

	pr_debug(DBG_CM "(QP%d): SIW QP state: %s => %s\n", QP_ID(qp),
		siw_qp_state_to_string[qp->attrs.state],
		siw_qp_state_to_string[attrs->state]);


	switch (qp->attrs.state) {

	case SIW_QP_STATE_IDLE:
	case SIW_QP_STATE_RTR:

		switch (attrs->state) {

		case SIW_QP_STATE_RTS:

			if ((mask & init_to_rts_mask) != init_to_rts_mask) {
				pr_debug("(QP%d): socket, ird, and/or ord missing\n",
						QP_ID(qp));
				rv = -EINVAL;
				break;
			}
			pr_debug(DBG_CM "(QP%d): Enter RTS: "
				"peer 0x%08x, local 0x%08x\n", QP_ID(qp),
				qp->cep->llp.raddr.sin_addr.s_addr,
				qp->cep->llp.laddr.sin_addr.s_addr);

			qp->attrs.state = SIW_QP_STATE_RTS;

			qp->attrs.irq_size
				= attrs->irq_size ? attrs->irq_size : 1;
			qp->attrs.orq_size
				= attrs->orq_size ? attrs->orq_size : 1;

			notify_established(
				siw_ctx_ofa2siw(qp->ofa_qp.uobject->context),
				qp);
			break;

		case SIW_QP_STATE_ERROR:
			qp->attrs.state = SIW_QP_STATE_ERROR;
			if (qp->cep) {
				siw_cep_put(qp->cep);
				qp->cep = NULL;
			}
			break;

		case SIW_QP_STATE_RTR:
			qp->attrs.state = SIW_QP_STATE_RTR;
			break;

		default:
			pr_debug(DBG_CM
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case SIW_QP_STATE_RTS:

		switch (attrs->state) {

		case SIW_QP_STATE_CLOSING:
		case SIW_QP_STATE_TERMINATE:
		case SIW_QP_STATE_ERROR:
			qp->attrs.state = attrs->state;
			drop_conn = 1;
			break;

		default:
			pr_debug(
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case SIW_QP_STATE_TERMINATE:

		switch (attrs->state) {

		case SIW_QP_STATE_ERROR:
			qp->attrs.state = SIW_QP_STATE_ERROR;

			break;

		default:
			pr_debug(
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
		}
		break;

	case SIW_QP_STATE_CLOSING:

		switch (attrs->state) {

		case SIW_QP_STATE_IDLE:
			qp->attrs.state = SIW_QP_STATE_IDLE;

			break;

		case SIW_QP_STATE_CLOSING:
			/*
			 * The LLP may already moved the QP to closing
			 * due to graceful peer close init
			 */
			break;

		case SIW_QP_STATE_ERROR:
			/*
			 * QP was moved to CLOSING by LLP event
			 * not yet seen by user.
			 */
			qp->attrs.state = SIW_QP_STATE_ERROR;

			break;

		default:
			pr_debug(DBG_CM
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			return -ECONNABORTED;
		}
		break;

	default:
		pr_debug(DBG_CM " NOP: State: %d\n", qp->attrs.state);
		break;
	}
	if (drop_conn)
		siw_qp_cm_drop(qp, 0);

	return rv;
}

struct ib_qp *siw_get_ofaqp(struct ib_device *ofa_dev, int id)
{
	struct siw_qp *qp =  siw_qp_id2obj(siw_dev_ofa2siw(ofa_dev), id);

	pr_debug(DBG_OBJ ": dev_name: %s, OFA QPID: %d, QP: %p\n",
		ofa_dev->name, id, qp);
	if (qp) {
		/*
		 * siw_qp_id2obj() increments object reference count
		 */
		siw_qp_put(qp);
		pr_debug(DBG_OBJ " QPID: %d\n", QP_ID(qp));
		return &qp->ofa_qp;
	}
	return (struct ib_qp *)NULL;
}
