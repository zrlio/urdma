/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Patrick MacArthur <pam@zurich.ibm.com>
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

#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "urdma.h"
#include "verbs.h"
#include "obj.h"
#include "cm.h"

static char ib_qp_state_to_string[IB_QPS_ERR+1][sizeof "RESET"] = {
	[IB_QPS_RESET]	= "RESET",
	[IB_QPS_INIT]	= "INIT",
	[IB_QPS_RTR]	= "RTR",
	[IB_QPS_RTS]	= "RTS",
	[IB_QPS_SQD]	= "SQD",
	[IB_QPS_SQE]	= "SQE",
	[IB_QPS_ERR]	= "ERR"
};

static int ib_qp_state_to_siw_qp_state[IB_QPS_ERR+1] = {
	[IB_QPS_RESET]	= SIW_QP_STATE_IDLE,
	[IB_QPS_INIT]	= SIW_QP_STATE_IDLE,
	[IB_QPS_RTR]	= SIW_QP_STATE_RTR,
	[IB_QPS_RTS]	= SIW_QP_STATE_RTS,
	[IB_QPS_SQD]	= SIW_QP_STATE_CLOSING,
	[IB_QPS_SQE]	= SIW_QP_STATE_TERMINATE,
	[IB_QPS_ERR]	= SIW_QP_STATE_ERROR
};

static inline struct siw_pd *siw_pd_ofa2siw(struct ib_pd *ofa_pd)
{
	return container_of(ofa_pd, struct siw_pd, ofa_pd);
}

static inline struct siw_ucontext *siw_ctx_ofa2siw(struct ib_ucontext *ofa_ctx)
{
	return container_of(ofa_ctx, struct siw_ucontext, ib_ucontext);
}

static inline struct siw_qp *siw_qp_ofa2siw(struct ib_qp *ofa_qp)
{
	return container_of(ofa_qp, struct siw_qp, ofa_qp);
}

static inline struct siw_cq *siw_cq_ofa2siw(struct ib_cq *ofa_cq)
{
	return container_of(ofa_cq, struct siw_cq, ofa_cq);
}

int
siw_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
	return -ENOSYS;
}

static ssize_t siw_event_file_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *pos)
{
	struct siw_event_file *file;
	struct urdma_event_storage event;
	struct urdma_cq_event *cq_event;
	struct siw_cq *cq;
	ssize_t rv;

	if (count > sizeof(event)) {
		return -EINVAL;
	}

	if (copy_from_user(&event, buf, count)) {
		return -EFAULT;
	}

	file = filp->private_data;
	spin_lock_irq(&file->lock);
	if (!file->ctx) {
		rv = -EINVAL;
		goto out;
	}

	switch (event.event_type) {
	case SIW_EVENT_COMP_POSTED:
		if (count != sizeof(*cq_event)) {
			rv = -EINVAL;
			goto out;
		}
		cq_event = (struct urdma_cq_event *)&event;
		cq = siw_cq_id2obj(file->ctx->sdev, cq_event->cq_id);
		if (WARN_ON_ONCE(!cq)) {
			rv = -EINVAL;
			goto out;
		}
		cq->ofa_cq.comp_handler(&cq->ofa_cq, cq->ofa_cq.cq_context);
		siw_cq_put(cq);
		break;
	default:
		pr_debug(" got invalid event type %u\n", event.event_type);
		rv = -EINVAL;
		goto out;
	}

	rv = count;

out:
	spin_unlock_irq(&file->lock);
	return rv;
}

static int siw_event_file_release(struct inode *ignored, struct file *filp)
{
	struct siw_event_file *file = filp->private_data;

	if (file->ctx) {
		file->ctx->event_file = NULL;
	}
	kfree(file);
	return 0;
}

static struct file_operations siw_event_file_ops = {
	.owner = THIS_MODULE,
	.write = &siw_event_file_write,
	.release = &siw_event_file_release,
};


static struct file *siw_event_file_new(struct siw_ucontext *ctx, int *event_fd)
{
	struct file *filp;
	int rv;

	/* Create a file to communicate events between our userspace verbs
	 * library and this kernel verbs driver, which cannot be communicated
	 * (cleanly) using the uverbs interface. */
	rv = get_unused_fd_flags(O_CLOEXEC);
	if (rv < 0) {
		goto out;
	}
	*event_fd = rv;
	ctx->event_file = kzalloc(sizeof(*ctx->event_file), GFP_KERNEL);
	if (!ctx->event_file) {
		rv = -ENOMEM;
		goto free_fd;
	}
	ctx->event_file->ctx = ctx;
	spin_lock_init(&ctx->event_file->lock);
	filp = anon_inode_getfile("[siwevent]", &siw_event_file_ops,
			ctx->event_file, O_WRONLY|O_NONBLOCK);
	if (IS_ERR(filp)) {
		rv = PTR_ERR(filp);
		goto free_event_file;
	}
	return filp;

free_event_file:
	kfree(ctx->event_file);
free_fd:
	put_unused_fd(*event_fd);
out:
	return ERR_PTR(rv);
}


/* Empty implementation which allows verbs de-initialization to continue despite
 * user applications continuing to run. */
void urdma_disassociate_ucontext(struct ib_ucontext *ctx)
{
}


struct ib_ucontext *siw_alloc_ucontext(struct ib_device *ofa_dev,
				       struct ib_udata *udata)
{
	struct siw_ucontext *ctx = NULL;
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);
	int rv;

	pr_debug(DBG_CM "(device=%s)\n", ofa_dev->name);

	if (atomic_inc_return(&sdev->num_ctx) > SIW_MAX_CONTEXT) {
		pr_debug(": Out of CONTEXT's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		rv = -ENOMEM;
		goto err_out;
	}

	ctx->sdev = sdev;
	if (udata) {
		struct urdma_uresp_alloc_ctx uresp;
		struct file *filp;

		memset(&uresp, 0, sizeof uresp);
		uresp.dev_id = sdev->attrs.vendor_part_id;
		filp = siw_event_file_new(ctx, &uresp.event_fd);
		if (IS_ERR(filp)) {
			rv = PTR_ERR(filp);
			goto err_out;
		}

		rv = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (rv) {
			fput(filp);
			kfree(ctx->event_file);
			put_unused_fd(uresp.event_fd);
			goto err_out;
		}

		fd_install(uresp.event_fd, filp);
	}
	return &ctx->ib_ucontext;

err_out:
	if (ctx)
		kfree(ctx);

	atomic_dec(&sdev->num_ctx);
	return ERR_PTR(rv);
}

int siw_dealloc_ucontext(struct ib_ucontext *ofa_ctx)
{
	struct siw_ucontext *ctx = siw_ctx_ofa2siw(ofa_ctx);
	struct siw_event_file *file = ctx->event_file;

	if (file) {
		spin_lock_irq(&file->lock);
		file->ctx = NULL;
		spin_unlock_irq(&file->lock);
	}
	atomic_dec(&ctx->sdev->num_ctx);
	kfree(ctx);
	return 0;
}

#ifndef HAVE_IB_QUERY_DEVICE_UDATA
int siw_query_device(struct ib_device *ofa_dev, struct ib_device_attr *attr)
#else
int siw_query_device(struct ib_device *ofa_dev, struct ib_device_attr *attr,
		struct ib_udata *udata)
#endif
{
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);

	memset(attr, 0, sizeof *attr);

	attr->max_mr_size = -1ULL;
	attr->sys_image_guid = sdev->ofa_dev.node_guid;
	attr->vendor_id = sdev->attrs.vendor_id;
	attr->vendor_part_id = sdev->attrs.vendor_part_id;
	attr->max_qp = sdev->attrs.max_qp;

	attr->device_cap_flags = sdev->attrs.cap_flags;
	attr->max_cq = sdev->attrs.max_cq;
	attr->max_pd = sdev->attrs.max_pd;

	return 0;
}

/*
 * Approximate translation of real MTU for IB.
 *
 * TODO: is that needed for RNIC's? We may have a medium
 *       which reports MTU of 64kb and have to degrade to 4k??
 */
static inline enum ib_mtu siw_mtu_net2ofa(unsigned short mtu)
{
	if (mtu >= 4096)
		return IB_MTU_4096;
	if (mtu >= 2048)
		return IB_MTU_2048;
	if (mtu >= 1024)
		return IB_MTU_1024;
	if (mtu >= 512)
		return IB_MTU_512;
	if (mtu >= 256)
		return IB_MTU_256;
	return IB_MTU_4096;
}

int siw_query_port(struct ib_device *ofa_dev, u8 port,
		     struct ib_port_attr *attr)
{
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);

	memset(attr, 0, sizeof *attr);

	attr->state = sdev->state;
	if (WARN(!sdev->netdev, "No netdev associated with device %s",
				ofa_dev->name)) {
		attr->max_mtu = IB_MTU_1024;
	} else {
		attr->max_mtu = siw_mtu_net2ofa(sdev->netdev->mtu);
	}
	attr->active_mtu = attr->max_mtu;
	attr->gid_tbl_len = 1;
	attr->port_cap_flags = IB_PORT_CM_SUP;	/* ?? */
	attr->port_cap_flags |= IB_PORT_DEVICE_MGMT_SUP;
	attr->max_msg_sz = -1;
	attr->pkey_tbl_len = 1;
	attr->active_width = 2;
	attr->active_speed = 2;
	attr->phys_state = sdev->state == IB_PORT_ACTIVE ? 5 : 3;
	/*
	 * All zero
	 *
	 * attr->lid = 0;
	 * attr->bad_pkey_cntr = 0;
	 * attr->qkey_viol_cntr = 0;
	 * attr->sm_lid = 0;
	 * attr->lmc = 0;
	 * attr->max_vl_num = 0;
	 * attr->sm_sl = 0;
	 * attr->subnet_timeout = 0;
	 * attr->init_type_repy = 0;
	 */
	return 0;
}

int siw_query_pkey(struct ib_device *ofa_dev, u8 port, u16 idx, u16 *pkey)
{
	/* Report the default pkey */
	*pkey = 0xffff;
	return 0;
}

int siw_query_gid(struct ib_device *ofa_dev, u8 port, int idx,
		   union ib_gid *gid)
{
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);

	/* subnet_prefix == interface_id == 0; */
	memset(gid, 0, sizeof *gid);
	if (!WARN(!sdev->netdev, "No netdev associated with device %s",
				ofa_dev->name)) {
		memcpy(&gid->raw[0], sdev->netdev->dev_addr, 6);
	}

	return 0;
}

struct ib_pd *siw_alloc_pd(struct ib_device *ofa_dev,
			   struct ib_ucontext *context, struct ib_udata *udata)
{
	struct siw_pd	*pd = NULL;
	struct siw_dev	*sdev  = siw_dev_ofa2siw(ofa_dev);
	int rv;

	if (atomic_inc_return(&sdev->num_pd) > SIW_MAX_PD) {
		pr_debug(": Out of PD's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	pd = kmalloc(sizeof *pd, GFP_KERNEL);
	if (!pd) {
		pr_debug(": malloc\n");
		rv = -ENOMEM;
		goto err_out;
	}
	rv = siw_pd_add(sdev, pd);
	if (rv) {
		pr_debug(": siw_pd_add\n");
		rv = -ENOMEM;
		goto err_out;
	}
	if (context) {
		if (ib_copy_to_udata(udata, &pd->hdr.id, sizeof pd->hdr.id)) {
			rv = -EFAULT;
			goto err_out_idr;
		}
	}
	return &pd->ofa_pd;

err_out_idr:
	siw_remove_obj(&sdev->idr_lock, &sdev->pd_idr, &pd->hdr);
err_out:
	kfree(pd);
	atomic_dec(&sdev->num_pd);

	return ERR_PTR(rv);
}

int siw_dealloc_pd(struct ib_pd *ofa_pd)
{
	struct siw_pd	*pd = siw_pd_ofa2siw(ofa_pd);
	struct siw_dev	*sdev = siw_dev_ofa2siw(ofa_pd->device);

	siw_remove_obj(&sdev->idr_lock, &sdev->pd_idr, &pd->hdr);
	siw_pd_put(pd);

	return 0;
}

struct ib_ah *siw_create_ah(struct ib_pd *pd, struct ib_ah_attr *attr)
{
	return ERR_PTR(-ENOSYS);
}

int siw_destroy_ah(struct ib_ah *ah)
{
	return -ENOSYS;
}


void siw_qp_get_ref(struct ib_qp *ofa_qp)
{
	struct siw_qp	*qp = siw_qp_ofa2siw(ofa_qp);

	pr_debug(DBG_OBJ DBG_CM "(QP%d): Get Reference\n", QP_ID(qp));
	siw_qp_get(qp);
}


void siw_qp_put_ref(struct ib_qp *ofa_qp)
{
	struct siw_qp	*qp = siw_qp_ofa2siw(ofa_qp);

	pr_debug(DBG_OBJ DBG_CM "(QP%d): Put Reference\n", QP_ID(qp));
	siw_qp_put(qp);
}

#ifndef HAVE_IB_PROCESS_MAD_SIZES
int siw_no_mad(struct ib_device *ofa_dev, int flags, u8 port,
			    struct ib_wc *wc, struct ib_grh *grh,
			    struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	return -ENOSYS;
}
#else
int siw_no_mad(struct ib_device *ofa_dev, int flags, u8 port,
			    const struct ib_wc *wc, const struct ib_grh *grh,
			    const struct ib_mad_hdr *in_mad, size_t in_mad_size,
			    struct ib_mad_hdr *out_mad, size_t *out_mad_size,
			    u16 *out_mad_pkey_index)
{
	return -ENOSYS;
}
#endif


/*
 * siw_create_qp()
 *
 * Create QP of requested size on given device.
 *
 * @ofa_pd:	OFA PD contained in siw PD
 * @attrs:	Initial QP attributes.
 * @udata:	used to provide QP ID, SQ and RQ size back to user.
 */

struct ib_qp *siw_create_qp(struct ib_pd *ofa_pd,
			    struct ib_qp_init_attr *attrs,
			    struct ib_udata *udata)
{
	struct siw_qp			*qp = NULL;
	struct siw_pd			*pd = siw_pd_ofa2siw(ofa_pd);
	struct ib_device		*ofa_dev = ofa_pd->device;
	struct siw_dev			*sdev = siw_dev_ofa2siw(ofa_dev);
	struct siw_cq			*scq = NULL, *rcq = NULL;

	int rv = 0;

	pr_debug(DBG_OBJ DBG_CM ": new QP on device %s\n",
		ofa_dev->name);

	if (!ofa_pd->uobject) {
		pr_debug(": This driver does not support kernel clients\n");
		return ERR_PTR(-EINVAL);
	}

	if (atomic_inc_return(&sdev->num_qp) > SIW_MAX_QP) {
		pr_debug(": Out of QP's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	if (attrs->qp_type != IB_QPT_RC) {
		pr_debug(": Only RC QP's supported\n");
		rv = -EINVAL;
		goto err_out;
	}
	if (attrs->srq) {
		pr_debug(": SRQ is not supported\n");
		rv = -EINVAL;
		goto err_out;
	}

	scq = siw_cq_id2obj(sdev, ((struct siw_cq *)attrs->send_cq)->hdr.id);
	rcq = siw_cq_id2obj(sdev, ((struct siw_cq *)attrs->recv_cq)->hdr.id);

	if (!scq || !rcq) {
		pr_debug(DBG_OBJ ": Fail: SCQ: 0x%p, RCQ: 0x%p\n",
			scq, rcq);
		rv = -EINVAL;
		goto err_out;
	}
	qp = kzalloc(sizeof *qp, GFP_KERNEL);
	if (!qp) {
		pr_debug(": kzalloc\n");
		rv = -ENOMEM;
		goto err_out;
	}

	init_rwsem(&qp->state_lock);

	rv = siw_qp_add(sdev, qp);
	if (rv)
		goto err_out;

	qp->pd  = pd;
	qp->scq = scq;
	qp->rcq = rcq;
	qp->attrs.state = SIW_QP_STATE_IDLE;

	if (udata) {
		struct urdma_udata_create_qp ureq;
		struct urdma_uresp_create_qp uresp;

		rv = ib_copy_from_udata(&ureq, udata, sizeof(ureq));
		if (rv)
			goto err_out_idr;
		qp->attrs.irq_size = ureq.ird_max;
		qp->attrs.orq_size = ureq.ord_max;
		qp->attrs.urdma_devid = ureq.urdmad_dev_id;
		qp->attrs.urdma_qp_id = ureq.urdmad_qp_id;
		qp->attrs.urdma_rxq = ureq.rxq;
		qp->attrs.urdma_txq = ureq.txq;

		memset(&uresp, 0, sizeof uresp);
		uresp.kmod_qp_id = QP_ID(qp);

		rv = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (rv)
			goto err_out_idr;
	}

	qp->ofa_qp.qp_num = QP_ID(qp);

	siw_pd_get(pd);

	return &qp->ofa_qp;

err_out_idr:
	siw_remove_obj(&sdev->idr_lock, &sdev->qp_idr, &qp->hdr);
err_out:
	if (scq)
		siw_cq_put(scq);
	if (rcq)
		siw_cq_put(rcq);

	if (qp) {
		kfree(qp);
	}
	atomic_dec(&sdev->num_qp);

	return ERR_PTR(rv);
}

/*
 * Minimum siw_query_qp() verb interface.
 *
 * @qp_attr_mask is not used but all available information is provided
 */
int siw_query_qp(struct ib_qp *ofa_qp, struct ib_qp_attr *qp_attr,
		 int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	return -ENOSYS;
}

int siw_ofed_modify_qp(struct ib_qp *ofa_qp, struct ib_qp_attr *attr,
		       int attr_mask, struct ib_udata *udata)
{
	struct siw_qp_attrs	new_attrs;
	enum siw_qp_attr_mask	siw_attr_mask = 0;
	struct siw_qp		*qp = siw_qp_ofa2siw(ofa_qp);
	int			rv = 0;

	pr_debug(DBG_CM "(QP%d) modify_qp attr_mask %x\n",
			QP_ID(qp), attr_mask);

	memset(&new_attrs, 0, sizeof new_attrs);

	if (attr_mask & IB_QP_ACCESS_FLAGS) {

		siw_attr_mask |= SIW_QP_ATTR_ACCESS_FLAGS;

		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			new_attrs.flags |= SIW_RDMA_READ_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			new_attrs.flags |= SIW_RDMA_WRITE_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_MW_BIND)
			new_attrs.flags |= SIW_RDMA_BIND_ENABLED;
	}
	if (attr_mask & IB_QP_STATE) {
		pr_debug(DBG_CM "(QP%d): Desired IB QP state: %s\n",
			   QP_ID(qp), ib_qp_state_to_string[attr->qp_state]);

		new_attrs.state = ib_qp_state_to_siw_qp_state[attr->qp_state];

		/* TODO: SIW_QP_STATE_UNDEF is currently not possible ... */
		if (new_attrs.state == SIW_QP_STATE_UNDEF)
			return -EINVAL;

		siw_attr_mask |= SIW_QP_ATTR_STATE;
	}

	down_write(&qp->state_lock);

	rv = siw_qp_modify(qp, &new_attrs, siw_attr_mask);

	up_write(&qp->state_lock);

	pr_debug(DBG_CM "(QP%d): Exit with %d\n", QP_ID(qp), rv);
	return rv;
}

int siw_destroy_qp(struct ib_qp *ofa_qp)
{
	struct siw_qp		*qp = siw_qp_ofa2siw(ofa_qp);
	struct siw_qp_attrs	qp_attrs;

	pr_debug(DBG_CM "(QP%d): SIW QP state=%d, cep=0x%p\n",
		QP_ID(qp), qp->attrs.state, qp->cep);

	/*
	 * Mark QP as in process of destruction to prevent from eventual async
	 * callbacks to OFA core
	 */
	qp->attrs.flags |= SIW_QP_IN_DESTROY;

	down_write(&qp->state_lock);

	qp_attrs.state = SIW_QP_STATE_ERROR;
	(void)siw_qp_modify(qp, &qp_attrs, SIW_QP_ATTR_STATE);

	if (qp->cep) {
		siw_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);

	/* Drop references */
	siw_cq_put(qp->scq);
	siw_cq_put(qp->rcq);
	siw_pd_put(qp->pd);
	qp->scq = qp->rcq = NULL;

	siw_qp_put(qp);

	return 0;
}

/*
 * siw_post_send()
 *
 * Post a list of S-WR's to a SQ.
 *
 * @ofa_qp:	OFA QP contained in siw QP
 * @wr:		Null terminated list of user WR's
 * @bad_wr:	Points to failing WR in case of synchronous failure.
 */
int siw_post_send(struct ib_qp *ofa_qp, struct ib_send_wr *wr,
		  struct ib_send_wr **bad_wr)
{
	return -ENOSYS;
}

/*
 * siw_post_receive()
 *
 * Post a list of R-WR's to a RQ.
 *
 * @ofa_qp:	OFA QP contained in siw QP
 * @wr:		Null terminated list of user WR's
 * @bad_wr:	Points to failing WR in case of synchronous failure.
 */
int siw_post_receive(struct ib_qp *ofa_qp, struct ib_recv_wr *wr,
		     struct ib_recv_wr **bad_wr)
{
	return -ENOSYS;
}

int siw_destroy_cq(struct ib_cq *ofa_cq)
{
	struct siw_cq		*cq  = siw_cq_ofa2siw(ofa_cq);
	struct ib_device	*ofa_dev = ofa_cq->device;
	struct siw_dev		*sdev = siw_dev_ofa2siw(ofa_dev);

	siw_remove_obj(&sdev->idr_lock, &sdev->cq_idr, &cq->hdr);
	siw_cq_put(cq);

	return 0;
}

#ifndef HAVE_STRUCT_IB_CQ_INIT_ATTR
struct ib_cq_init_attr {
	unsigned int cqe;
	int comp_vector;
	u32 flags;
};
#endif

/*
 * siw_create_cq()
 *
 * Create CQ of requested size on given device.
 *
 * @ofa_dev:	OFA device contained in siw device
 * @size:	maximum number of CQE's allowed.
 * @ib_context: user context.
 * @udata:	used to provide CQ ID back to user.
 */
static struct ib_cq *do_siw_create_cq(struct ib_device *ofa_dev,
				      const struct ib_cq_init_attr *init_attr,
				      struct ib_ucontext *ib_context,
				      struct ib_udata *udata)
{
	struct siw_ucontext		*ctx;
	struct siw_cq			*cq = NULL;
	struct siw_dev			*sdev = siw_dev_ofa2siw(ofa_dev);
	struct urdma_uresp_create_cq	uresp;
	int rv;

	if (!ofa_dev) {
		pr_warn("NO OFA device\n");
		rv = -ENODEV;
		goto err_out;
	}
	if (atomic_inc_return(&sdev->num_cq) > SIW_MAX_CQ) {
		pr_debug(": Out of CQ's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	if (init_attr->cqe < 1) {
		pr_debug(": CQE: %d\n", init_attr->cqe);
		rv = -EINVAL;
		goto err_out;
	}
	cq = kzalloc(sizeof *cq, GFP_KERNEL);
	if (!cq) {
		pr_debug(":  kmalloc\n");
		rv = -ENOMEM;
		goto err_out;
	}
	cq->ofa_cq.cqe = init_attr->cqe;

	if (!ib_context) {
		rv = -EINVAL;
		goto err_out;
	}
	ctx = siw_ctx_ofa2siw(ib_context);

	rv = siw_cq_add(sdev, cq);
	if (rv)
		goto err_out;

	uresp.cq_id = OBJ_ID(cq);

	rv = ib_copy_to_udata(udata, &uresp, sizeof uresp);
	if (rv)
		goto err_out_idr;

	return &cq->ofa_cq;

err_out_idr:
	siw_remove_obj(&sdev->idr_lock, &sdev->cq_idr, &cq->hdr);
err_out:
	pr_debug(DBG_OBJ ": CQ creation failed %d", rv);

	kfree(cq);
	atomic_dec(&sdev->num_cq);

	return ERR_PTR(rv);
}

#ifndef HAVE_STRUCT_IB_CQ_INIT_ATTR
struct ib_cq *siw_create_cq(struct ib_device *ofa_dev, int size,
			    int vec, struct ib_ucontext *ib_context,
			    struct ib_udata *udata)
{
	struct ib_cq_init_attr init_attr;
	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cqe = size;
	init_attr.comp_vector = vec;
	return do_siw_create_cq(ofa_dev, &init_attr, ib_context, udata);
}
#else
struct ib_cq *siw_create_cq(struct ib_device *ofa_dev,
			    const struct ib_cq_init_attr *init_attr,
			    struct ib_ucontext *ib_context,
			    struct ib_udata *udata)
{
	return do_siw_create_cq(ofa_dev, init_attr, ib_context, udata);
}
#endif

/*
 * siw_poll_cq()
 *
 * Reap CQ entries if available and copy work completion status into
 * array of WC's provided by caller. Returns number of reaped CQE's.
 *
 * @ofa_cq:	OFA CQ contained in siw CQ.
 * @num_cqe:	Maximum number of CQE's to reap.
 * @wc:		Array of work completions to be filled by siw.
 */
int siw_poll_cq(struct ib_cq *ofa_cq, int num_cqe, struct ib_wc *wc)
{
	return -ENOSYS;
}

/*
 * siw_req_notify_cq()
 *
 * Handled entirely in userspace.
 *
 * @ofa_cq:	OFA CQ contained in siw CQ.
 * @flags:	Requested notification flags.
 */
int siw_req_notify_cq(struct ib_cq *ofa_cq, enum ib_cq_notify_flags flags)
{
	return 0;
}

/*
 * siw_dereg_mr()
 *
 * Release Memory Region.
 *
 * @ofa_mr:     OFA MR contained in siw MR.
 */
int siw_dereg_mr(struct ib_mr *ofa_mr)
{
	return -ENOSYS;
}

/*
 * siw_reg_user_mr()
 *
 * Register Memory Region.
 *
 * @ofa_pd:	OFA PD contained in siw PD.
 * @start:	starting address of MR (virtual address)
 * @len:	len of MR
 * @rnic_va:	not used by siw
 * @rights:	MR access rights
 * @udata:	user buffer to communicate STag and Key.
 */
struct ib_mr *siw_reg_user_mr(struct ib_pd *ofa_pd, u64 start, u64 len,
			      u64 rnic_va, int rights, struct ib_udata *udata)
{
	return ERR_PTR(-ENOSYS);
}


/*
 * siw_get_dma_mr()
 *
 * Create a (empty) DMA memory region, where no umem is attached.
 * All DMA addresses are created via siw_dma_mapping_ops - which
 * will return just kernel virtual addresses, since siw runs on top
 * of TCP kernel sockets.
 */
struct ib_mr *siw_get_dma_mr(struct ib_pd *ofa_pd, int rights)
{
	return ERR_PTR(-ENOSYS);
}


/*
 * siw_create_srq()
 *
 * Create Shared Receive Queue of attributes @init_attrs
 * within protection domain given by @ofa_pd.
 *
 * @ofa_pd:	OFA PD contained in siw PD.
 * @init_attrs:	SRQ init attributes.
 * @udata:	not used by siw.
 */
struct ib_srq *siw_create_srq(struct ib_pd *ofa_pd,
			      struct ib_srq_init_attr *init_attrs,
			      struct ib_udata *udata)
{
	return ERR_PTR(-ENOSYS);
}

/*
 * siw_modify_srq()
 *
 * Modify SRQ. The caller may resize SRQ and/or set/reset notification
 * limit and (re)arm IB_EVENT_SRQ_LIMIT_REACHED notification.
 *
 * NOTE: it is unclear if OFA allows for changing the MAX_SGE
 * parameter. siw_modify_srq() does not check the attrs->max_sge param.
 */
int siw_modify_srq(struct ib_srq *ofa_srq, struct ib_srq_attr *attrs,
		   enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	return -ENOSYS;
}

/*
 * siw_query_srq()
 *
 * Query SRQ attributes.
 */
int siw_query_srq(struct ib_srq *ofa_srq, struct ib_srq_attr *attrs)
{
	return -ENOSYS;
}

/*
 * siw_destroy_srq()
 *
 * Destroy SRQ.
 * It is assumed that the SRQ is not referenced by any
 * QP anymore - the code trusts the OFA environment to keep track
 * of QP references.
 */
int siw_destroy_srq(struct ib_srq *ofa_srq)
{
	return -ENOSYS;
}


/*
 * siw_post_srq_recv()
 *
 * Post a list of receive queue elements to SRQ.
 * NOTE: The function does not check or lock a certain SRQ state
 *       during the post operation. The code simply trusts the
 *       OFA environment.
 *
 * @ofa_srq:	OFA SRQ contained in siw SRQ
 * @wr:		List of R-WR's
 * @bad_wr:	Updated to failing WR if posting fails.
 */
int siw_post_srq_recv(struct ib_srq *ofa_srq, struct ib_recv_wr *wr,
		      struct ib_recv_wr **bad_wr)
{
	return -ENOSYS;
}

#ifdef HAVE_IB_GET_PORT_IMMUTABLE
/*
 * urdma_port_immutable()
 *
 * Set immutable port attributes.
 *
 * @ofa_dev:	OFA device structure
 * @port_num:	port number
 * @immutable:	structure containing immutable fields to fill in
 */
int urdma_port_immutable(struct ib_device *ibdev, u8 port_num,
			struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	err = siw_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->core_cap_flags = RDMA_CORE_PORT_IWARP;

	return 0;
}
#endif
