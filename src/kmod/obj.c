/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Patrick MacArthur <patrick@patrickmacarthur.net>
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

#include <linux/spinlock.h>
#include <linux/kref.h>

#include "urdma.h"
#include "obj.h"
#include "cm.h"


void siw_objhdr_init(struct siw_objhdr *hdr)
{
	kref_init(&hdr->ref);
}

void siw_idr_init(struct siw_dev *sdev)
{
	spin_lock_init(&sdev->idr_lock);

	idr_init(&sdev->qp_idr);
	idr_init(&sdev->cq_idr);
	idr_init(&sdev->pd_idr);
}

void siw_idr_release(struct siw_dev *sdev)
{
	idr_destroy(&sdev->qp_idr);
	idr_destroy(&sdev->cq_idr);
	idr_destroy(&sdev->pd_idr);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
static inline int siw_add_obj(spinlock_t *lock, struct idr *idr,
			      struct siw_objhdr *obj)
{
	u32		pre_id, id;
	unsigned long	flags;
	int		rv;

	get_random_bytes(&pre_id, sizeof pre_id);
	pre_id &= 0xffff;
again:
	do {
		if (!(idr_pre_get(idr, GFP_KERNEL)))
			return -ENOMEM;

		spin_lock_irqsave(lock, flags);
		rv = idr_get_new_above(idr, obj, pre_id, &id);
		spin_unlock_irqrestore(lock, flags);

	} while  (rv == -EAGAIN);

	if (rv == 0) {
		siw_objhdr_init(obj);
		obj->id = id;
		pr_debug(DBG_OBJ "(OBJ%d): IDR New Object\n", id);
	} else if (rv == -ENOSPC && pre_id != 1) {
		pre_id = 1;
		goto again;
	} else {
		pr_debug(DBG_OBJ "(OBJ??): IDR New Object failed!\n");
	}
	return rv;
}
#else
static inline int siw_add_obj(spinlock_t *lock, struct idr *idr,
			      struct siw_objhdr *obj)
{
	unsigned long flags;
	int id, pre_id;

	do {
		get_random_bytes(&pre_id, sizeof pre_id);
		pre_id &= 0xffffff;
	} while (pre_id == 0);
again:
	spin_lock_irqsave(lock, flags);
	id = idr_alloc(idr, obj, pre_id, 0xffffff - 1, GFP_KERNEL);
	spin_unlock_irqrestore(lock, flags);

	if (id > 0) {
		siw_objhdr_init(obj);
		obj->id = id;
		pr_debug(DBG_OBJ "(OBJ%d): IDR New Object\n", id);
	} else if (id == -ENOSPC && pre_id != 1) {
		pre_id = 1;
		goto again;
	} else {
		if (WARN_ONCE(id == 0, "(OBJ??): IDR New Object failed!\n")) {
			id = -EINVAL;
		}
	}
	return id > 0 ? 0 : id;
}
#endif

static inline struct siw_objhdr *siw_get_obj(struct idr *idr, int id)
{
	struct siw_objhdr *obj;

	obj = idr_find(idr, id);
	if (obj)
		kref_get(&obj->ref);

	return obj;
}

struct siw_cq *siw_cq_id2obj(struct siw_dev *sdev, int id)
{
	struct siw_objhdr *obj = siw_get_obj(&sdev->cq_idr, id);
	if (obj) {
		pr_debug(DBG_OBJ "(CQ%d): New refcount: %d\n",
			obj->id, kref_read(&obj->ref));
		return container_of(obj, struct siw_cq, hdr);
	}

	return NULL;
}

struct siw_qp *siw_qp_id2obj(struct siw_dev *sdev, int id)
{
	struct siw_objhdr *obj = siw_get_obj(&sdev->qp_idr, id);
	if (obj) {
		pr_debug(DBG_OBJ "(QP%d): New refcount: %d\n",
			obj->id, kref_read(&obj->ref));
		return container_of(obj, struct siw_qp, hdr);
	}

	return NULL;
}

int siw_qp_add(struct siw_dev *sdev, struct siw_qp *qp)
{
	int rv = siw_add_obj(&sdev->idr_lock, &sdev->qp_idr, &qp->hdr);
	if (!rv) {
		pr_debug(DBG_OBJ "(QP%d): New Object\n", QP_ID(qp));
		qp->hdr.sdev = sdev;
	}
	return rv;
}

int siw_cq_add(struct siw_dev *sdev, struct siw_cq *cq)
{
	int rv = siw_add_obj(&sdev->idr_lock, &sdev->cq_idr, &cq->hdr);
	if (!rv) {
		pr_debug(DBG_OBJ "(CQ%d): New Object\n", cq->hdr.id);
		cq->hdr.sdev = sdev;
	}
	return rv;
}

int siw_pd_add(struct siw_dev *sdev, struct siw_pd *pd)
{
	int rv = siw_add_obj(&sdev->idr_lock, &sdev->pd_idr, &pd->hdr);
	if (!rv) {
		pr_debug(DBG_OBJ "(PD%d): New Object\n", pd->hdr.id);
		pd->hdr.sdev = sdev;
	}
	return rv;
}

void siw_remove_obj(spinlock_t *lock, struct idr *idr,
		      struct siw_objhdr *hdr)
{
	unsigned long	flags;

	pr_debug(DBG_OBJ "(OBJ%d): IDR Remove Object\n", hdr->id);

	spin_lock_irqsave(lock, flags);
	idr_remove(idr, hdr->id);
	spin_unlock_irqrestore(lock, flags);
}


/********** routines to put objs back and free if no ref left *****/

static void siw_free_cq(struct kref *ref)
{
	struct siw_cq *cq =
		(container_of(container_of(ref, struct siw_objhdr, ref),
			      struct siw_cq, hdr));

	pr_debug(DBG_OBJ "(CQ%d): Free Object\n", cq->hdr.id);

	atomic_dec(&cq->hdr.sdev->num_cq);
	kfree(cq);
}

static void siw_free_qp(struct kref *ref)
{
	struct siw_qp	*qp =
		container_of(container_of(ref, struct siw_objhdr, ref),
			     struct siw_qp, hdr);
	struct siw_dev	*sdev = qp->hdr.sdev;

	pr_debug(DBG_OBJ DBG_CM "(QP%d): Free Object\n", QP_ID(qp));

	if (qp->cep)
		siw_cep_put(qp->cep);

	siw_remove_obj(&sdev->idr_lock, &sdev->qp_idr, &qp->hdr);

	atomic_dec(&sdev->num_qp);
	kfree(qp);
}

static void siw_free_pd(struct kref *ref)
{
	struct siw_pd	*pd =
		container_of(container_of(ref, struct siw_objhdr, ref),
			     struct siw_pd, hdr);

	pr_debug(DBG_OBJ "(PD%d): Free Object\n", pd->hdr.id);

	atomic_dec(&pd->hdr.sdev->num_pd);
	kfree(pd);
}


void siw_cq_put(struct siw_cq *cq)
{
	pr_debug(DBG_OBJ "(CQ%d): Old refcount: %d\n",
		OBJ_ID(cq), kref_read(&cq->hdr.ref));
	kref_put(&cq->hdr.ref, siw_free_cq);
}

void siw_qp_put(struct siw_qp *qp)
{
	pr_debug(DBG_OBJ "(QP%d): Old refcount: %d\n",
		QP_ID(qp), kref_read(&qp->hdr.ref));
	kref_put(&qp->hdr.ref, siw_free_qp);
}

void siw_pd_put(struct siw_pd *pd)
{
	pr_debug(DBG_OBJ "(PD%d): Old refcount: %d\n",
		OBJ_ID(pd), kref_read(&pd->hdr.ref));
	kref_put(&pd->hdr.ref, siw_free_pd);
}
