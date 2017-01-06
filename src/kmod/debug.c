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

#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <net/tcp.h>
#include <linux/list.h>
#include <linux/debugfs.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "urdma.h"
#include "cm.h"
#include "obj.h"


static struct dentry *siw_debugfs;

static struct siw_dev *
siw_debugfs_file_to_sdev(struct file *f)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
	return f->f_dentry->d_inode->i_private;
#else
	return f->f_path.dentry->d_inode->i_private;
#endif
}

static ssize_t siw_show_qps(struct file *f, char __user *buf, size_t space,
			    loff_t *ppos)
{
	struct siw_dev	*sdev = siw_debugfs_file_to_sdev(f);
	struct siw_qp *qp;
	char *kbuf = NULL;
	u32 qp_id;
	int len = 0, n, num_qp;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	num_qp = atomic_read(&sdev->num_qp);
	if (!num_qp)
		goto out;

	len = snprintf(kbuf, space, "%s: %d QPs\n", sdev->ofa_dev.name, num_qp);
	if (len > space) {
		len = space;
		goto out;
	}
	space -= len;
	n = snprintf(kbuf + len, space,
		     "%-7s%-6s%-6s%-5s%-5s%-20s%-20s\n",
		     "QP-ID", "State", "Ref's", "IRQ", "ORQ", "Sock", "CEP");

	if (n > space) {
		len += space;
		goto out;
	}
	len += n;
	space -= n;

	idr_for_each_entry(&sdev->qp_idr, qp, qp_id) {
		n = snprintf(kbuf + len, space,
			     "%-7d%-6d%-6d%-5d%-5d 0x%-17p"
			     " 0x%-18p\n",
			     QP_ID(qp),
			     qp->attrs.state,
			     atomic_read(&qp->hdr.ref.refcount),
			     qp->attrs.irq_size,
			     qp->attrs.orq_size,
			     qp->attrs.llp_stream_handle,
			     qp->cep);
		if (n < space) {
			len += n;
			space -= n;
		} else {
			len += space;
			break;
		}
	}
out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);

	return len;
};

static ssize_t siw_show_ceps(struct file *f, char __user *buf, size_t space,
			     loff_t *ppos)
{
	struct siw_dev	*sdev = siw_debugfs_file_to_sdev(f);
	struct list_head *pos, *tmp;
	char *kbuf = NULL;
	int len = 0, n, num_cep;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	num_cep = atomic_read(&sdev->num_cep);
	if (!num_cep)
		goto out;

	len = snprintf(kbuf, space, "%s: %d CEPs\n", sdev->ofa_dev.name,
		       num_cep);
	if (len > space) {
		len = space;
		goto out;
	}
	space -= len;

	n = snprintf(kbuf + len, space,
		     "%-20s%-6s%-6s%-7s%-3s%-3s%-4s%-21s%-9s\n",
		     "CEP", "State", "Ref's", "QP-ID", "LQ", "LC", "U", "Sock",
		     "CM-ID");

	if (n > space) {
		len += space;
		goto out;
	}
	len += n;
	space -= n;

	list_for_each_safe(pos, tmp, &sdev->cep_list) {
		struct siw_cep *cep = list_entry(pos, struct siw_cep, devq);

		n = snprintf(kbuf + len, space,
			     "0x%-18p%-6d%-6d%-7d%-3s%-3s%-4d0x%-18p"
			     " 0x%-16p\n",
			     cep, cep->state,
			     atomic_read(&cep->ref.refcount),
			     cep->qp ? QP_ID(cep->qp) : -1,
			     list_empty(&cep->listenq) ? "n" : "y",
			     cep->listen_cep ? "y" : "n",
			     cep->in_use,
			     cep->llp.sock,
			     cep->cm_id);
		if (n < space) {
			len += n;
			space -= n;
		} else {
			len += space;
			break;
		}
	}
out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);

	return len;
};

static ssize_t siw_show_stats(struct file *f, char __user *buf, size_t space,
			      loff_t *ppos)
{
	struct siw_dev	*sdev = siw_debugfs_file_to_sdev(f);
	char *kbuf = NULL;
	int len = 0;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	len =  snprintf(kbuf, space, "Allocated SIW Objects:\n"
		"Device %s (%s):\t"
		"%s: %d, %s %d, %s: %d, %s: %d, %s: %d\n",
		sdev->ofa_dev.name,
		(sdev->netdev && (sdev->netdev->flags & IFF_UP))
				? "IFF_UP" : "IFF_DOWN",
		"CXs", atomic_read(&sdev->num_ctx),
		"PDs", atomic_read(&sdev->num_pd),
		"QPs", atomic_read(&sdev->num_qp),
		"CQs", atomic_read(&sdev->num_cq),
		"CEPs", atomic_read(&sdev->num_cep));
	if (len > space)
		len = space;
out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);
	return len;
}

static const struct file_operations siw_qp_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= siw_show_qps
};

static const struct file_operations siw_cep_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= siw_show_ceps
};

static const struct file_operations siw_stats_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= siw_show_stats
};

void siw_debugfs_add_device(struct siw_dev *sdev)
{
	struct dentry	*entry;

	if (!siw_debugfs)
		return;

	sdev->debugfs = debugfs_create_dir(sdev->ofa_dev.name, siw_debugfs);
	if (sdev->debugfs) {
		entry = debugfs_create_file("qp", S_IRUSR, sdev->debugfs,
					    (void *)sdev, &siw_qp_debug_fops);
		if (!entry)
			pr_debug(DBG_DM ": could not create 'qp' entry\n");

		entry = debugfs_create_file("cep", S_IRUSR, sdev->debugfs,
					    (void *)sdev, &siw_cep_debug_fops);
		if (!entry)
			pr_debug(DBG_DM ": could not create 'cep' entry\n");

		entry = debugfs_create_file("stats", S_IRUSR, sdev->debugfs,
					    (void *)sdev,
					    &siw_stats_debug_fops);
		if (!entry)
			pr_debug(DBG_DM ": could not create 'stats' entry\n");
	}
}

void siw_debugfs_del_device(struct siw_dev *sdev)
{
	if (sdev->debugfs) {
		debugfs_remove_recursive(sdev->debugfs);
		sdev->debugfs = NULL;
	}
}

void siw_debug_init(void)
{
	siw_debugfs = debugfs_create_dir("siw", NULL);

	if (!siw_debugfs || siw_debugfs == ERR_PTR(-ENODEV)) {
		pr_debug(DBG_DM ": could not init debugfs\n");
		siw_debugfs = NULL;
	}
}

void siw_debugfs_delete(void)
{
	if (siw_debugfs)
		debugfs_remove_recursive(siw_debugfs);

	siw_debugfs = NULL;
}
