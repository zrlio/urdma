/* dpdk_write_server.c */

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
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/prctl.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ring.h>

#include "proto_memcached.h"
#include "util.h"
#include "verbs.h"
#include "kvstore.h"
#include "options.h"

#define RECV_BUF_LEN 25000
#define DEFAULT_UDP_PORT 10000

#define MAX_RECV_WR 63
#define MAX_SEND_WR 63

static struct kvstore *store;

char recvbuf[MAX_RECV_WR][RECV_BUF_LEN];

struct memcached_header_parsed {
	struct memcached_header *header;
	size_t value_len;
	void *value;
	size_t key_len;
	char key[KVSTORE_KEY_LEN_MAX + 1];
};

static int send_credits = MAX_SEND_WR;

struct pending_response {
	size_t capacity;
	struct memcached_header_parsed cmd;
	char sendbuf[RECV_BUF_LEN];
};

static struct pending_response sendbuf[MAX_SEND_WR];

/* Note that !rte_ring_empty(sendbuf_ring) does NOT imply send_credits > 0,
 * since RDMA READ and WRITE requests will consume a send credit without using
 * a buffer from this ring.  The converse, however, is true:
 * (send_credits > 0 => !rte_ring_empty(sendbuf_ring)) */
static struct rte_ring *sendbuf_ring;

struct server_context {
	struct rdma_cm_id *cm_id;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
};

static void
init_sendbufs(void)
{
	int x, ret;

	sendbuf_ring = rte_ring_create("sendbuf_ring", MAX_SEND_WR + 1,
			rte_socket_id(), RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (!sendbuf_ring) {
		rte_exit(EXIT_FAILURE, "dpdk_write_server: Error creating send buffer ring: %s\n",
				rte_strerror(rte_errno));
	}

	for (x = 0; x < MAX_SEND_WR; ++x) {
		sendbuf[x].capacity = RECV_BUF_LEN;
		ret = rte_ring_enqueue(sendbuf_ring, &sendbuf[x]);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE, "dpdk_write_server: Enqueue send buffer %d of %d to free ring failed\n",
					x, MAX_SEND_WR);
		}
	}
} /* init_sendbufs */

static const char *
memcached_opcode_str(enum memcached_opcode op)
{
	static const char *str[] = {
		"GET",
		"SET",
		"ADD",
		"REPLACE",
		"DELETE",
	};
	if (op < memcached_opcode_get || op > memcached_opcode_delete) {
		return "<unknown>";
	} else {
		return str[op];
	}
} /* memcached_opcode_str */

static void
make_error_response(struct memcached_header *response,
		enum memcached_response_status status)
{
	response->key_length = 0;
	response->extras_length = 0;
	response->data_type = 0;
	response->status = rte_be_to_cpu_16(status);
	response->cas_version = 0;
	response->rdma_stag = rte_be_to_cpu_32(0);
	response->rdma_length = rte_be_to_cpu_32(0);
	response->rdma_offset = rte_be_to_cpu_64(0);
}

static void
handle_recv_set(__attribute__((unused)) struct ibv_qp *qp,
		struct pending_response *response,
		struct memcached_header *resp_head)
{
	struct memcached_header_parsed *cmd;
	struct kv_handle *h;

	cmd = &response->cmd;

	cmd->value = memcached_header_value(cmd->header);
	cmd->value_len = rte_be_to_cpu_32(cmd->header->total_body_length)
			- cmd->key_len - cmd->header->extras_length;
	switch (cmd->header->opcode) {
	case memcached_opcode_set:
		h = kvstore_object_set(store, cmd->key, cmd->value,
				cmd->value_len);
		break;
	case memcached_opcode_add:
		h = kvstore_object_create(store, cmd->key, cmd->value,
				cmd->value_len);
		break;
	case memcached_opcode_replace:
		h = kvstore_object_replace(store, cmd->key, cmd->value,
				cmd->value_len);
		break;
	default:
		errno = EPROTO;
		h = NULL;
		break;
	}

	if (!h) {
		RTE_LOG(ERR, USER2, "SET object %s (%zu bytes) failed: %s\n",
					cmd->key, cmd->value_len, strerror(errno));
		make_error_response(resp_head, (errno == EMSGSIZE)
				? memcached_value_too_large
				: memcached_item_not_stored);
		return;
	}

        resp_head->key_length = 0;
        resp_head->extras_length = 0;
        resp_head->data_type = 0;
        resp_head->status = rte_cpu_to_be_16(memcached_no_error);
        resp_head->cas_version = rte_cpu_to_be_64(kvstore_cas_version(h));
	resp_head->rdma_stag = rte_cpu_to_be_32(h->mr->rkey);
	resp_head->rdma_length = rte_cpu_to_be_32(h->mr->length);
	resp_head->rdma_offset = rte_cpu_to_be_64((uintptr_t)h->mr->addr);
}

static void
handle_recv_get(struct ibv_qp *qp,
		struct pending_response *response,
		struct memcached_header *resp_head)
{
	struct memcached_get_resp_header *resp;
	struct memcached_header_parsed *cmd;
	struct kv_handle *h;
	int ret;

	resp = (struct memcached_get_resp_header *)resp_head;
	cmd = &response->cmd;

	h = kvstore_object_get(store, cmd->key);
	if (!h) {
		RTE_LOG(ERR, USER2, "GET object %s failed: %s\n",
					cmd->key, strerror(errno));
		make_error_response(resp_head, memcached_key_not_found);
		return;
	}

	send_credits--;
	ret = usiw_accl_post_write(qp, h->value,
			RTE_MIN(rte_be_to_cpu_32(cmd->header->rdma_length),
				h->length), NULL,
			rte_be_to_cpu_64(cmd->header->rdma_offset),
			rte_be_to_cpu_32(cmd->header->rdma_stag),
			response);
	if (ret) {
		send_credits++;
		RTE_LOG(ERR, USER2, "post_write failed for %s request id=%" PRIx32 ": %s\n",
				memcached_opcode_str(cmd->header->opcode),
				rte_be_to_cpu_32(cmd->header->opaque),
				strerror(-ret));
		make_error_response(resp_head, memcached_out_of_memory);
		return;
	}

        resp->head.key_length = 0;
        resp->head.extras_length = 8;
        resp->head.data_type = 0;
        resp->head.status = rte_cpu_to_be_16(memcached_no_error);
        resp->head.cas_version = rte_cpu_to_be_64(kvstore_cas_version(h));
	resp->head.rdma_stag = rte_cpu_to_be_32(h->mr->rkey);
	resp->head.rdma_length = rte_cpu_to_be_32(h->mr->length);
	resp->head.rdma_offset = rte_cpu_to_be_64((uintptr_t)h->mr->addr);
	resp->flags = rte_cpu_to_be_32(0);
	resp->value_len = rte_cpu_to_be_32(h->length);
}

static struct pending_response *
dequeue_response(void)
{
	void *ptr = NULL;
	NDEBUG_UNUSED int ret;

	ret = rte_ring_dequeue(sendbuf_ring, &ptr);
	assert(ret == 0);

	return ptr;
} /* dequeue_response */

static void
handle_recv(struct ibv_qp *qp, struct ibv_wc *wc)
{
	struct memcached_header_parsed *cmd;
	struct pending_response *response;
	struct memcached_header *resp_head;
	size_t response_size;
	int ret;

	response = dequeue_response();
	cmd = &response->cmd;
	cmd->header = (struct memcached_header *)(uintptr_t)wc->wr_id;

	if (cmd->header->magic != memcached_magic_request) {
		RTE_LOG(NOTICE, USER2, "Received malformed response: incorrect magic number %" PRIx8 "\n",
				cmd->header->magic);
		return;
	}

	resp_head = (struct memcached_header *)response->sendbuf;
	resp_head->magic = memcached_magic_response;
	resp_head->opcode = cmd->header->opcode;
	resp_head->opaque = cmd->header->opaque;

	cmd->key_len = rte_be_to_cpu_16(cmd->header->key_length);
	if (cmd->key_len > KVSTORE_KEY_LEN_MAX) {
		RTE_LOG(DEBUG, USER2, "Got request with key_len %zu > maximum %u\n",
					cmd->key_len, KVSTORE_KEY_LEN_MAX);
		make_error_response(resp_head, memcached_invalid_arguments);
		goto respond;
	}
	if (cmd->key_len > 0) {
		strncpy(cmd->key, memcached_header_key(cmd->header),
				cmd->key_len);
		cmd->key[cmd->key_len] = '\0';
	}

	/* These helper functions set all fields in the response, except that
	 * key_length remains in host byte order and total_body_length is not
	 * filled in (we fill it in below just before sending). */
	switch (cmd->header->opcode) {
	case memcached_opcode_get:
		handle_recv_get(qp, response, resp_head);
		break;
	case memcached_opcode_set:
	case memcached_opcode_add:
	case memcached_opcode_replace:
		handle_recv_set(qp, response, resp_head);
		break;
	default:
		RTE_LOG(WARNING, USER2, "Got unknown opcode %" PRIu8 "\n",
				cmd->header->opcode);
		make_error_response(resp_head, memcached_unknown_command);
		break;
	}

respond:
        send_credits--;
	response_size = resp_head->extras_length + resp_head->key_length;
	resp_head->key_length = rte_cpu_to_be_16(resp_head->key_length);
	resp_head->total_body_length = rte_cpu_to_be_32(response_size);

	ret = usiw_accl_post_recv(qp, (void *)(uintptr_t)wc->wr_id,
			RECV_BUF_LEN, (void *)(uintptr_t)wc->wr_id);
	if (ret) {
		RTE_LOG(ERR, USER2, "post_recv failed: %s\n", strerror(-ret));
	}

	response_size += sizeof(*resp_head);
        ret = usiw_accl_post_send(qp, resp_head, response_size, NULL, response);
        if (ret) {
                send_credits++;
                RTE_LOG(ERR, USER2, "post_send failed for %s request id=%" PRIx32 ": %s\n",
				memcached_opcode_str(cmd->header->opcode),
                                rte_be_to_cpu_32(cmd->header->opaque),
                                strerror(-ret));
        }
}

static __attribute__((noreturn)) int
do_master_lcore_work(struct server_context *ctx)
{
	struct ibv_wc wc_ring[128];
	struct ibv_wc wc;
	struct ibv_qp *qp;
	unsigned int head, tail;
	int x;

	head = 0;
	tail = 0;
	qp = ctx->cm_id->qp;

	while (1) {
		x = ibv_poll_cq(ctx->cq, 1, &wc);
		if (!x)
			continue;
		if (wc.status != IBV_WC_SUCCESS) {
			rte_exit(EXIT_FAILURE, "Got non-success completion status\n");
		}

		switch (wc.opcode) {
		case IBV_WC_RECV:
			if (send_credits) {
				handle_recv(qp, &wc);
			} else {
				assert(tail >= head || head > UINT_MAX - 128);
				assert(tail - head < 128);
				memcpy(&wc_ring[tail++ & 127], &wc, sizeof(wc));
			}
			break;

		case IBV_WC_SEND:
			send_credits++;
			x = rte_ring_enqueue(sendbuf_ring,
					(void *)(uintptr_t)wc.wr_id);
			if (x != 0) {
				rte_exit(EXIT_FAILURE, "dpdk_write_server: Enqueue send buffer to free ring failed\n");
			}
			break;

		case IBV_WC_RDMA_WRITE:
			send_credits++;
			break;

		default:
			RTE_LOG(DEBUG, USER2, "Got unexpected completion type %d\n",
					wc.opcode);
		}

		if (send_credits && head != tail) {
			handle_recv(qp, &wc_ring[head++ & 127]);
		}
	}
}

static struct server_context *
server_new(struct sockaddr *listen_addr)
{
	struct ibv_qp_init_attr qp_init_attr;
	struct rdma_conn_param conn_params;
	struct ibv_device_attr ib_devattr;
	struct server_context *ctx;
	struct rdma_cm_id *listen_id;
	int ret, x;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		perror("allocate server context");
		return NULL;
	}

	if (rdma_create_id(NULL, &listen_id, ctx, RDMA_PS_TCP)) {
		perror("rdma_create_id");
		goto free_ctx;
	}

	if (rdma_bind_addr(listen_id, listen_addr)) {
		perror("rdma_bind_addr");
		goto free_listen_id;
	}

	if (rdma_listen(listen_id, 0)) {
		perror("rdma_listen");
		goto free_listen_id;
	}

	if (rdma_get_request(listen_id, &ctx->cm_id)) {
		perror("rdma_get_request");
		goto free_listen_id;
	}

	ret = ibv_query_device(ctx->cm_id->verbs, &ib_devattr);
	if (ret) {
		perror("ibv_query_device");
		goto free_listen_id;
	} else if (ib_devattr.vendor_id != USIW_DEVICE_VENDOR_ID
			|| ib_devattr.vendor_part_id
					!= USIW_DEVICE_VENDOR_PART_ID) {
		fprintf(stderr, "Bound device is not our driver\n");
		goto free_cm_id;
	}

	ctx->pd = ibv_alloc_pd(ctx->cm_id->verbs);
	if (!ctx->pd) {
		perror("ibv_alloc_pd");
		goto free_cm_id;
	}

	ctx->cq = ibv_create_cq(ctx->cm_id->verbs, 127, NULL, NULL, 0);
	if (!ctx->cq) {
		perror("ibv_create_cq");
		goto free_pd;
	}

	qp_init_attr.qp_context = ctx;
	qp_init_attr.send_cq = ctx->cq;
	qp_init_attr.recv_cq = ctx->cq;
	qp_init_attr.srq = NULL;
	qp_init_attr.cap.max_send_wr = MAX_SEND_WR;
	qp_init_attr.cap.max_recv_wr = MAX_SEND_WR;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.cap.max_inline_data = 0;
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 1;
	if (rdma_create_qp(ctx->cm_id, ctx->pd, &qp_init_attr)) {
		perror("rdma_create_qp");
		goto free_cq;
	}

	for (x = 0; x < MAX_RECV_WR; ++x) {
		ret = usiw_accl_post_recv(ctx->cm_id->qp, recvbuf[x],
				RECV_BUF_LEN, recvbuf[x]);
		if (ret < 0) {
			fprintf(stderr, "dpdk_post_recv: %s\n",
					strerror(-ret));
			goto free_qp;
		}
	}

	conn_params.private_data = NULL;
	conn_params.private_data_len = 0;
	conn_params.responder_resources = 1;
	conn_params.initiator_depth = 1;
	conn_params.flow_control = 0;
	conn_params.rnr_retry_count = 7;
	ret = rdma_accept(ctx->cm_id, &conn_params);
	if (ret < 0) {
		perror("rdma_accept");
		goto free_qp;
	}

	rdma_destroy_id(listen_id);
	goto out;

free_qp:
	rdma_destroy_qp(ctx->cm_id);
free_cq:
	ibv_destroy_cq(ctx->cq);
free_pd:
	ibv_dealloc_pd(ctx->pd);
free_cm_id:
	rdma_destroy_id(ctx->cm_id);
free_listen_id:
	rdma_destroy_id(listen_id);
free_ctx:
	free(ctx);
	ctx = NULL;
out:
	return ctx;
} /* server_new */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct server_context *ctx;
	struct server_options options;
	struct sockaddr_in inaddr;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	ret = parse_options(argc, argv, &options);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");
	}

	argc -= ret;
	argv += ret;

	init_sendbufs();

	inaddr.sin_family = AF_INET;
	inaddr.sin_port = rte_cpu_to_be_16(DEFAULT_UDP_PORT);
	inaddr.sin_addr.s_addr = INADDR_ANY;
	ctx = server_new((struct sockaddr *)&inaddr);

	store = kvstore_new(options.nvm_fn, 10240, ctx->pd);
	if (!store)
		rte_exit(EXIT_FAILURE, "Cannot allocate key value store: %s\n",
				strerror(errno));

	if (rte_lcore_count() > 1)
		RTE_LOG(WARNING, USER2,
			"Too many lcores enabled. Only 1 used.\n");

	return do_master_lcore_work(ctx);
}
