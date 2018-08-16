/* verbs_pingpong/main.c */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2016, IBM Corporation
 * Copyright (c) 2016-2018, University of New Hampshire
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

#define _GNU_SOURCE

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_cycles.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include "verbs.h"

#define PACKET_MIN_LEN ETHER_MIN_LEN
#define PACKET_MAX_LEN 1073741824

#define MAX_BURST_SIZE 512

#define BASE_UDP_PORT 10000

static struct app_options {
	unsigned long long packet_count;
	unsigned long packet_size;
	unsigned long burst_size;
	unsigned int thread_count;
	FILE *output_file;
} options = {
	.packet_count = 1000000,
	.packet_size = ETHER_MIN_LEN,
	.burst_size = 8,
	.thread_count = 2,
	.output_file = NULL,
};

struct stats {
	uint64_t latency;
		/**< Per-packet unidirectional latency, in cycles.  It is
		 * measured by inserting a cycle counter timestamp into an
		 * outgoing packet and then calculating the difference from the
		 * current cycle counter when the response is received.  The
		 * final value is the MEAN across all threads (note that the
		 * master thread will receive the sum and itself divide by the
		 * number of workers). */
	uint64_t start_time;
		/**< Per-thread start cycle counter.  The final value is the
		 * MIN across all threads. */
	uint64_t end_time;
		/**< Per-thread end cycle counter. The final value is the MAX
		 * across all threads. */
	uint64_t elapsed_cycles;
		/**< Total cycles elapsed across all threads. The final value
		 * is the SUM across all threads. */
	uint64_t poll_cycles;
		/**< Total Cycles spent in recv poll loop. The final value is
		 * the SUM across all threads. */
	uintmax_t max_poll_cycles;
		/**< The maximum number of cycles spent in the recv poll
		 * loop. The final value is the MAX across all threads. */
	unsigned long long message_count;
		/**< Messages actually sent. The final value is the SUM across
		 * all threads. */
	uintmax_t *recv_count_histo;
		/**< The number of times that ibv_poll_cq returned each
		 * number of messages. The final value for each bucket is the
		 * SUM across all threads. */
	unsigned long first_burst_size;
		/**< The number of messages sent by the client in the first
		 * burst.  This will be greater that or equal to the input
		 * burst_size, since we try to keep sending messages until we
		 * receive the first response.  The final value is the MAX
		 * across all threads. */
};

struct pending_transfer {
	int count;
		/**< The buffer can be reused when count == 0.  This means that
		 * the send and receive both completed. */
	struct ibv_send_wr send_wr;
		/**< SEND work request for this transfer. */
	struct ibv_sge send_sge;
		/**< Scatter-gather element for the SEND work request for this
		 * transfer. */
	struct ibv_recv_wr recv_wr;
		/**< RECV work request for this transfer. */
	struct ibv_sge recv_sge;
		/**< Scatter-gather element for the RECV work request for this
		 * transfer. */
};

struct thread_param {
	int id;
		/**< Identifier of this thread, starting with 1. */
	struct rdma_cm_id *cm_id;
		/**< Reference to the cm_id used to create this connection. */
	struct ibv_qp *qp;
		/**< Reference to the queue pair to use. */
	struct stats *final_stats;
		/**< Reference to the final statistics filled in by each
		 * thread.  Accesses to this must be protected by lock. */
	bool is_client;
		/**< True iff we are a client. */
	struct ibv_cq *cq;
		/**< Completion queue associated with above port. */
	pthread_mutex_t *lock;
		/**< Protects final_stats.  Locked only after each thread has
		 * completed its main loop. */
	struct pending_transfer *pending;
		/**< Array of pending transfers, with size
		 * options.burst_size. */
};

static pthread_mutex_t done_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t done_cond = PTHREAD_COND_INITIALIZER;
static int remaining_count;

static _Noreturn void pr_exit(int code, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(code);
}

/** UDP port is in host byte order. */
static void
qp_init(struct ibv_context *ibctx, struct ibv_qp_init_attr *qp_init_attr)
{
	struct ibv_cq *cq;

	assert(qp_init_attr != NULL);

	cq = ibv_create_cq(ibctx, 2 * options.burst_size, NULL, NULL, 0);
	if (!cq) {
		pr_exit(EXIT_FAILURE, "Create CQ with size %lu: %s\n",
				2 * options.burst_size, strerror(errno));
	}

	qp_init_attr->qp_context = NULL;
	qp_init_attr->send_cq = cq;
	qp_init_attr->recv_cq = cq;
	qp_init_attr->srq = NULL;
	qp_init_attr->cap.max_send_wr = options.burst_size;
	qp_init_attr->cap.max_recv_wr = options.burst_size;
	qp_init_attr->cap.max_send_sge = 1;
	qp_init_attr->cap.max_recv_sge = 1;
	qp_init_attr->cap.max_inline_data = 0;
	qp_init_attr->qp_type = IBV_QPT_RC;
	qp_init_attr->sq_sig_all = 1;
} /* qp_init */


static int
print_stats(FILE *fptr, const struct stats *stats)
{
	uint64_t elapsed_cycles;
	double timer_hz, physical_time, cpu_time, poll_time, latency;
	unsigned int x;
	int ret;

	elapsed_cycles = stats->end_time - stats->start_time;
	timer_hz = rte_get_timer_hz();
	physical_time = elapsed_cycles / timer_hz;
	cpu_time = stats->elapsed_cycles / timer_hz;
	poll_time = stats->poll_cycles / timer_hz;
	latency = 1e6 * stats->latency / timer_hz;

	flockfile(fptr);
	errno = 0;
	ret = fprintf(fptr, "{\n  \"requested_packet_count\": %llu,\n",
			options.packet_count);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"packet_size\": %lu,\n", options.packet_size);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"burst_size\": %lu,\n", options.burst_size);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"slave_thread_count\": %u,\n",
			options.thread_count - 1);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"packet_count\": %llu,\n",
			stats->message_count);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"physical_time\": %.9f,\n", physical_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"cpu_time\": %.9f,\n", cpu_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"recv_poll_time\": %.9f,\n", poll_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"max_recv_poll_time\": %.9f,\n",
			stats->max_poll_cycles / timer_hz);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"message_rate\": %f,\n",
			stats->message_count / physical_time);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"throughput\": %f,\n",
			8 * options.packet_size * stats->message_count
			/ (physical_time * 1000000));
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"throughput_unit\": \"Mbps\",\n");
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"latency\": %.9f,\n", latency);
	if (ret < 0)
		return ret;
	ret = fprintf(fptr, "  \"latency_unit\": \"microsecond\",\n");
	if (ret < 0)
		return ret;
	if (stats->first_burst_size) {
		ret = fprintf(fptr, "  \"first_burst_size\": %lu,\n",
				stats->first_burst_size);
		if (ret < 0)
			return ret;
	}
	ret = fprintf(fptr, "  \"wc_count_per_burst_histo\": [");
	if (ret < 0)
		return ret;

	for (x = 0; x < 2 * options.burst_size; ++x) {
		ret = fprintf(fptr, "%" PRIuMAX ", ",
				stats->recv_count_histo[x]);
		if (ret < 0)
			return ret;
	}
	ret = fprintf(fptr, "%" PRIuMAX "]\n}\n",
			stats->recv_count_histo[2 * options.burst_size]);
	if (ret < 0)
		return ret;

	ret = fflush(fptr);
	if (ret == EOF) {
		return -1;
	}
	funlockfile(fptr);

	return 0;
} /* print_stats */

static int
do_master_thread_work(struct stats *stats)
{
	unsigned int x;

	pthread_mutex_lock(&done_mutex);
	while (remaining_count > 0) {
		pthread_cond_wait(&done_cond, &done_mutex);
	}
	pthread_mutex_unlock(&done_mutex);

	/* Print the stats. */
	stats->latency /= options.thread_count;
	if (print_stats(options.output_file
					? options.output_file : stdout,
					stats) != 0) {
		pr_exit(EXIT_FAILURE, "Error dumping statistics: %s\n",
				strerror(errno));
	}

	/* Close the stats output file */
	if (options.output_file) {
		if (fclose(options.output_file) == EOF) {
			pr_exit(EXIT_FAILURE, "Error detected closing JSON stream: %s\n",
					strerror(errno));
		}
	}

	return EXIT_SUCCESS;
}

static int
wait_cq_bulk(struct stats *stats, struct ibv_cq *cq, struct ibv_wc *wc,
		int wc_count, uint64_t *poll_cycles)
{
	uint64_t poll_start, poll_end;
	int ret;

	poll_start = rte_get_timer_cycles();
	do {
		ret = ibv_poll_cq(cq, wc_count, wc);
	} while (ret == 0);
	stats->recv_count_histo[ret]++;
	if (poll_cycles) {
		poll_end = rte_get_timer_cycles();
		*poll_cycles = poll_end - poll_start;
	}

	return ret;
} /* wait_recv_bulk */

static int
post_recv(struct thread_param *arg, struct ibv_recv_wr *wr)
{
	struct pending_transfer *pending;
	struct ibv_recv_wr *bad_wr;
	int ret;

	ret = ibv_post_recv(arg->qp, wr, &bad_wr);
	if (ret) {
		pending = (void *)(uintptr_t)bad_wr->wr_id;
		fprintf(stderr, "Could not post receive work request #%td: %s\n",
				pending - arg->pending,
				strerror(-ret));
	}
	return ret;
} /* post_recv */

static int
post_send(struct thread_param *arg, struct ibv_send_wr *wr)
{
	struct pending_transfer *pending;
	struct ibv_send_wr *bad_wr;
	int ret;

	ret = ibv_post_send(arg->qp, wr, &bad_wr);
	if (ret) {
		pending = (void *)(uintptr_t)bad_wr->wr_id;
		fprintf(stderr, "Could not post send work request #%td: %s\n",
				pending - arg->pending,
				strerror(-ret));
	}
	return ret;
} /* post_send */

static int
handle_burst(struct thread_param *arg, struct ibv_wc *wc,
		unsigned int wc_count,
		unsigned int timestamp_offset,
		struct stats *stats,
		uint64_t *roundtrip_count,
		int *remaining_send,
		int *remaining_recv,
		int *pending_active)
{
	struct pending_transfer *pending;
	unsigned int x;
	uintptr_t pktbuf_addr;
	uint64_t *pkt_timestamp;
	int ret;

	for (x = 0; x < wc_count; x++) {
		pending = (struct pending_transfer *)(uintptr_t)wc[x].wr_id;
		if (wc[x].opcode == IBV_WC_RECV) {
			pktbuf_addr = pending->send_sge.addr;
			pkt_timestamp = (uint64_t *)(pktbuf_addr
							+ timestamp_offset);
			if (*pkt_timestamp != 0) {
				stats->latency += rte_get_timer_cycles()
					- *pkt_timestamp;
				*pkt_timestamp = 0;
				(*roundtrip_count)++;
			}
		}

		if (--pending->count == 0) {
			if (*remaining_recv > 0) {
				pending->recv_wr.next = NULL;
				ret = post_recv(arg, &pending->recv_wr);
				if (ret) {
					return ret;
				}
				(*remaining_recv)--;
				pending->count++;
			}
			if (*remaining_send > 0) {
				pktbuf_addr = pending->send_sge.addr;
				pkt_timestamp = (uint64_t *)(pktbuf_addr
							+ timestamp_offset);
				if (!((*remaining_send - x) & 255)) {
					*pkt_timestamp = rte_get_timer_cycles();
				}
				ret = post_send(arg, &pending->send_wr);
				if (ret) {
					return ret;
				}
				(*remaining_send)--;
				pending->count++;
			}
			if (pending->count == 0) {
				(*pending_active)--;
			}
		}
		assert(pending->count >= 0);
	}
	return 0;
} /* handle_burst */

static int
handle_last_server_burst(struct thread_param *arg, struct ibv_wc *wc,
		unsigned int wc_count,
		int *remaining_send,
		int *pending_active)
{
	struct pending_transfer *pending;
	unsigned int x;
	int ret;

	for (x = 0; x < wc_count; x++) {
		assert(wc[x].status == IBV_WC_SUCCESS);
		pending = (void *)(uintptr_t)wc[x].wr_id;

		if (--pending->count == 0) {
			if (*remaining_send > 0) {
				ret = post_send(arg, &pending->send_wr);
				if (ret) {
					return ret;
				}
				(*remaining_send)--;
				pending->count++;
			} else {
				(*pending_active)--;
			}
		}
	}
	assert(*pending_active >= 0);
	return 0;
} /* handle_last_server_burst */

static void
handle_last_client_burst(struct ibv_wc *wc,
		unsigned int wc_count,
		unsigned int timestamp_offset,
		struct stats *stats,
		uint64_t *roundtrip_count,
		int *pending_active)
{
	struct pending_transfer *pending;
	unsigned int x;
	uintptr_t sendbuf_addr;
	uint64_t *pkt_timestamp;

	for (x = 0; x < wc_count; x++) {
		assert(wc[x].status == IBV_WC_SUCCESS);
		pending = (void *)(uintptr_t)wc[x].wr_id;
		if (wc[x].opcode == IBV_WC_RECV) {
			sendbuf_addr = pending->send_sge.addr;
			pkt_timestamp = (uint64_t *)(sendbuf_addr
					+ timestamp_offset);
			if (*pkt_timestamp != 0) {
				stats->latency += rte_get_timer_cycles()
					- *pkt_timestamp;
				*pkt_timestamp = 0;
				(*roundtrip_count)++;
			}
		}

		if (--pending->count == 0) {
			(*pending_active)--;
		}
	}
	assert(*pending_active >= 0);
} /* handle_last_client_burst */


/** Initializes a pending transfer.  offset is the number of bytes from the
 * beginning of sendbuf and recvbuf that this transfer should start at.
 * next_recv is used to chain the receive work requests so they can all be
 * posted with a single ibv_post_recv(). */
static void
pending_transfer_init(struct pending_transfer *pending, char *sendbuf,
		char *recvbuf, size_t offset, struct ibv_recv_wr *next_recv)
{
	pending->send_wr.wr_id = (uintptr_t)pending;
	pending->send_wr.next = NULL;
	pending->send_wr.sg_list = &pending->send_sge;
	pending->send_wr.num_sge = 1;
	pending->send_wr.opcode = IBV_WR_SEND;
	pending->send_wr.send_flags = 0;

	pending->send_sge.addr = (uintptr_t)sendbuf + offset;
	pending->send_sge.length = options.packet_size;
	pending->send_sge.lkey = 0;

	pending->recv_wr.wr_id = (uintptr_t)pending;
	pending->recv_wr.next = next_recv;
	pending->recv_wr.sg_list = &pending->recv_sge;
	pending->recv_wr.num_sge = 1;

	pending->recv_sge.addr = (uintptr_t)recvbuf + offset;
	pending->recv_sge.length = options.packet_size;
	pending->recv_sge.lkey = 0;

	pending->count = 1;
} /* pending_transfer_init */


static struct pending_transfer *
pending_transfer_array_new(void)
{
	struct pending_transfer *pending;
	char *sendbuf, *recvbuf;
	unsigned int x;

	pending = calloc(options.burst_size, sizeof(*pending));
	if (!pending) {
		return NULL;
	}

	sendbuf = aligned_alloc(64, options.burst_size * options.packet_size);
	if (!sendbuf) {
		return NULL;
	}

	recvbuf = aligned_alloc(64, options.burst_size * options.packet_size);
	if (!recvbuf) {
		return NULL;
	}

	for (x = 0; x < options.burst_size - 1; ++x) {
		pending_transfer_init(&pending[x], sendbuf, recvbuf,
				x * options.packet_size,
				&pending[x + 1].recv_wr);
	}
	assert(x == options.burst_size - 1);
	pending_transfer_init(&pending[x], sendbuf, recvbuf,
			x * options.packet_size, NULL);

	return pending;
} /* pending_transfer_array_new */

static void
pending_transfer_array_free(struct pending_transfer *pending)
{
	free((void *)(uintptr_t)pending[0].send_sge.addr);
	free((void *)(uintptr_t)pending[0].recv_sge.addr);
	free(pending);
} /* pending_transfer_array_free */

static void *
do_thread_work(void *rawarg)
{
	struct thread_param *arg;
	struct ibv_wc *wc;
	struct ibv_qp *qp;
	struct stats stats;
	struct pending_transfer *pending;
	uint64_t roundtrip_count;
	uint64_t poll_cycles;
	uint64_t start_time, end_time;
	unsigned int wc_count;
	unsigned int timestamp_offset;
	unsigned int x;
	int remaining_send, remaining_recv, pending_active;
	int ret;

	arg = (struct thread_param *)rawarg;
	assert(arg->id >= 1);
	qp = arg->qp;

	wc = calloc(2 * options.burst_size, sizeof(*wc));
	if (!wc) {
		pthread_exit(NULL);
	}

	pending = arg->pending;
	stats.recv_count_histo = calloc(2 * options.burst_size + 1,
			sizeof(*stats.recv_count_histo));
	remaining_send = options.packet_count;
	remaining_recv = options.packet_count - options.burst_size;
	stats.latency = 0;
	stats.first_burst_size = 0;
	roundtrip_count = 0;
	pending_active = options.burst_size;

	if (arg->is_client) {
		timestamp_offset = 0;
		start_time = rte_get_timer_cycles();
		for (x = 0; x < options.burst_size; ++x) {
			ret = post_send(arg, &pending[x].send_wr);
			if (ret != 0) {
				pthread_exit(NULL);
			}
			pending[x].count++;
		}
		remaining_send -= options.burst_size;

		fprintf(stderr, "thread %u sent first burst\n", arg->id);
	} else {
		timestamp_offset = sizeof(uint64_t);
		fprintf(stderr, "thread %u awaiting first burst\n", arg->id);
		wc_count = wait_cq_bulk(&stats, arg->cq, wc,
				2 * options.burst_size, NULL);
		fprintf(stderr, "thread %u received first burst with %u messages\n",
				arg->id, wc_count);
		start_time = rte_get_timer_cycles();
		handle_burst(arg, wc, wc_count, timestamp_offset, &stats,
				&roundtrip_count, &remaining_send,
				&remaining_recv, &pending_active);
	}

	stats.poll_cycles = 0;
	stats.max_poll_cycles = 0;
	while (remaining_send > 0 && remaining_recv > 0) {
		wc_count = wait_cq_bulk(&stats, arg->cq, wc,
				2 * options.burst_size, &poll_cycles);
		stats.poll_cycles += poll_cycles;
		if (poll_cycles > stats.max_poll_cycles) {
			stats.max_poll_cycles = poll_cycles;
		}

		handle_burst(arg, wc, wc_count, timestamp_offset, &stats,
				&roundtrip_count, &remaining_send,
				&remaining_recv, &pending_active);
	}

	/* On client: we have sent all X messages, but must receive the last
	 * replies from the server (as well as getting the remaining send
	 * completions) */
	/* On server: we have received all X messages, but must wait for the
	 * remaining send completions */
	if (!arg->is_client) {
		assert(remaining_recv == 0);
	}

	while (pending_active > 0) {
		wc_count = wait_cq_bulk(&stats, arg->cq, wc,
				2 * options.burst_size, &poll_cycles);
		stats.poll_cycles += poll_cycles;
		if (poll_cycles > stats.max_poll_cycles) {
			stats.max_poll_cycles = poll_cycles;
		}

		if (arg->is_client) {
			handle_last_client_burst(wc, wc_count,
					timestamp_offset, &stats,
					&roundtrip_count, &pending_active);
		} else {
			handle_last_server_burst(arg, wc, wc_count,
					&remaining_send,
					&pending_active);
		}
	}
	assert(remaining_send == 0 && remaining_recv == 0);

	end_time = rte_get_timer_cycles();
	stats.elapsed_cycles = end_time - start_time;
	stats.message_count = options.packet_count - remaining_send;
	stats.latency = (roundtrip_count == 0) ? 0.0
		: (stats.latency / (2 * roundtrip_count));

	pthread_mutex_lock(arg->lock);
	arg->final_stats->latency += stats.latency;
	if (start_time < arg->final_stats->start_time) {
		arg->final_stats->start_time = start_time;
	}
	if (end_time > arg->final_stats->end_time) {
		arg->final_stats->end_time = end_time;
	}
	arg->final_stats->elapsed_cycles += stats.elapsed_cycles;
	arg->final_stats->poll_cycles += stats.poll_cycles;
	arg->final_stats->message_count += stats.message_count;
	for (x = 0; x <= 2 * options.burst_size; ++x) {
		arg->final_stats->recv_count_histo[x]
					+= stats.recv_count_histo[x];
	}
	if (stats.max_poll_cycles > arg->final_stats->max_poll_cycles) {
		arg->final_stats->max_poll_cycles
					= stats.max_poll_cycles;
	}
	if (stats.first_burst_size > arg->final_stats->first_burst_size) {
		arg->final_stats->first_burst_size = stats.first_burst_size;
	}
	pthread_mutex_unlock(arg->lock);

	free(stats.recv_count_histo);
	pending_transfer_array_free(pending);

	ret = ibv_destroy_qp(qp);
	if (ret != 0) {
		fprintf(stderr, "Could not destroy QP: %s\n", strerror(-ret));
	}
	ret = ibv_destroy_cq(arg->cq);
	if (ret != 0) {
		fprintf(stderr, "Could not destroy CQ: %s\n", strerror(-ret));
	}

	pthread_mutex_lock(&done_mutex);
	if (--remaining_count == 0) {
		pthread_cond_signal(&done_cond);
	}
	pthread_mutex_unlock(&done_mutex);
	pthread_exit(NULL);
}

static struct option longopts[] = {
	{ .name = "packet-count", .has_arg = required_argument,
		.flag = NULL, .val = 'c' },
	{ .name = "packet-size", .has_arg = required_argument,
		.flag = NULL, .val = 's' },
	{ .name = "burst-size", .has_arg = required_argument,
		.flag = NULL, .val = 'b' },
	{ .name = "output", .has_arg = required_argument,
		.flag = NULL, .val = 'o' },
	{ .name = "thread-count", .has_arg = required_argument,
		.flag = NULL, .val = 't' },
	{ .name = "help", .has_arg = no_argument, .flag = NULL, .val = 'h' },
	{ 0 },
};

static void
usage(int status)
{
	printf("Usage: verbs_pingpong [<options>] [<server_ip> [<server_port>]]\n\n");
	printf("  %23s %s\n", "--burst-size",
		"Maximum number of outstanding packets");
	printf("  %23s %s\n", "--packet-count",
		"total number of packets to send");
	printf("  %23s %s\n", "--packet-size",
		"size of packets to send");
	printf("  %23s %s\n", "--output",
		"file to output statistics to (default stdout)");
	printf("  %23s %s\n", "--thread-count",
		"number of active threads (>=2)");
	fflush(stdout);
	exit(status);
} /* usage */

/** Intended to be equivalent to the shell command
 * "mkdir -p $(dirname ${path})". */
static int
make_parent_dir(const char *path)
{
	struct stat st;
	char *pathcopy;
	char *dir;
	int ret;

	pathcopy = alloca(strlen(path) + 1);
	strcpy(pathcopy, path);
	dir = dirname(pathcopy);
	if (strcmp(dir, "/") == 0) {
		errno = ENOENT;
		return -1;
	} else if ((ret = stat(dir, &st)) < 0 && errno == ENOENT) {
		/* Recur to ensure parent directory exists */
		ret = make_parent_dir(dir);
		if (ret == 0) {
			/* If parent directory exists or was created, create
			 * this directory. */
			return mkdir(dir, 0770);
		} else {
			return ret;
		}
	} else if (ret < 0) {
		return ret;
	} else if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return -1;
	} else {
		/* Exists and is a directory */
		return 0;
	}
} /* make_parent_dir */

static unsigned int
parse_options(int argc, char *argv[])
{
	char *endch;
	int ch;

	while ((ch = getopt_long(argc, argv,
					"c:" /* --packet-count */
					"s:" /* --packet-size */
					"b:" /* --burst-size */
					"o:" /* --output */
					"t:" /* --thread-count */
					"h" /* --help */
					, longopts, NULL)) != -1) {
		switch (ch) {
		case 'c':
			errno = 0;
			options.packet_count = strtoull(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0' || !options.packet_count) {
				pr_exit(EXIT_FAILURE,
						"Invalid packet count \"%s\"\n",
						optarg);
			}
			break;
		case 's':
			errno = 0;
			options.packet_size = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0'
					|| options.packet_size < PACKET_MIN_LEN
					|| options.packet_size > PACKET_MAX_LEN) {
				pr_exit(EXIT_FAILURE,
						"Invalid packet size \"%s\"\n",
						optarg);
			}
			break;
		case 'b':
			errno = 0;
			options.burst_size = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0'
					|| !options.burst_size
					|| options.burst_size
					> MAX_BURST_SIZE) {
				pr_exit(EXIT_FAILURE,
						"Invalid burst size \"%s\"\n",
						optarg);
			}
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 'o':
			if (options.output_file) {
				pr_exit(EXIT_FAILURE,
					"Only a single output file may be specified.\n");
			}
			if (make_parent_dir(optarg) < 0) {
				pr_exit(EXIT_FAILURE,
					"Could not create parent directory for %s: %s\n",
					optarg, strerror(errno));
			}
			options.output_file = fopen(optarg, "w");
			if (!options.output_file) {
				pr_exit(EXIT_FAILURE,
					"Could not open %s for writing: %s\n",
					optarg, strerror(errno));
			}
			break;
		case 't':
			errno = 0;
			options.thread_count = strtoul(optarg, &endch, 0);
			if (errno != 0 || *endch != '\0'
					|| options.thread_count < 2) {
				pr_exit(EXIT_FAILURE,
						"Invalid thread count \"%s\"\n",
						optarg);
			}
			break;
		default:
			pr_exit(EXIT_FAILURE, "Unexpected option -%c\n", ch);
			break;
		}
	}

	return optind - 1;
} /* parse_options */

static struct rdma_cm_id *
init_ep(struct ibv_pd *ibpd, char *node, uint16_t udp_port)
{
	struct rdma_addrinfo hints, *info;
	struct rdma_conn_param conn_param = {
		.private_data = NULL,
	};
	struct rdma_cm_id *cm_id, *listen_id;
	struct ibv_qp_init_attr qp_init_attr;
	char *service;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = RAI_FAMILY;
	hints.ai_family = AF_INET;
	hints.ai_qp_type = IBV_QPT_RC;
	hints.ai_port_space = RDMA_PS_TCP;
	ret = asprintf(&service, "%u", udp_port);
	if (ret < 0) {
		pr_exit(EXIT_FAILURE, "OOM\n");
	}
	if (!node) {
		hints.ai_flags |= RAI_PASSIVE;
	}
	if (rdma_getaddrinfo(node, service, &hints, &info) < 0) {
		pr_exit(EXIT_FAILURE, "rdma_getaddrinfo() failed: %s\n",
				strerror(errno));
	}

	qp_init(ibpd->context, &qp_init_attr);
	if (rdma_create_ep(&cm_id, info, ibpd, &qp_init_attr) < 0) {
		pr_exit(EXIT_FAILURE, "rdma_create_ep() failed: %s\n",
				strerror(errno));
	}

	conn_param.private_data = NULL;
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	if (node) {
		if (rdma_connect(cm_id, &conn_param) < 0) {
			pr_exit(EXIT_FAILURE, "rdma_connect() failed: %s\n",
					strerror(errno));
		}
	} else {
		listen_id = cm_id;
		if (rdma_listen(listen_id, 0) < 0) {
			pr_exit(EXIT_FAILURE, "rdma_listen() failed: %s\n",
					strerror(errno));
		}

		if (rdma_get_request(listen_id, &cm_id) < 0) {
			pr_exit(EXIT_FAILURE, "rdma_get_request() failed: %s\n",
					strerror(errno));
		}

		if (rdma_accept(cm_id, &conn_param) < 0) {
			pr_exit(EXIT_FAILURE, "rdma_accept() failed: %s\n",
					strerror(errno));
		}
	}

	if (!cm_id->send_cq || !cm_id->recv_cq) {
		RTE_LOG(WARNING, USER2, "cm_id send_cq=%p recv_cq=%p\n",
				(void *)cm_id->send_cq,
				(void *)cm_id->recv_cq);
		assert(qp_init_attr.send_cq && qp_init_attr.recv_cq);
		cm_id->send_cq = qp_init_attr.send_cq;
		cm_id->recv_cq = qp_init_attr.recv_cq;
	}

	free(service);
	return cm_id;
} /* init_ep */

/*
 * The main function, which does initialization and calls the per-thread
 * functions.
 */
int
main(int argc, char *argv[])
{
	static pthread_mutex_t lock;
	struct thread_param *param;
	struct rdma_cm_id *cm_id;
	struct stats final_stats;
	struct ibv_device_attr ib_devattr;
	struct ibv_context **ib_devs;
	struct ibv_context *ibctx;
	struct ibv_pd *ibpd;
	unsigned int x;
	pthread_attr_t tattr;
	pthread_t tid;
	int ret;

	ret = parse_options(argc, argv);

	argv[ret] = argv[0];
	argc -= ret;
	argv += ret;

	if (options.packet_count < options.burst_size) {
		fprintf(stderr, "ERROR: packet_count %llu < burst_size %lu\n",
				options.packet_count, options.burst_size);
		usage(EXIT_FAILURE);
	}

	ib_devs = rdma_get_devices(NULL);
	if (!ib_devs) {
		pr_exit(EXIT_FAILURE, "Get verbs devices failed: %s\n",
				strerror(errno));
	}

	for (ibctx = *ib_devs; ibctx != NULL; ++ibctx) {
		ret = ibv_query_device(ibctx, &ib_devattr);
		if (!ret && ib_devattr.vendor_id == URDMA_DEVICE_VENDOR_ID
				&& ib_devattr.vendor_part_id
						== URDMA_DEVICE_VENDOR_PART_ID) {
			break;
		}
	}
	rdma_free_devices(ib_devs);
	if (!ibctx) {
		pr_exit(EXIT_FAILURE, "Could not find DPDK verbs device; is kernel module loaded?\n");
	}

	ibpd = ibv_alloc_pd(ibctx);
	if (!ibpd) {
		pr_exit(EXIT_FAILURE, "Create PD: %s\n", strerror(errno));
	}

	pthread_mutex_init(&lock, NULL);
	memset(&final_stats, 0, sizeof(final_stats));
	final_stats.start_time = UINT64_MAX;
	final_stats.recv_count_histo = calloc(2 * options.burst_size + 1,
			sizeof(*final_stats.recv_count_histo));
	if (!final_stats.recv_count_histo) {
		pr_exit(EXIT_FAILURE, "Could not allocate stats histogram: %s\n",
				strerror(errno));
	}


	if (options.thread_count < 2) {
		pr_exit(EXIT_FAILURE, "This benchmark requires at least 2 threads\n");
	}
	param = calloc(options.thread_count - 1, sizeof(*param));
	if (!param) {
		pr_exit(EXIT_FAILURE,
			"Could not allocate thread parameters: %s\n",
			strerror(errno));
	}

	for (x = 0; x < options.thread_count - 1; ++x) {
		param[x].id = x + 1;
		param[x].lock = &lock;
		param[x].final_stats = &final_stats;
		cm_id = init_ep(ibpd, argv[1], BASE_UDP_PORT + x);
		param[x].cm_id = cm_id;
		param[x].qp = cm_id->qp;
		param[x].cq = cm_id->send_cq;

		param[x].pending = pending_transfer_array_new();

		ret = post_recv(&param[x], &param[x].pending[0].recv_wr);
		if (ret) {
			pr_exit(EXIT_FAILURE, "Post recv work request list failed\n");
		}

		param[x].is_client = (argc >= 2);
	}

	ret = pthread_attr_init(&tattr);
	if (ret) {
		pr_exit(EXIT_FAILURE, "Could not create thread attributes: %s\n",
				strerror(errno));
	}
	pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	remaining_count = options.thread_count - 1;
	for (x = 0; x < options.thread_count - 1; ++x) {
		ret = pthread_create(&tid, &tattr, do_thread_work, &param[x]);
		if (ret != 0) {
			pr_exit(EXIT_FAILURE, "Could not launch main work task: %s\n",
					strerror(errno));
		}
	}
	pthread_attr_destroy(&tattr);

	return do_master_thread_work(&final_stats);
}
