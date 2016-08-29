/* dpdk_write_client.c */

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
#include <stdbool.h>
#include <string.h>
#include <sys/prctl.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>

#include "kvstore_limits.h"
#include "options.h"
#include "util.h"
#include "proto_memcached.h"
#include "verbs.h"

#ifdef NDEBUG
#define NDEBUG_UNUSED __attribute__((unused))
#else
#define NDEBUG_UNUSED
#endif

#define RECV_BUF_LEN 25000
#define LINE_SIZE 20483
#define DEFAULT_UDP_PORT 10000

#define STAG_TABLE_BUCKET_COUNT 1024
#define STAG_TABLE_SHIFT 10
#define STAG_ENTRIES_PER_BUCKET 4
static_assert(1 << STAG_TABLE_SHIFT == STAG_TABLE_BUCKET_COUNT,
		"STAG_TABLE_SHIFT must match STAG_TABLE_BUCKET_COUNT");

#define MAX_SEND_WR 63
#define MAX_RECV_WR 63

enum output_state {
	output_request = 0,
	output_response = 1,
};

struct rdma_remote_buf {
	uint32_t rdma_stag;
	uint32_t rdma_length;
	uint64_t rdma_offset;
};

struct stag_entry {
	unsigned int lru;
	uint32_t hash;
	char key[KVSTORE_KEY_LEN_MAX + 1];
	struct rdma_remote_buf buf;
};

struct stag_bucket {
	struct stag_entry entry[STAG_ENTRIES_PER_BUCKET];
};

struct stag_table {
	struct stag_bucket bucket[STAG_TABLE_BUCKET_COUNT];
	unsigned int lru_latest;
};

struct pending_request {
	int count;
		/**< Number of remaining pending operations. The block can be
		 * re-used when count == 0. It is an invariant that
		 * count >= 0. */
	struct ibv_mr *mr;
	size_t sendbuf_capacity;
		/**< Size of the request buffer in bytes. */
	size_t rdma_length;
		/**< Size of the RDMA request made against rdmabuf. */
	char sendbuf[RECV_BUF_LEN];
	char rdmabuf[KVSTORE_VALUE_LEN_MAX];
};

struct stats {
	long long send_completion_count;
	long long recv_completion_count;
	long long write_completion_count;
	long long read_completion_count;
	long long cache_miss_count;

	uint64_t start_time;
	uint64_t end_time;
	unsigned long long message_count;
};

struct client_state {
	int pending_count;
	uint32_t request_id;
	struct rte_hash *pending_table;
	struct rdma_cm_id *cm_id;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct client_options options;
	enum output_state output_state;

	struct pending_request send_req[MAX_SEND_WR];
	char recvbuf[MAX_RECV_WR][RECV_BUF_LEN];
	struct stag_table stag_table;
	struct stats stats;
};

static void
do_output_request(struct client_state *state, uint32_t opaque, const char *line)
{
	if (!state->options.output_fp) {
		return;
	}
	if (state->output_state != output_request) {
		fprintf(state->options.output_fp, "--\r\n");
		state->output_state = output_request;
	}
	fprintf(state->options.output_fp, "%" PRIu32 ": %s\r\n", opaque, line);
	fflush(state->options.output_fp);
} /* do_ouput_request */

static void
do_output_get_response(struct client_state *state,
		struct memcached_get_resp_header *header,
		const char *key, const void *value)
{
	if (!state->options.output_fp) {
		return;
	}
	if (state->output_state != output_response) {
		fprintf(state->options.output_fp, "--\r\n");
		state->output_state = output_response;
	}
	fprintf(state->options.output_fp, "%" PRIu32 ": VALUE %s %" PRIu32 " %" PRIu32 " %" PRIu64 "\r\n%*s\r\nEND\r\n",
			header->head.opaque, key,
			rte_be_to_cpu_32(header->flags),
			rte_be_to_cpu_32(header->value_len),
			rte_be_to_cpu_64(header->head.cas_version),
			(int)rte_be_to_cpu_32(header->value_len),
			(char *)value);
	fflush(state->options.output_fp);
} /* do_ouput_get_request */

static void
do_output_rdma_write_response(struct client_state *state, uint32_t opaque)
{
	if (!state->options.output_fp) {
		return;
	}
	if (state->output_state != output_response) {
		fprintf(state->options.output_fp, "--\r\n");
		state->output_state = output_response;
	}
	fprintf(state->options.output_fp, "%" PRIu32 ": STORED\r\n", opaque);
	fflush(state->options.output_fp);
} /* do_output_rdma_write_response */

static void
do_output_rdma_read_response(struct client_state *state,
		uint32_t opaque, const char *key, size_t key_len,
		const void *value, size_t value_len)
{
	if (!state->options.output_fp) {
		return;
	}
	if (state->output_state != output_response) {
		fprintf(state->options.output_fp, "--\r\n");
		state->output_state = output_response;
	}
	fprintf(state->options.output_fp, "%" PRIu32 ": VALUE %*s 0 %zu\r\n%*s\r\nEND\r\n",
			opaque, (int)key_len, key,
			value_len, (int)value_len, (char *)value);
	fflush(state->options.output_fp);
} /* do_output_rdma_read_response */

static void
do_output_nonget_response(struct client_state *state,
		struct memcached_header *header)
{
	const char *status;
	if (!state->options.output_fp) {
		return;
	}
	if (state->output_state != output_response) {
		fprintf(state->options.output_fp, "--\r\n");
		state->output_state = output_response;
	}

	switch (rte_be_to_cpu_16(header->status)) {
	case memcached_no_error:
		switch (header->opcode) {
		case memcached_opcode_set:
		case memcached_opcode_add:
		case memcached_opcode_replace:
			status = "STORED";
			break;
		case memcached_opcode_delete:
			status = "DELETED";
			break;
		default:
			status = "OK";
			break;
		}
		break;
	case memcached_key_not_found:
		status = "NOT_FOUND";
		break;
	case memcached_key_exists:
		status = "EXISTS";
		break;
	case memcached_value_too_large:
		status = "TOO_LARGE";
		break;
	case memcached_invalid_arguments:
		status = "INVALID_ARGUMENTS";
		break;
	case memcached_item_not_stored:
		status = "NOT_STORED";
		break;
	case memcached_non_numeric_value:
		status = "NON_NUMERIC";
		break;
	case memcached_out_of_memory:
		status = "SERVER_ERROR OUT_OF_MEMORY";
		break;
	case memcached_unknown_command:
	default:
		status = "ERROR";
		break;
	}

	fprintf(state->options.output_fp, "%" PRIu32 ": %s\r\n",
			header->opaque, status);
	fflush(state->options.output_fp);
} /* do_ouput_nonget_request */

/** Unconditionally sets the stag, length, and offset for the value buffer
 * associated with the given key.  This will remove the least recently used
 * entry in the bucket if the bucket is full, and replace any existing entry
 * with the same key. */
static void
stag_table_set(struct stag_table *tbl, const char *key, size_t key_len,
		uint32_t rdma_stag, uint32_t rdma_length, uint64_t rdma_offset)
{
	struct stag_entry *lru, *cur;
	struct stag_bucket *b;
	uint32_t hash;
	int x;

	if (key_len > KVSTORE_KEY_LEN_MAX) {
		key_len = KVSTORE_KEY_LEN_MAX;
	}
	hash = rte_jhash(key, key_len, 0);
	b = &tbl->bucket[hash & ((UINT32_C(1) << STAG_TABLE_SHIFT) - 1)];
	lru = NULL;
	for (x = 0; x < STAG_ENTRIES_PER_BUCKET; ++x) {
		cur = &b->entry[x];
		if (cur->hash == hash && strncmp(cur->key, key,
						KVSTORE_KEY_LEN_MAX) == 0) {
			/* Priority 1: replace an older entry with the same
			 * key */
			lru = cur;
			break;
		} else if (!cur->key[0]) {
			/* Priority 2: take the place of an empty entry */
			lru = cur;
		} else if (!lru || (lru->key[0] != '\0'
					&& cur->lru < lru->lru)) {
			/* Priority 3: take the place of the least recently
			 * used entry in this bucket iff we can't find anything
			 * that satisfies the above conditions */
			lru = cur;
		}
	}
	lru->lru = tbl->lru_latest++;
	lru->hash = hash;
	strncpy(lru->key, key, key_len);
	lru->key[key_len] = '\0';
	lru->buf.rdma_stag = rdma_stag;
	lru->buf.rdma_length = rdma_length;
	lru->buf.rdma_offset = rdma_offset;
} /* stag_table_add */

static struct stag_entry *
stag_table_do_lookup(struct stag_table *tbl, const char *key, size_t key_len)
{
	struct stag_entry *cur;
	struct stag_bucket *b;
	uint32_t hash;
	int x;

	hash = rte_jhash(key, strnlen(key, key_len), 0);
	if (key_len > KVSTORE_KEY_LEN_MAX) {
		key_len = KVSTORE_KEY_LEN_MAX;
	}
	b = &tbl->bucket[hash & ((UINT32_C(1) << STAG_TABLE_SHIFT) - 1)];
	for (x = 0; x < STAG_ENTRIES_PER_BUCKET; ++x) {
		cur = &b->entry[x];
		if (cur->hash == hash && strncmp(cur->key, key,
					key_len) == 0) {
			return cur;
		}
	}
	return NULL;
} /* stag_table_do_lookup */

/** Lookup the stag associated with the given key.  Returns true and fills in
 * remote_buf if the key is in the table; returns false if the key is not in
 * the table. */
static bool
stag_table_lookup(struct stag_table *tbl, const char *key, size_t key_len,
		struct rdma_remote_buf *remote_buf)
{
	struct stag_entry *cur;

	cur = stag_table_do_lookup(tbl, key, key_len);
	if (!cur) {
		return false;
	}

	cur->lru++;
	memcpy(remote_buf, &cur->buf, sizeof(*remote_buf));
	return true;
} /* stag_table_lookup */

/** Remove the stag associated with the given key.  Returns true if the key was
 * removed or false if the key was not in the table. */
static bool
stag_table_del(struct stag_table *tbl, const char *key, size_t key_len)
{
	struct stag_entry *cur;

	cur = stag_table_do_lookup(tbl, key, key_len);
	if (!cur) {
		return false;
	}

	cur->key[0] = '\0';
	return true;
} /* stag_table_del */

static int
wait_for_n_completions(struct ibv_cq *cq, struct ibv_wc *wc, unsigned int n)
{
	int ret;

	do {
		ret = ibv_poll_cq(cq, n, wc);
		if (ret < 0) {
			return ret;
		}
		wc += ret;
		n -= ret;
	} while (n > 0);

	return 0;
} /* wait_for_n_completions */

static void
strtrim(char *s)
{
	char *p;
	if (*s == '\0')
		return;

	/* Place p on the last non-space character in the string */
	for (p = s + strlen(s) - 1; p != s && isspace(*p); --p)
		;

	/* Set the first space character to null.  We know that this is safe
	 * since the string is non-empty (checked above) and we started the
	 * loop above with p on the character immediately before the
	 * terminating null, so if it didn't move we will just write the
	 * terminating null over itself. */
	*(p + 1) = '\0';
}

static enum memcached_opcode
parse_opcode(const char *command)
{
	if (strcmp(command, "get") == 0) {
		return memcached_opcode_get;
	} else if (strcmp(command, "set") == 0) {
		return memcached_opcode_set;
	} else if (strcmp(command, "add") == 0) {
		return memcached_opcode_add;
	} else if (strcmp(command, "replace") == 0) {
		return memcached_opcode_replace;
	} else if (strcmp(command, "delete") == 0) {
		return memcached_opcode_delete;
	} else {
		return -1;
	}
}

static int
parse_command_get(struct client_state *state, char *key,
		struct pending_request *req, size_t *size)
{
	struct memcached_header *head;
	char *key_dest;
	size_t key_len;

	key_len = strlen(key);

	head = (struct memcached_header *)req->sendbuf;
	head->key_length = rte_cpu_to_be_16(key_len);
	head->extras_length = 0;
	head->data_type = 0;
	head->status = rte_cpu_to_be_16(0);
	head->total_body_length = rte_cpu_to_be_32(key_len);
	head->opaque = state->request_id++;
	head->cas_version = rte_cpu_to_be_64(0);
	head->rdma_stag = rte_cpu_to_be_32(req->mr->rkey);
	head->rdma_length = rte_cpu_to_be_32(req->mr->length);
	head->rdma_offset = rte_cpu_to_be_64((uintptr_t)req->mr->addr);

	key_dest = memcached_header_key(head);
	strncpy(key_dest, key, *size - sizeof(*head));

	*size = 0;

	return 0;
} /* parse_command_get */

static int
parse_command_set(struct client_state *state, char *command,
		struct pending_request *req, size_t *size)
{
	enum { max_tokens = 5 };
	struct memcached_set_req_header *head;
	char *tokens[max_tokens];
	char *key_dest;
	char *endch;
	size_t key_len;
	unsigned long value_size;
	int ret;

	head = (struct memcached_set_req_header *)req->sendbuf;

	ret = rte_strsplit(command, LINE_SIZE, tokens, max_tokens, ' ');
	if (ret < max_tokens - 1) {
		RTE_LOG(DEBUG, USER2, "Too few tokens\n");
		return -EPROTO;
	}

	key_len = strlen(tokens[0]);

	errno = 0;
	head->flags = rte_cpu_to_be_32(strtoul(tokens[1], &endch, 0));
	if (errno != 0 || *endch != '\0') {
		RTE_LOG(DEBUG, USER2, "Invalid flags\n");
		return -EPROTO;
	}

	errno = 0;
	head->expire = rte_cpu_to_be_32(strtoul(tokens[2], &endch, 0));
	if (errno != 0 || *endch != '\0') {
		RTE_LOG(DEBUG, USER2, "Invalid expiration\n");
		return -EPROTO;
	}

	errno = 0;
	value_size = strtoul(tokens[3], &endch, 0);
	if (errno != 0 || (*endch != '\0' && *endch != '\r' && *endch != '\n')
			|| value_size > *size - sizeof(*head) - key_len) {
		RTE_LOG(DEBUG, USER2, "Invalid value size %s\n",
				tokens[3]);
		return -EPROTO;
	}

	head->head.key_length = rte_cpu_to_be_16(key_len);
	head->head.extras_length = 8;
	head->head.data_type = 0;
	head->head.status = rte_cpu_to_be_16(0);
	head->head.total_body_length = rte_cpu_to_be_32(head->head.extras_length
			+ key_len + value_size);
	head->head.opaque = state->request_id++;
	head->head.cas_version = rte_cpu_to_be_64(0);
	head->head.rdma_stag = rte_cpu_to_be_32(0);
	head->head.rdma_length = rte_cpu_to_be_32(0);
	head->head.rdma_offset = rte_cpu_to_be_64(0);

	key_dest = memcached_header_key(&head->head);
	strncpy(key_dest, tokens[0], *size - sizeof(*head));

	*size = value_size;

	return 0;
} /* parse_command_set */

/** Parses a text protocol memcached protocol request in command into a binary
 * memcached protocol request.  This function will mutate command as part of
 * tokenizing it.  If a value is expected as part of the command, *size will be
 * updated with the expected size of the value.  If no value is expected for
 * the command, then *size will be set to 0. */
static int
parse_command(struct client_state *state, char *command,
		struct pending_request *req, size_t *size)
{
	enum { max_tokens = 2 };
	struct memcached_header *head;
	char *tokens[max_tokens];
	enum memcached_opcode opcode;
	int ret;

	do_output_request(state, state->request_id, command);

	head = (struct memcached_header *)req->sendbuf;
	head->magic = memcached_magic_request;

	ret = rte_strsplit(command, LINE_SIZE, tokens, max_tokens, ' ');
	if (ret < max_tokens) {
		RTE_LOG(DEBUG, USER2, "Could not split command from arguments\n");
		return -EPROTO;
	}

	opcode = parse_opcode(tokens[0]);
	if (opcode < 0) {
		RTE_LOG(DEBUG, USER2, "Unknown command: %s\n", command);
		return -EPROTO;
	}
	head->opcode = opcode;

	switch (head->opcode) {
	case memcached_opcode_set:
	case memcached_opcode_add:
	case memcached_opcode_replace:
		return parse_command_set(state, tokens[1], req, size);
	case memcached_opcode_get:
		return parse_command_get(state, tokens[1], req, size);
	case memcached_opcode_delete:
	default:
		errno = ENOTSUP;
		return -1;
	}
} /* parse_command */

static int
do_send_command(struct client_state *state,
		struct pending_request *req, struct ibv_qp *qp)
{
	struct memcached_header *head;
	struct rdma_remote_buf remote_buf;
	struct iovec iov[2];
	const char *key;
	size_t iov_count;
	size_t size;
	int ret;

	head = (struct memcached_header *)req->sendbuf;
	size = sizeof(*head) + rte_be_to_cpu_32(head->total_body_length);
	ret = rte_hash_add_key_data(state->pending_table, &head->opaque, req);
	if (ret) {
		RTE_LOG(CRIT, USER2, "Could not add request %" PRIx32 " to pending table: %s\n",
				head->opaque, strerror(-ret));
		return ret;
	}
	state->pending_count++;

	switch (head->opcode) {
	case memcached_opcode_get:
		key = memcached_header_key(head);
		if (stag_table_lookup(&state->stag_table, key,
					rte_be_to_cpu_16(head->key_length),
					&remote_buf)) {
			req->rdma_length = RTE_MIN(remote_buf.rdma_length,
					(size_t)KVSTORE_VALUE_LEN_MAX);
			return usiw_accl_post_read(qp, req->rdmabuf,
					req->rdma_length, NULL,
					remote_buf.rdma_offset,
					remote_buf.rdma_stag, req);
		}
		break;
	case memcached_opcode_set:
	case memcached_opcode_replace:
		key = memcached_header_key(head);
		if (stag_table_lookup(&state->stag_table, key,
					rte_be_to_cpu_16(head->key_length),
					&remote_buf)) {
			req->rdma_length = RTE_MIN(remote_buf.rdma_length,
					req->rdma_length);
			return usiw_accl_post_write(qp, req->rdmabuf,
					req->rdma_length, NULL,
					remote_buf.rdma_offset,
					remote_buf.rdma_stag, req);
		}
		break;
	default:
		/* fall out of switch for default behavior */
		break;
	}

	/* We are performing a two-sided operation and must await the receive
	 * completion as well */
	req->count++;
	iov[0].iov_base = req->sendbuf;
	iov[0].iov_len = size - req->rdma_length;
	iov_count = 1;
	if (req->rdma_length > 0) {
		iov_count++;
		iov[1].iov_base = req->rdmabuf;
		iov[1].iov_len = req->rdma_length;
	}
	return usiw_accl_post_sendv(qp, iov, iov_count, NULL, req);
} /* do_send_command */

/** Reads the next command from the text input stream, converts it to its
 * binary representation, and sends it to the server. Returns true if it read
 * a command and false if it did not. This function will terminate the program
 * if there is an I/O error or malformed command. */
static bool
send_next_command(struct client_state *state,
		FILE *fp, struct pending_request *req)
{
	struct memcached_header *req_head;
	char command[LINE_SIZE];
	size_t size;
	int ret;

	assert(req->count == 0);
	if (fgets(command, sizeof(command), fp) == NULL) {
		return false;
	}
	req->count = 1;
	strtrim(command);
	size = req->sendbuf_capacity;
	ret = parse_command(state, command, req, &size);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid input: %s\n", strerror(-ret));
	}
	if (size) {
		errno = 0;
		req->rdma_length = size;
		if (fread(req->rdmabuf, 1, size, fp) < size) {
			rte_exit(EXIT_FAILURE, "Invalid input: missing value: %s\n",
					feof(fp)
					? "unexpected end of file"
					: strerror(errno));
		}
		if (fgets(command, LINE_SIZE, fp) == NULL
				|| (command[0] != '\n' && (command[0] == '\r'
						&& command[1] != '\n'))) {
			rte_exit(EXIT_FAILURE, "Malformed input: missing newline after end of value\n");
		}
		req_head = (struct memcached_header *)req->sendbuf;
		do_output_request(state, req_head->opaque, req->rdmabuf);
	} else {
		req->rdma_length = 0;
	}
	ret = do_send_command(state, req, state->cm_id->qp);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Could not send parsed request: %s\n",
				strerror(-ret));
	}

	state->stats.message_count++;
	return true;
} /* send_next_command */

/** Decrements the pending completion count for the given request.  This
 * function requires that the hash (Jenkins hash) be pre-computed for the
 * opaque request ID.  The pointer is reset to NULL if the request is still
 * pending, i.e., we need to await more completions.  If the pointer is *not*
 * reset to NULL, the count has reached 0 and the request context may be
 * reused. */
static void
pending_request_unref(struct client_state *state,
		struct pending_request **req, hash_sig_t hash)
{
	struct memcached_header *head;
	NDEBUG_UNUSED int ret;

	if (--(*req)->count > 0) {
		*req = NULL;
		return;
	}

	head = (struct memcached_header *)((*req)->sendbuf);
	RTE_LOG(DEBUG, USER2, "Freeing request with opaque=%" PRIx32 "\n",
			head->opaque);
	ret = rte_hash_del_key_with_hash(state->pending_table,
			&head->opaque, hash);
	assert(ret >= 0);
	state->pending_count--;
} /* pending_request_unref */

static void
handle_good_get_response(struct client_state *state,
		struct pending_request *req,
		struct memcached_get_resp_header *resp)
{
	struct memcached_header *req_head;
	NDEBUG_UNUSED size_t key_length;

	req_head = (struct memcached_header *)req->sendbuf;
	key_length = rte_be_to_cpu_16(req_head->key_length);
	assert(key_length > 0);
	do_output_get_response(state, resp, memcached_header_key(req_head),
			req->rdmabuf);
} /* handle_good_get_response */

/** Handles an RDMA WRITE completion.  This is a virtual SET response.  This
 * function returns the request operation that originated the RDMA WRITE, which
 * may be immediately reused for another request. */
static struct pending_request *
handle_rdma_write_completion(struct client_state *state,
		struct pending_request *req)
{
	struct memcached_header *req_head;
	hash_sig_t hash;

	req_head = (struct memcached_header *)req->sendbuf;
	hash = rte_hash_hash(state->pending_table, &req_head->opaque);

	do_output_rdma_write_response(state, req_head->opaque);

	pending_request_unref(state, &req, hash);
	assert(req != NULL);
	return req;
} /* handle_rdma_read_completion */

/** Handles an RDMA READ completion.  This is a virtual GET response.  This
 * function returns the request operation that originated the RDMA READ, which
 * may be immediately reused for another request. */
static struct pending_request *
handle_rdma_read_completion(struct client_state *state,
		struct pending_request *req)
{
	struct memcached_header *req_head;
	hash_sig_t hash;
	size_t key_length;

	req_head = (struct memcached_header *)req->sendbuf;
	hash = rte_hash_hash(state->pending_table, &req_head->opaque);

	key_length = rte_be_to_cpu_16(req_head->key_length);
	do_output_rdma_read_response(state, req_head->opaque,
			memcached_header_key(req_head),
			key_length, req->rdmabuf, req->rdma_length);

	pending_request_unref(state, &req, hash);
	assert(req != NULL);
	return req;
} /* handle_rdma_read_completion */

/** Handles an incoming response.  If the response is valid and is the last
 * completions for its corresponding request, this function will return a
 * pointer to the request context and it may be immediately reused.  Otherwise,
 * this function will return NULL. */
static struct pending_request *
handle_response(struct client_state *state, struct memcached_header *resp)
{
	struct pending_request *req;
	struct memcached_header *req_head;
	int_least32_t ret;
	uint_fast16_t status;
	const char *key;
	size_t key_length;
	hash_sig_t hash;

	if (resp->magic != memcached_magic_response) {
		RTE_LOG(NOTICE, USER2, "Received malformed response: incorrect magic number %" PRIx8 "\n",
				resp->magic);
		return NULL;
	}

	hash = rte_hash_hash(state->pending_table, &resp->opaque);
	ret = rte_hash_lookup_with_hash_data(state->pending_table,
			&resp->opaque, hash, (void **)&req);
	if (ret == -ENOENT) {
		return NULL;
	} else {
		assert(ret >= 0);
	}

	status = rte_be_to_cpu_16(resp->status);
	switch (status) {
	case memcached_no_error:
		req_head = (struct memcached_header *)req->sendbuf;

		key_length = rte_be_to_cpu_16(req_head->key_length);
		if (key_length > 0) {
			key = memcached_header_key(req_head);
			stag_table_set(&state->stag_table, key, key_length,
					rte_be_to_cpu_32(resp->rdma_stag),
					rte_be_to_cpu_32(resp->rdma_length),
					rte_be_to_cpu_64(resp->rdma_offset));
		}

		switch (req_head->opcode) {
		case memcached_opcode_get:
			handle_good_get_response(state, req,
				(struct memcached_get_resp_header *)resp);
			break;
		default:
			do_output_nonget_response(state, resp);
			break;
		}
		break;
	default:
		do_output_nonget_response(state, resp);
		RTE_LOG(NOTICE, USER2, "Received error response to opaque=%" PRIx32 ": %" PRIxFAST16 "\n",
				resp->opaque, status);
		break;
	}

	pending_request_unref(state, &req, hash);
	return req;
} /* handle_response */


static struct pending_request *
handle_completion_failure(struct client_state *state, struct ibv_wc *wc)
{
	struct memcached_header *req_head;
	struct pending_request *req;
	const char *key;

	if (wc->status == IBV_WC_REM_ACCESS_ERR) {
		/* We got an error due to an invalid stag for an RDMA READ or
		 * RDMA WRITE.  Most likely the stag expired.  We can remove
		 * the old stag entry and redo the command using SEND which
		 * should work; otherwise next time we'll exit. */
		req = (void *)(uintptr_t)wc->wr_id;
		req_head = (struct memcached_header *)req->sendbuf;
		key = memcached_header_key(req_head);
		stag_table_del(&state->stag_table, key,
				rte_be_to_cpu_16(req_head->key_length));
		state->stats.cache_miss_count++;
		state->pending_count--;
		do_send_command(state, req, state->cm_id->qp);
	} else {
		rte_exit(EXIT_FAILURE, "Got non-success completion status\n");
	}

	/* We cannot reuse this request in any case. */
	return NULL;
} /* handle_completion_failure */

static void
dump_stats(FILE *stream, const struct stats *stats)
{
	uint64_t elapsed_cycles;
	double physical_time;

	elapsed_cycles = stats->end_time - stats->start_time;
	physical_time = (double)elapsed_cycles / rte_get_timer_hz();

	fprintf(stream, "{\n  \"message_count\": %llu,\n",
			stats->message_count);
	fprintf(stream, "  \"physical_time\": %.9f,\n",
			physical_time);
	fprintf(stream, "  \"message_rate\": %.9f,\n",
			stats->message_count / physical_time);
	fprintf(stream, "  \"recv_completion_count\": %lld,\n",
			stats->recv_completion_count);
	fprintf(stream, "  \"write_completion_count\": %lld,\n",
			stats->write_completion_count);
	fprintf(stream, "  \"read_completion_count\": %lld,\n",
			stats->read_completion_count);
	fprintf(stream, "  \"cache_miss_count\": %lld\n}\n",
			stats->cache_miss_count);
} /* print_stats */

static struct pending_request *
handle_completion(struct client_state *state,
		struct ibv_qp *qp, struct ibv_wc *wc)
{
	struct pending_request *req;
	struct memcached_header *head;
	void *wr_context;

	if (wc->status != IBV_WC_SUCCESS) {
		return handle_completion_failure(state, wc);
	}

	wr_context = (void *)(uintptr_t)wc->wr_id;
	switch (wc->opcode) {
	case IBV_WC_RECV:
		req = handle_response(state, wr_context);
		usiw_accl_post_recv(qp, wr_context, RECV_BUF_LEN,
				wr_context);
		state->stats.recv_completion_count++;
		break;
	case IBV_WC_SEND:
		req = wr_context;
		head = (struct memcached_header *)req->sendbuf;
		pending_request_unref(state, &req, rte_hash_hash(
					state->pending_table,
					&head->opaque));
		state->stats.send_completion_count++;
		break;
	case IBV_WC_RDMA_READ:
		req = handle_rdma_read_completion(state, wr_context);
		state->stats.read_completion_count++;
		break;
	case IBV_WC_RDMA_WRITE:
		req = handle_rdma_write_completion(state, wr_context);
		state->stats.write_completion_count++;
		break;
	default:
		req = NULL;
		break;
	}

	return req;
} /* handle_completion */

static void
do_master_lcore_work(struct client_state *state)
{
	const struct client_options *options = &state->options;
	struct pending_request *req;
	struct ibv_wc wc;
	int x;

	state->stats.start_time = rte_get_timer_cycles();
	for (x = 0; x < MAX_SEND_WR; ++x) {
		if (!send_next_command(state, options->command_fp,
					&state->send_req[x])) {
			rte_exit(EXIT_FAILURE, "Not enough commands in input\n");
		}
	}

	while (1) {
		x = wait_for_n_completions(state->cq, &wc, 1);
		assert(x == 1);
		req = handle_completion(state, state->cm_id->qp, &wc);
		if (req && !send_next_command(state,
					options->command_fp, req)) {
			/* We're done getting keys */
			break;
		}
	}

	RTE_LOG(INFO, USER2, "Seeded all keys\n");
	while (state->pending_count > 0) {
		RTE_LOG(DEBUG, USER2, "%d requests still pending\n",
				state->pending_count);
		x = wait_for_n_completions(state->cq, &wc, 1);
		assert(x == 1);
		(void)handle_completion(state, state->cm_id->qp, &wc);
	}
	RTE_LOG(INFO, USER2, "Got all SEND and RECV completions\n");
	state->stats.end_time = rte_get_timer_cycles();
	dump_stats(stdout, &state->stats);
}

static void
init_send_bufs(struct client_state *state)
{
	struct rte_hash_parameters hparam;
	struct pending_request *req;
	int x;

	for (x = 0; x < MAX_SEND_WR; ++x) {
		req = &state->send_req[x];
		req->sendbuf_capacity = RECV_BUF_LEN;
		req->mr = ibv_reg_mr(state->pd,
				req->rdmabuf,
				KVSTORE_VALUE_LEN_MAX,
				IBV_ACCESS_REMOTE_WRITE);
		if (!req->mr) {
			rte_exit(EXIT_FAILURE, "Could not register RDMA buffer: %s\n",
					strerror(errno));
		}
	}

	memset(&hparam, 0, sizeof(hparam));
	hparam.name = "pending_table";
	hparam.entries = 2 * MAX_SEND_WR;
	hparam.key_len = sizeof(uint32_t);
	hparam.hash_func = rte_jhash;
	hparam.hash_func_init_val = 0;
	hparam.socket_id = rte_socket_id();

	state->pending_table = rte_hash_create(&hparam);
	if (!state->pending_table) {
		rte_exit(EXIT_FAILURE, "Could not create pending send table: %s\n",
				rte_strerror(rte_errno));
	}
} /* init_send_bufs */


static struct client_state *
client_new(struct sockaddr *local_addr, struct sockaddr *server_addr)
{
	struct ibv_qp_init_attr qp_init_attr;
	struct rdma_conn_param conn_params;
	struct ibv_device_attr ib_devattr;
	struct client_state *state;
	int ret, x;

	state = calloc(1, sizeof(*state));
	if (!state) {
		perror("allocate server context");
		return NULL;
	}

	if (rdma_create_id(NULL, &state->cm_id, state, RDMA_PS_TCP)) {
		perror("rdma_create_id");
		goto free_state;
	}

	if (rdma_resolve_addr(state->cm_id, local_addr, server_addr, 2000)) {
		perror("rdma_resolve_addr");
		goto free_cm_id;
	}

	ret = ibv_query_device(state->cm_id->verbs, &ib_devattr);
	if (ret) {
		perror("ibv_query_device");
		goto free_cm_id;
	} else if (ib_devattr.vendor_id != USIW_DEVICE_VENDOR_ID
			|| ib_devattr.vendor_part_id
					!= USIW_DEVICE_VENDOR_PART_ID) {
		fprintf(stderr, "Bound device is not our driver\n");
		goto free_cm_id;
	}

	if (rdma_resolve_route(state->cm_id, 2000)) {
		perror("rdma_resolve_route");
		goto free_cm_id;
	}

	state->pd = ibv_alloc_pd(state->cm_id->verbs);
	if (!state->pd) {
		perror("ibv_alloc_pd");
		goto free_cm_id;
	}

	state->cq = ibv_create_cq(state->cm_id->verbs, 127, NULL, NULL, 0);
	if (!state->cq) {
		perror("ibv_create_cq");
		goto free_pd;
	}

	qp_init_attr.qp_context = NULL;
	qp_init_attr.send_cq = state->cq;
	qp_init_attr.recv_cq = state->cq;
	qp_init_attr.srq = NULL;
	qp_init_attr.cap.max_send_wr = MAX_SEND_WR;
	qp_init_attr.cap.max_recv_wr = MAX_SEND_WR;
	qp_init_attr.cap.max_send_sge = 2;
	qp_init_attr.cap.max_recv_sge = 2;
	qp_init_attr.cap.max_inline_data = 0;
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 1;
	if (rdma_create_qp(state->cm_id, state->pd, &qp_init_attr)) {
		perror("rdma_create_qp");
		goto free_cq;
	}

	init_send_bufs(state);

	for (x = 0; x < MAX_RECV_WR; ++x) {
		ret = usiw_accl_post_recv(state->cm_id->qp, state->recvbuf[x],
				RECV_BUF_LEN, state->recvbuf[x]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Error posting receive %u: %s\n",
				x, strerror(-ret));
	}

	conn_params.private_data = NULL;
	conn_params.private_data_len = 0;
	conn_params.responder_resources = 1;
	conn_params.initiator_depth = 1;
	conn_params.flow_control = 0;
	conn_params.rnr_retry_count = 7;
	ret = rdma_connect(state->cm_id, &conn_params);
	if (ret < 0) {
		perror("rdma_connect");
		goto free_qp;
	}
	goto out;

free_qp:
	rdma_destroy_qp(state->cm_id);
free_cq:
	ibv_destroy_cq(state->cq);
free_pd:
	ibv_dealloc_pd(state->pd);
free_cm_id:
	rdma_destroy_id(state->cm_id);
free_state:
	free(state);
	state = NULL;
out:
	return state;
} /* init_port */


static void
usage(int exit_status, const char *reason)
{
        rte_exit(exit_status, "%s\nUsage: dpdk_write_client -- %s <iface_ip> <server_ip> [<port>]\n",
                option_string(), reason);
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct client_options options;
	struct client_state *state;
	struct sockaddr_in local_inaddr, server_inaddr;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	ret = parse_options(argc, argv, &options);
	if (ret < 0) {
		usage(EXIT_FAILURE, "Error processing command-line options");
	}

	argv[ret] = argv[0];
	argc -= ret;
	argv += ret;

	if (argc < 2) {
		usage(EXIT_FAILURE, "Insufficient arguments");
	}

	local_inaddr.sin_family = AF_INET;
	local_inaddr.sin_port = 0;
	local_inaddr.sin_addr.s_addr = INADDR_ANY;

	server_inaddr.sin_family = AF_INET;
	server_inaddr.sin_port = rte_cpu_to_be_16(DEFAULT_UDP_PORT);
	if (parse_ipv4_address(argv[1], &server_inaddr.sin_addr.s_addr,
				NULL) != 0) {
		usage(EXIT_FAILURE, "Bad IP address");
	}

	state = client_new((struct sockaddr *)&local_inaddr,
			(struct sockaddr *)&server_inaddr);
	if (!state) {
		rte_exit(EXIT_FAILURE, "Could not initialize client state");
	}
	state->options = options;

	if (rte_lcore_count() > 1)
		RTE_LOG(DEBUG, USER2,
			"\nWARNING: Too many lcores enabled. Only 1 used.\n");

	do_master_lcore_work(state);
	return EXIT_SUCCESS;
}
