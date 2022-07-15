/* proto.h */

/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
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

#ifndef PROTO_H
#define PROTO_H

#include "proto_trp.h"

#define UDP_IPV4_HDR_LEN (sizeof(struct udp_hdr) + sizeof(struct ipv4_hdr) + ETHER_HDR_LEN)
#define RDMAP_MAX_PAYLOAD(mtu, type) (mtu - (sizeof(type) + UDP_IPV4_HDR_LEN))

#define DDP_V1_UNTAGGED_DF 0x01
#define DDP_V1_TAGGED_DF 0x81
#define DDP_V1_UNTAGGED_LAST_DF 0x41
#define DDP_V1_TAGGED_LAST_DF 0xc1
#define DDP_GET_T(flags) ((flags >> 7) & 0x1)
#define DDP_GET_L(flags) ((flags >> 6) & 0x1)
#define DDP_GET_DV(flags) ((flags) & 0x3)

#define RDMAP_V1 0x40
#define RDMAP_GET_RV(flags) ((flags >> 6) & 0x3)
#define RDMAP_GET_OPCODE(flags) ((flags) & 0xf)

/** Given a pointer to a structure representing a packet header, returns a
 * pointer to the payload (one byte immediately after the header) */
#define PAYLOAD_OF(x) ((char *)((x) + 1))

struct rdmap_packet {
	uint8_t ddp_flags; /* 0=Tagged 1=Last 7-6=DDP_Version */
	uint8_t rdmap_info; /* 1-0=RDMAP_Version 7-4=Opcode */
	uint32_t sink_stag;
	uint32_t immediate; /* The immediate data */
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_packet) == 10, "unexpected sizeof(rdmap_packet)");

enum ddp_queue_number {
	ddp_queue_send = 0,
	ddp_queue_read_request = 1,
	ddp_queue_terminate = 2,
	ddp_queue_atomic_response = 3,
	ddp_queue_ack = 4,
};

enum rdmap_atomic_opcodes {
	rdmap_atomic_fetchadd = 0,
	rdmap_atomic_cmpswap = 1,
};

struct rdmap_tagged_packet {
	struct rdmap_packet head;
	uint64_t offset;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_tagged_packet) == 18, "unexpected sizeof(rdmap_tagged_packet)");

struct rdmap_untagged_packet {
	struct rdmap_packet head;
	uint32_t qn; /* Queue Number */
	uint32_t msn; /* Message Sequence Number */
	uint32_t mo; /* Message Offset */
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_untagged_packet) == 22, "unexpected sizeof(rdmap_untagged_packet)");

#define RDMAP_TAGGED_ALLOC_SIZE(len) (sizeof(struct rdmap_tagged_packet) + (len))
#define RDMAP_UNTAGGED_ALLOC_SIZE(len) (sizeof(struct rdmap_untagged_packet) + (len))

struct rdmap_readreq_packet {
	struct rdmap_untagged_packet untagged;
	uint64_t sink_offset;
	uint32_t read_msg_size;
	uint32_t source_stag;
	uint64_t source_offset;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_readreq_packet) == 46, "unexpected sizeof(rdmap_readreq_packet)");

struct rdmap_terminate_packet {
	struct rdmap_untagged_packet untagged;
	uint16_t error_code; /* 0-3 layer 4-7 etype 8-16 code */
	uint8_t hdrct; /* bits: 0-M 1-D 2-R */
	uint8_t reserved;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_terminate_packet) == 26, "unexpected sizeof(rdmap_terminate_packet)");

struct rdmap_terminate_payload {
	uint16_t ddp_seg_len;
	struct rdmap_packet payload;
} __attribute__((__packed__));

struct rdmap_atomicreq_packet {
	struct rdmap_untagged_packet untagged;
	uint32_t opcode;
	uint32_t req_id;
	uint32_t remote_stag;
	uint64_t remote_offset;
	uint64_t add_swap_data;
	uint64_t add_swap_mask;
	uint64_t compare_data;
	uint64_t compare_mask;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_atomicreq_packet) == 74, "unexpected sizeof(rdmap_atomicreq_packet)");

struct rdmap_atomicresp_packet {
	struct rdmap_untagged_packet untagged;
	uint32_t req_id;
	uint64_t orig_value;
} __attribute__((__packed__));
static_assert(sizeof(struct rdmap_atomicresp_packet) == 34, "unexpected sizeof(rdmap_atomicresp_packet)");

enum rdmap_packet_type {
	rdmap_opcode_rdma_write = 0,
	rdmap_opcode_rdma_read_request = 1,
	rdmap_opcode_rdma_read_response = 2,
	rdmap_opcode_send = 3,
	rdmap_opcode_send_inv = 4,
	rdmap_opcode_send_se = 5,
	rdmap_opcode_send_se_inv = 6,
	rdmap_opcode_terminate = 7,
	rdmap_opcode_imm_data = 8,
	rdmap_opcode_imm_data_se = 9,
	rdmap_opcode_atomic_request = 10,
	rdmap_opcode_atomic_response = 11,
	rdmap_opcode_rdma_write_with_imm = 12,
	rdmap_opcode_send_with_imm = 13,
};

enum /*rdmap_hdrct*/ {
	rdmap_hdrct_m = 1,
	rdmap_hdrct_d = 2,
	rdmap_hdrct_r = 4,
};

enum rdmap_errno {
	rdmap_error_local_catastrophic = 0x0000,
	rdmap_error_stag_invalid = 0x0100,
	rdmap_error_base_or_bounds_violation = 0x0101,
	rdmap_error_access_violation = 0x0102,
	rdmap_error_stag_wrong_stream = 0x0103,
	rdmap_error_to_wrap = 0x0104,
	rdmap_error_protection_stag_not_invalidated = 0x0109,
	rdmap_error_remote_protection_unspecified = 0x01ff,
	rdmap_error_version_invalid = 0x0205,
	rdmap_error_opcode_unexpected = 0x0206,
	rdmap_error_remote_stream_catastrophic = 0x0207,
	rdmap_error_remote_global_catastrophic = 0x0208,
	rdmap_error_operation_stag_not_invalidated = 0x0209,
	rdmap_error_remote_operation_unspecified = 0x02ff,
	ddp_error_local_catastrophic = 0x1000,
	ddp_error_tagged_stag_invalid = 0x1100,
	ddp_error_tagged_base_or_bounds_violation = 0x1101,
	ddp_error_tagged_stag_wrong_stream = 0x1102,
	ddp_error_tagged_to_wrap = 0x1103,
	ddp_error_tagged_version_invalid = 0x1104,
	ddp_error_untagged_invalid_qn = 0x1201,
	ddp_error_untagged_no_buffer = 0x1202,
	ddp_error_untagged_invalid_msn = 0x1203,
	ddp_error_untagged_invalid_mo = 0x1204,
	ddp_error_untagged_message_too_long = 0x1205,
	ddp_error_untagged_version_invalid = 0x1206,
};

#endif
