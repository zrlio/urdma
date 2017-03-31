/* proto.h */

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

#ifndef PROTO_TRP_H
#define PROTO_TRP_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

enum {
	trp_req = 0x1000,
		/**< Initial request from the client.  Any data in the packet
		 * is considered to be part of the RDMA CM private data
		 * exchange. */
	trp_accept = 0x2000,
		/**< Accepting a connection request from the client.  Any data
		 * in the packet is passed as private data to the client
		 * application. */
	trp_reject = 0x3000,
		/**< Rejecting a connection request from the client.  Any data
		 * in the packet is passed as private data to the client
		 * application. */
	trp_fin = 0x4000,
		/**< Indicates that the sender wishes to close the connection.
		 * The connection is destroyed as soon as this message is sent;
		 * no response from the receiver is necessary nor expected. */
	trp_sack = 0x5000,
		/**< This packet is a selective acknowledgement that contains
		 * no data.  Rather, the psn and ack_psn fields indicate the
		 * minimum and (maximum + 1) sequence numbers, respectively, in
		 * a contiguous range that have been received. */
	trp_opcode_mask = 0xf000,
		/**< Mask of all bits used for opcode. */
	trp_reserved_mask = 0x0fff,
		/**< Mask of all bits not currently used. */
	trp_opcode_shift = 12,
		/**< Number of bits that opcode is shifted by. */
};

struct trp_hdr {
	uint32_t psn;
	uint32_t ack_psn;
	uint16_t opcode;
} __attribute__((__packed__));

struct trp_rr_params {
	uint16_t pd_len;
	uint16_t ird;
	uint16_t ord;
} __attribute__((__packed__));

struct trp_rr {
	struct trp_hdr hdr;
	struct trp_rr_params params;
} __attribute__((__packed__));

#endif
