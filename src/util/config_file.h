/*
 * Userspace Software iWARP library for DPDK
 *
 * Authors: Patrick MacArthur <pam@zurich.ibm.com>
 *
 * Copyright (c) 2016, IBM Corporation
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

#include <stdio.h>
#include <rte_pci.h>

enum { ipv4_addr_len_max = 20 };

enum urdma_port_id_type {
	urdma_port_id_index = 0,
	urdma_port_id_pci = 1,
};

struct json_object;

struct usiw_port_config {
	int id_type;
	struct rte_pci_addr pci_address;
	unsigned int mtu;
	unsigned int rx_desc_count;
	unsigned int tx_desc_count;
	unsigned int rx_burst_size;
	unsigned int tx_burst_size;
	int max_qp;
	char ipv4_address[ipv4_addr_len_max];
};

struct usiw_config {
	struct json_object *root;
};

int
urdma__config_file_get_ports(struct usiw_config *config,
			     struct usiw_port_config **port_config);

int
urdma__config_file_get_eal_args(struct usiw_config *config, char **argv);

char *
urdma__config_file_get_sock_name(struct usiw_config *config);

int
urdma__config_file_get_timer_interval(struct usiw_config *config);

int
urdma__config_file_open(struct usiw_config *config);

void
urdma__config_file_close(struct usiw_config *config);
