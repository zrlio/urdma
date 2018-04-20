#!/bin/bash
# setup_dpdk_node.sh
#
# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
#
# Copyright (c) 2016, IBM Corporation
# Copyright (c) 2016-2018, University of New Hampshire
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#   - Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#
#   - Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
#   - Neither the name of IBM nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Sets up DPDK on a node, along with everything needed to run as non-root
# on Ubuntu 17.10.

dpdk_group_users=(patrick)

sudo yum install bc libpcap-devel dpdk-dev \
	linux-image-generic linux-headers-generic \
	libibverbs-dev librdmacm-dev

if [[ -d /etc/modules-load.d ]]; then
    sudo tee /etc/modules-load.d/90-dpdk.conf <<EOF
vfio-pci
vfio_iommu_type1
rte_kni
EOF
fi

sudo tee /etc/udev/rules.d/99-dpdk.rules <<EOF
SUBSYSTEM=="uio", MODE="0660", GROUP="dpdk"
SUBSYSTEM=="vfio", MODE="0660", GROUP="dpdk"
DEVPATH=="/devices/virtual/misc/kni", GROUP="dpdk"
EOF

sudo tee /etc/sudoers.d/dpdk.conf <<EOF
%dpdk     ALL=(ALL)       NOPASSWD: /sbin/setcap cap_net_admin+ep *
%dpdk     ALL=(ALL)       NOPASSWD: /sbin/rmmod urdma
%dpdk     ALL=(ALL)       NOPASSWD: /sbin/modprobe urdma *
EOF

sudo groupadd dpdk
for user in "${dpdk_group_users[@]}"; do
    sudo usermod -a -G dpdk ${user}
done
