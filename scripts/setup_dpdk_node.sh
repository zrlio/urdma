#!/bin/bash
# setup_dpdk_node.sh
#
# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <pam@zurich.ibm.com>
#
# Copyright (c) 2016, IBM Corporation
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

# Sets up DPDK on a node, along with everything needed to run as non-root.

kernel_version=3.17.8
dpdk_version=2.2.0
dpdk_target=x86_64-native-linuxapp-gcc
dpdk_prefix=${HOME}/.local/dpdk/${dpdk_version}
dpdk_group_users=(patrick)

sudo yum install bc libpcap-devel

cd /usr/src
tar xf ${HOME}/downloads/linux-${kernel_version}.tar.xz
cd linux-${kernel_version}
cp /boot/config-$(uname -r) .config
make olddefconfig
make -j8
make modules_install
make install

KDIR=/usr/src/linux-${kernel_version}

tmpdir=$(mktemp -d)
trap "cd /; rm -rf ${tmpdir}" EXIT
cd ${tmpdir}

tar xf ${HOME}/downloads/dpdk-${dpdk_version}.tar.gz
cd dpdk-${dpdk_version}
make config T=${dpdk_target}
sed -i -e 's/^CONFIG_RTE_LIBRTE_PMD_PCAP=/&y/' \
    -e 's/^CONFIG_RTE_EAL_IGB_UIO=/&n/' \
    build/.config
make -j8 EXTRA_CFLAGS=-g RTE_KERNEL=${KDIR}
make install prefix=${HOME}/.local/dpdk/${dpdk_version} \
    kerneldir=\$\(prefix\)/kmod
sudo mkdir -p /lib/modules/$(uname -r)/extra/dpdk
sudo cp ${HOME}/.local/dpdk/${dpdk_version}/kmod/rte_kni.ko \
    /lib/modules/$(uname -r)/extra/dpdk
sudo depmod -A

mkdir -p ${HOME}/privatemodules/dpdk
cat >${HOME}/privatemodules/dpdk/${dpdk_version} <<EOF
#%Module1.0
##
## DPDK ${dpdk_version} for ${dpdk_target} target
##

proc ModulesHelp { } {
   puts stderr "This module loads DPDK ${dpdk_version} into the user's path"
}
module-whatis  "Data Plane Development Kit ${dpdk_version} built with gcc for Linux"

conflict dpdk

setenv	RTE_SDK		${dpdk_prefix}/share/dpdk
setenv	RTE_TARGET	${dpdk_target}
setenv  RTE_KERNEL      ${KDIR}

prepend-path PATH ${dpdk_prefix}/bin
prepend-path PATH ${dpdk_prefix}/sbin
EOF

mkdir -p /etc/rdma
sudo tee /etc/rdma/rdma.conf <<EOF
# Load IPoIB
IPOIB_LOAD=no
# Load SRP (SCSI Remote Protocol initiator support) module
SRP_LOAD=no
# Load SRPT (SCSI Remote Protocol target support) module
SRPT_LOAD=no
# Load iSER (iSCSI over RDMA initiator support) module
ISER_LOAD=no
# Load iSERT (iSCSI over RDMA target support) module
ISERT_LOAD=no
# Load RDS (Reliable Datagram Service) network protocol
RDS_LOAD=no
# Load NFSoRDMA client transport module
XPRTRDMA_LOAD=no
# Load NFSoRDMA server transport module
SVCRDMA_LOAD=no
# Should we modify the system mtrr registers?  We may need to do this if you
# get messages from the ib_ipath driver saying that it couldn't enable
# write combining for the PIO buffs on the card.
#
# Note: recent kernels should do this for us, but in case they don't, we'll
# leave this option
FIXUP_MTRR_REGS=no

EOF

if [[ -d /etc/modules-load.d ]]; then
    sudo tee /etc/modules-load.d/90-dpdk.conf <<EOF
ib_core
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
%dpdk     ALL=(ALL)       NOPASSWD: /sbin/rmmod siw2
%dpdk     ALL=(ALL)       NOPASSWD: /sbin/insmod /home/pam/src/usiw/build/src/kdpdkverbs/x86_64-native-linuxapp-gcc/kmod/usiw.ko
EOF

sudo groupadd dpdk
for user in "${dpdk_group_users[@]}"; do
    sudo usermod -a -G dpdk ${user}
done
