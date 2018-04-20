#!/bin/bash
#
# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
#
# Copyright (c) 2016, IBM Corporation
# Copyright (c) 2016, University of New Hampshire
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

TOP_SRCDIR=$1
TESTAPP=$2
LOGID=$3
shift 3

LOGFILE=${HOME}/log/${TESTAPP}/${LOGID}.log

readonly TOP_SRCDIR TESTIP LOGFILE
export LOGFILE

set -ex
mkdir -p $(dirname ${LOGFILE})
exec > >(tee ${LOGFILE}) 2>&1

cd ${TOP_SRCDIR}
make O=build clean
make O=build
sudo make O=build RTE_SDK=${RTE_SDK} RTE_TARGET=${RTE_TARGET} modules_install
sudo setcap cap_net_admin+ep ${TOP_SRCDIR}/build/src/${TESTAPP}/${RTE_TARGET}/app/${TESTAPP}

sudo modprobe -r urdma &>/dev/null || true
sudo modprobe urdma

export IBV_DRIVERS=$(realpath build/src/liburdma/${RTE_TARGET}/lib/liburdma)
perf record --call-graph dwarf -o ${HOME}/perf.${LOGID}.data -- ${TOP_SRCDIR}/build/src/${TESTAPP}/${RTE_TARGET}/app/${TESTAPP} "$@"
