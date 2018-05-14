#!/bin/bash
#
# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
#
# Copyright (c) 2016, IBM Corporation
# Copyright (c) 2018, University of New Hampshire
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

if [[ $# -ne 1 ]]; then
	printf "Usage: %s <profile>\n" "$0" >&2
	printf "\nExample profiles are stored in config/profiles\n"
	exit 1
fi

profile=$1
source "${profile}"

# Make input variables read-only
readonly TOP_SRCDIR DEPLOY_DIR SERVER_NODE CLIENT_NODE
readonly SERVER_DPDK_IP
readonly CLIENT_DPDK_IP
readonly SERVER_EXTRA_ARGS CLIENT_EXTRA_ARGS

# Log ID
LOGID=$(date +%Y%m%d-%H%M)
readonly LOGID

readonly our_tmpdir=$(mktemp -d)
trap "rm -rf ${our_tmpdir}" EXIT
mkfifo ${our_tmpdir}/server_fifo
mkfifo ${our_tmpdir}/client_fifo

cd ${TOP_SRCDIR}
ssh ${SERVER_NODE} mkdir -p ${DEPLOY_DIR}
ssh ${CLIENT_NODE} mkdir -p ${DEPLOY_DIR}
rm -f urdma-*.tar.gz
make distcheck || exit 1
tarname=urdma-*.tar.gz
tarbn=$(basename ${tarname} .tar.gz)
ssh ${SERVER_NODE} tar -C ${DEPLOY_DIR} -xz <${tarname}
ssh ${CLIENT_NODE} tar -C ${DEPLOY_DIR} -xz <${tarname}
tmux neww -n dpdk-server \
	"ret=127
	trap 'exec 3>${our_tmpdir}/server_fifo; echo \${ret} >&3' EXIT
	ssh -t ${SERVER_NODE} ${DEPLOY_DIR}/${tarbn}/scripts/run_real.sh \
	${DEPLOY_DIR}/${tarbn} ${SERVER_APP} ${LOGID} \
	${SERVER_EXTRA_ARGS}
	ret=\$?"
sleep 5
tmux neww -n dpdk-client \
	"ret=127
	trap 'exec 3>${our_tmpdir}/client_fifo; echo \${ret} >&3' EXIT
	ssh -t ${CLIENT_NODE} ${DEPLOY_DIR}/${tarbn}/scripts/run_real.sh \
	${DEPLOY_DIR}/${tarbn} ${CLIENT_APP} ${LOGID} \
	${CLIENT_EXTRA_ARGS} \
	-a ${SERVER_DPDK_IP}
	ret=\$?"

exec 3<${our_tmpdir}/server_fifo
read server_ret <&3
exec 3<&-

exec 3<${our_tmpdir}/client_fifo
read client_ret <&3
exec 3<&-

rsync -a ${SERVER_NODE}:log/ ${HOME}/log/${SERVER_NODE}
rsync -a ${CLIENT_NODE}:log/ ${HOME}/log/${CLIENT_NODE}

printf "Output is in the following log files:\n"
printf " %s/log/%s/%s/%s.log\n" \
	"${HOME}" "${SERVER_NODE}" "${SERVER_APP}" "${LOGID}"
printf " %s/log/%s/%s/%s.log\n" \
	"${HOME}" "${CLIENT_NODE}" "${CLIENT_APP}" "${LOGID}"

if [[ ${server_ret} -ne 0 ]]; then
	exit ${server_ret}
elif [[ ${client_ret} -ne 0 ]]; then
	exit ${client_ret}
fi
