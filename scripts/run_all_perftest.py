#!/usr/bin/env python3
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

import copy
import datetime
import json
import os
import os.path
import random
import re
import subprocess as subp
import sys
import tempfile
import time

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

logroot = os.path.join(os.environ['HOME'], 'results', 'perftest')
node0 = 'este'
node0_iface_ip = '10.0.1.1'
node1 = 'bobbio'
node1_iface_ip = '10.0.1.2'
iteration_count = 2000

col_Mbits = 'BW average[Mb/sec]'
col_Mbytes = 'BW average[MB/sec]'
col_lat_min = 't_min[usec]'
col_lat_median = 't_typical[usec]'
col_lat_max = 't_max[usec]'
col_size = '#bytes'


def log_file_name(app, logid, role):
    return os.path.join(logroot, app, logid, '{}.{}.log'.format(app, role))


def run_test(app, logid):
    print("Running {}...".format(app), end='')
    sys.stdout.flush()

    if app == 'ib_read_bw':
        client_node = node0
        client_iface_ip = node0_iface_ip
        server_node = node1
        server_iface_ip = node1_iface_ip
    else:
        server_node = node0
        server_iface_ip = node0_iface_ip
        client_node = node1
        client_iface_ip = node1_iface_ip

    server_results_filename = log_file_name(app, logid, 'server')
    client_results_filename = log_file_name(app, logid, 'client')
    os.makedirs(os.path.dirname(server_results_filename), exist_ok=False)

    with open(server_results_filename, 'w') as server_out_fp, \
            open(client_results_filename, 'w') as client_out_fp:
        p1 = subp.Popen(['ssh', server_node, app, '-R', '-F',
                         '-n', str(iteration_count), '-a'],
                        stdout=server_out_fp, stderr=subp.STDOUT)
        time.sleep(5)

        p2 = subp.Popen(['ssh', client_node, app, '-R', '-F',
                         '-n', str(iteration_count), '-a', server_iface_ip],
                        stdout=client_out_fp, stderr=subp.STDOUT)

        p1.communicate()
        p2.communicate()
        if p1.returncode == 0 and p2.returncode == 0:
            print("OK")
            return client_results_filename
        else:
            print("FAIL")
            raise subp.CalledProcessError()


def find_table(fh):
    hdrline = re.compile('#bytes')
    last = 0
    line = fh.readline()
    while line:
        if hdrline.search(line):
            fh.seek(last)
            return
        last = fh.tell()
        line = fh.readline()
    raise ValueError


def load_data_frame(fn, header_names):
    with open(fn, 'r') as fh:
        find_table(fh)
        if header_names is not None:
            fh.readline()
            df = pd.read_table(fh, '[ \t]+', names=header_names,
                               engine='python', skipfooter=1)
        else:
            df = pd.read_table(fh, '[ \t]+', engine='python',
                               skipfooter=1)
        if col_Mbytes in df:
            df[col_Mbits] = df[col_Mbytes] * 8
        return df


def size_formatter(x, pos):
    x = int(x)
    if x < 1000:
        return '{:d}'.format(x)
    elif x < 1000000:
        return '{} kB'.format(x // 1000)
    elif x < 1000000000:
        return '{} MB'.format(x // 1000000)
    else:
        return '{} GB'.format(x // 1000000000)


def do_plot_bw(apps, df, logid):
    fig, ax = plt.subplots()
    df.plot(x=col_size, ax=ax, y=apps, title='Throughput', logx=True)
    ax.xaxis.set_major_formatter(FuncFormatter(size_formatter))
    ax.yaxis.set_label_text('Throughput (Mbps)')
    plt.savefig(os.path.join(os.environ['HOME'], 'results', 'perftest',
                'bw-{}.pdf'.format(logid)))
    plt.savefig(os.path.join(os.environ['HOME'], 'results', 'perftest',
                'bw-{}.eps'.format(logid)))


def main():
    do_run_test = False
    logid = ''
    if len(sys.argv) == 1:
        logid = datetime.datetime.now().strftime('%Y%m%d-%H%M')
        do_run_test = True
    else:
        logid = sys.argv[1]

    lat_tests = ['ib_send_lat', 'ib_write_lat', 'ib_read_lat']
    df = pd.DataFrame(data={col_size: []})
    for app in lat_tests:
        if do_run_test:
            fn = run_test(app, logid)
        else:
            fn = log_file_name(app, logid, 'client')
        nextdf = load_data_frame(fn, None)
        nextdf = nextdf.filter(items=[col_size, col_lat_median])
        nextdf = nextdf[nextdf[col_size] <= 2048]
        nextdf = nextdf.rename(columns={col_lat_median: app})
        df = df.merge(nextdf, on=col_size, how='right')
    df.plot(x=col_size, y=lat_tests, title='Latency (microseconds)')
    plt.savefig(os.path.join(os.environ['HOME'], 'results', 'perftest',
                'latency-{}.pdf'.format(logid)))
    plt.savefig(os.path.join(os.environ['HOME'], 'results', 'perftest',
                'latency-{}.eps'.format(logid)))

    bw_tests = ['ib_send_bw', 'ib_write_bw', 'ib_read_bw']
    df = pd.DataFrame(data={col_size: []})
    bw_header_names = [col_size, '#iterations', 'BW peak[MB/sec]',
                       'BW average[MB/sec]', 'MsgRate[Mpps]']
    for app in bw_tests:
        if do_run_test:
            fn = run_test(app, logid)
        else:
            fn = log_file_name(app, logid, 'client')
        nextdf = load_data_frame(fn, bw_header_names)
        nextdf = nextdf.filter(items=[col_size, col_Mbits])
        nextdf = nextdf.rename(columns={col_Mbits: app})
        df = df.merge(nextdf, on=col_size, how='right')
    do_plot_bw(bw_tests, df, logid)

if __name__ == '__main__':
    main()
