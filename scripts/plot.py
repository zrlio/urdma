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

import numpy as np
import pandas as pd
from pandas.io.json import json_normalize
import matplotlib.pyplot as plt
import json
import sys

def make_plot(data, x_axis, y_axis, category):
    '''Makes a plot for the given data set (as a list of hash objects) using
    matplotlib.'''
    grouped = data.groupby([x_axis, category])
    y_values = grouped[y_axis].mean().unstack()
    errors = grouped[y_axis].std().unstack()
    fig, ax = plt.subplots()
    y_values.plot(yerr=errors, ax=ax, kind='line',
                  xlim=[0, data[x_axis].max() * 1.05],
                  ylim=[0, data[y_axis].max() * 1.05])
    ax.yaxis.set_label_text(y_axis)
    plt.savefig("{}-vs-{}.pdf".format(y_axis, x_axis))

def make_hist(data, x_axis, x_value, y_axis):
    grouped = data.groupby((x_axis, 'run_id'))
    group = grouped.get_group((x_value, 0))
    plt.figure("{} = {}".format(x_axis, x_value))
    group[y_axis].apply(lambda v: plt.hist(range(0, len(v)), len(v), weights=v,
                                           log=True))
    plt.xlabel(y_axis)
    plt.ylabel('Count')
    plt.title("{} = {}; burst_size = 96".format(x_axis, x_value))
    plt.savefig("hist-{}-{}-{}.pdf".format(y_axis, x_axis, x_value))

def make_data_frame(filename):
    with open(filename, 'r') as fp:
        jdata = json.load(fp)
        return json_normalize(jdata)

def main():
    json_in_file = sys.argv[1]
    x_axis = sys.argv[2]
    print("input file is", json_in_file)
    print("x axis label is", x_axis)
    data = make_data_frame(json_in_file)

    make_plot(data, x_axis, 'message_rate', 'app')
    make_plot(data, x_axis, 'latency', 'app')
    make_plot(data, x_axis, 'throughput', 'app')

if __name__ == "__main__":
    main()
