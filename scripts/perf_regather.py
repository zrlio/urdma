#!/usr/bin/env python3
#
# Userspace Software iWARP library for DPDK
#
# Authors: Patrick MacArthur <patrick@patrickmacarthur.net>
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
import subprocess as subp
import sys
import tempfile
import time

def load_config(conf_file):
    with open(conf_file, 'r') as fp:
        return json.load(fp)

def add_result(config, results, current_config):
    node = config['client']['node']
    resultsdir = config['common']['resultsdir']
    results_file = current_config['results_file']
    with open(results_file, 'r') as fp:
        next_result = json.load(fp)
        next_result['run_id'] = current_config['runid']
        next_result['app'] = config['client']['app']
        results.append(next_result)

def main():
    config = load_config(sys.argv[1])

    config['common']['logid'] = sys.argv[2]
    config['common']['resultsdir'] = os.path.join(os.environ['HOME'],
            'results', config['client']['app'], config['common']['logid'])

    experiment = config['experiment']
    results = []
    for runid in range(experiment['run_count']):
        for value in experiment['values']:
            var_opt = experiment['var_opt']
            current_config = dict(var_opt=var_opt, value=value, runid=runid)
            current_config['results_file'] = os.path.join(
                    os.environ['HOME'], 'results', config['client']['app'],
                    config['common']['logid'],
                    '{}.{}.{}.client.log'.format(var_opt, str(value),
                                                 str(runid)))
            add_result(config, results, current_config)

    with open(os.path.join(config['common']['resultsdir'],
                           'results.json'), 'w') as fp:
        json.dump(results, fp, indent=2)

if __name__ == '__main__':
    main()
