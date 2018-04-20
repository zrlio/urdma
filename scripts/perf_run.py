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
import random
import subprocess as subp
import sys
import tempfile
import time

def run_test(config, wait_fifo_file, param, runid):
    param_file_prefix = ""
    new_common = copy.deepcopy(config['common'])
    for var_opt, value in param.items():
        param_file_prefix += "{}-{}.".format(var_opt, str(value))
        if var_opt == "checksum_offload":
            if not value:
                new_common['app_args'].append("--disable-checksum-offload")
        else:
            new_common['app_args'] += ["--{}={}".format(
                var_opt.translate(str.maketrans({'_': '-'})),
                str(value))]

    print("Running {} with {}...".format(config['client']['app'],
        str(param)), end='')
    sys.stdout.flush()

    current_config = dict(parameters=param, runid=runid)
    current_config['results_file'] = os.path.join(
            os.environ['HOME'], 'results', config['client']['app'],
            config['common']['logid'],
            '{}{}.server.log'.format(param_file_prefix, str(runid)))
    new_config = dict(local=config['server'], common=new_common,
                     current=current_config)
    server_conf_fp = tempfile.NamedTemporaryFile(mode='w')
    json.dump(new_config, server_conf_fp)
    server_conf_fp.flush()
    p1 = subp.Popen(['tmux', 'neww', '-d', '-n', 'dpdk-server',
                     os.path.join(config['common']['top_srcdir'], 'scripts',
                                  'perf_run_tmux_helper.py'),
                     server_conf_fp.name, wait_fifo_file])
    time.sleep(5)

    current_config['results_file'] = os.path.join(
            os.environ['HOME'], 'results', config['client']['app'],
            config['common']['logid'],
            '{}{}.client.log'.format(param_file_prefix, str(runid)))
    new_config = dict(local=config['client'], common=new_common,
                     current=current_config)
    client_conf_fp = tempfile.NamedTemporaryFile(mode='w')
    json.dump(new_config, client_conf_fp)
    client_conf_fp.flush()
    p2 = subp.Popen(['tmux', 'neww', '-d', '-n', 'dpdk-client',
                     os.path.join(config['common']['top_srcdir'], 'scripts',
                                  'perf_run_tmux_helper.py'),
                     client_conf_fp.name])

    p1.communicate()
    p2.communicate()
    with open(wait_fifo_file, 'r') as wait_fifo_fp:
        wait_fifo_fp.readline()
    print("DONE")
    server_conf_fp.close()
    client_conf_fp.close()
    return current_config


def load_config(conf_file):
    with open(conf_file, 'r') as fp:
        return json.load(fp)

def deploy_code(node, srcdir, deploy_dir):
    oldpwd = os.getcwd()
    os.chdir(srcdir)
    p1 = subp.Popen(['git', 'archive', '--format', 'tar', 'HEAD'],
                    stdout=subp.PIPE)
    p2 = subp.Popen(['ssh', node, 'tar', '-C', deploy_dir, '-x'],
                    stdin=p1.stdout)
    p1.stdout.close()
    p2.communicate()
    os.chdir(oldpwd)

def add_result(config, results, current_config):
    node = config['client']['node']
    resultsdir = config['common']['resultsdir']
    results_file = current_config['results_file']
    subp.check_call(['scp', '{}:{}'.format(node, results_file),
                     resultsdir], stdout=subp.DEVNULL)
    with open(results_file, 'r') as fp:
        next_result = json.load(fp)
        next_result['run_id'] = current_config['runid']
        next_result['app'] = config['client']['app']
        results.append(next_result)

def make_parameter_list(experiment):
    """Creates a list of experiment configurations from the description of the
    experiment.  The input is specified as a dictionary of parameters each of
    which is a list of values.

    (doctest currently fails because the output doesn't exactly match, but it
    is semantically equivalent)

    >>> make_configuration_list(dict(parameters=dict(a=[1, 2, 3], b=['x', 'y'])))
    [{'a': 1, 'b': 'x'}, {'a': 1, 'b': 'y'}, {'a': 2, 'b': 'x'}, \
    {'a': 2, 'b': 'y'}, {'a': 3, 'b': 'x'}, {'a': 3, 'b': 'y'}]
    """
    def add_value(oldlist, key, value_list):
        newlist = []
        for oldconfig in oldlist:
            for value in vlist:
                nextconfig = copy.copy(oldconfig)
                nextconfig[key] = value
                newlist.append(nextconfig)
        return newlist

    configlist = [dict()]
    for key, vlist in experiment['parameters'].items():
        configlist = add_value(configlist, key, vlist)
    return configlist

def main():
    with tempfile.TemporaryDirectory() as our_tmpdir:
        wait_fifo_file = os.path.join(our_tmpdir, 'wait_fifo')
        os.mkfifo(wait_fifo_file)

        config = load_config(sys.argv[1])

        config['common']['logid'] = datetime.datetime.now().strftime(
                "%Y%m%d-%H%M")
        config['common']['resultsdir'] = os.path.join(os.environ['HOME'],
                'results', config['client']['app'], config['common']['logid'])
        os.makedirs(config['common']['resultsdir'])

        top_srcdir = config['common']['top_srcdir']
        if top_srcdir.startswith('~' + os.path.sep):
            config['common']['top_srcdir'] = os.environ['HOME'] + top_srcdir[1:]
        deploy_code(config['server']['node'], config['common']['top_srcdir'],
                config['common']['deploy_dir'])
        deploy_code(config['client']['node'], config['common']['top_srcdir'],
                config['common']['deploy_dir'])

        experiment = config['experiment']
        paramlist = make_parameter_list(experiment)
        results = []
        for runid in range(experiment['run_count']):
            random.shuffle(paramlist)
            for param in paramlist:
                current_config = run_test(config, wait_fifo_file, param, runid)
                try:
                    add_result(config, results, current_config)
                except ValueError as err:
                    print("Could not parse JSON result from last test:",
                            str(err))
                    pass

        with open(os.path.join(config['common']['resultsdir'],
                               'results.json'), 'w') as fp:
            json.dump(results, fp, indent=2)

if __name__ == '__main__':
    main()
