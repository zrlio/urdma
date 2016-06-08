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

import json
import io
import os
import os.path
import subprocess as subp
import sys
import tempfile

def get_var(config, varname):
    if varname in config['local']:
        return config['local'][varname]
    elif varname in config['common']:
        return config['common'][varname]
    else:
        return None

def make_log_dir(node, app):
    log_dir = os.path.join(os.environ['HOME'], 'log', node, app)
    os.makedirs(log_dir, exist_ok=True)
    return log_dir

def main():
    try:
        with open(sys.argv[1], 'r') as conf_fp:
            try:
                config = json.load(conf_fp)
                logid = get_var(config, 'logid')
                node = get_var(config, 'node')
                app = get_var(config, 'app')
                log_file = os.path.join(make_log_dir(node, app),
                                        '{}.log'.format(logid))
                conf_fp.seek(0, io.SEEK_SET)
                print("Starting processes")
                sys.stdout.flush()
                p1 = subp.Popen(['ssh', '-t', config['local']['node'],
                                os.path.join(
                                    config['common']['deploy_dir'],
                                    'scripts', 'perf_run_ssh_helper.py')],
                               stdin=conf_fp, stdout=subp.PIPE,
                               stderr=subp.STDOUT, bufsize=0)
                p2 = subp.Popen(['tee', log_file], stdin=p1.stdout)
                print("Waiting for processes to finish")
                sys.stdout.flush()
                p1.stdout.close()
                try:
                    p2.communicate()
                except KeyboardInterrupt:
                    p1.kill()
                    p2.kill()
                    p2.communicate()
            except ValueError:
                print('Could not parse JSON object from', sys.argv[1])
                conf_fp.seek(0, io.SEEK_SET)
                print(conf_fp.read())
                raise
    finally:
        if len(sys.argv) > 2:
            with open(sys.argv[2], 'w') as signal_fp:
                signal_fp.write('done\n')

if __name__ == '__main__':
    main()
