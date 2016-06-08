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
import os
import os.path
import subprocess as subp
import sys
import tempfile

def load_modules(*args):
    if 'MODULESHOME' not in os.environ:
        environ['MODULESHOME'] = '/usr/share/Modules'
        environ['LOADEDMODULES'] = ''
        environ['MODULESPATH'] = '/usr/share/Modules/modulefiles:/etc/modulefiles'
    for arg in args:
        out = subp.check_output(['modulecmd', 'python', 'load', arg])
        exec(out)

def get_var(config, varname):
    if varname in config['local']:
        return config['local'][varname]
    elif varname in config['common']:
        return config['common'][varname]
    else:
        return None

def run_logged(args):
    print("+", str(args))
    sys.stdout.flush()
    return subp.call(args)


def main():
    try:
        load_modules('use.own', 'dpdk')

        config = json.load(sys.stdin)
        top_srcdir = get_var(config, 'deploy_dir')
        app = get_var(config, 'app')

        run_logged(['make', '-C', top_srcdir, 'O=build',
                   'EXTRA_CFLAGS=-DNDEBUG'])
        run_logged(['pkill', app])

        eal_args = ['-l', config['local']['lcore_layout']]
        app_args = config['common']['app_args']
        app_args += ['-o', config['current']['results_file']]
        for iface in get_var(config, 'dpdk_interfaces'):
            eal_args += ['-w', iface['port']]
            app_args.append(iface['ipv4_address'])
        eal_log_level = get_var(config, 'eal_log_level')
        if eal_log_level is not None:
            eal_args += ['--log-level', str(eal_log_level)]
        if 'server_ip_address' in config['local']:
            app_args.append(config['local']['server_ip_address'])

        app_path = os.path.join(top_srcdir, 'build', 'src', app,
                os.environ['RTE_TARGET'], 'app', app)
        run_logged([app_path] + eal_args + ['--'] + app_args)
    finally:
        pass

if __name__ == '__main__':
    main()
